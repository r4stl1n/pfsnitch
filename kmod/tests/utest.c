/*
 * utest - functional test of the Phase 3 fail-fast upcall.
 *
 * Plays the daemon in a thread: read() events from /dev/pfsnitch and RESOLVE
 * them by a toy policy (port 9999 = allow, 8888 = deny). The main thread then
 * drives real connect()/sendto() calls and checks that a miss returns EAGAIN,
 * and that after the daemon resolves, a retry gets the cached verdict.
 *
 * The point worth proving is the UDP case: an unconnected sendto() with a
 * destination is routed through socket_check_connect, so the upcall fires for
 * UDP too - which is the whole reason Phase 3/4 can reach the per-packet UDP
 * overhead.
 *
 *   cc -O2 -pthread -o utest utest.c && doas ./utest
 */

#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdatomic.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../pfsnitch_ioctl.h"

#define ALLOW_PORT 9999
#define DENY_PORT  8888

static int dev;
static _Atomic int stop;
static _Atomic int udp_events;	/* count of UDP events the "daemon" saw */
static _Atomic int tcp_events;	/* TCP events - should stay 0: TCP is not upcalled */
static int fails;

/* The daemon: deliver events, resolve by destination port. */
static void *
daemon_thread(void *arg)
{
	(void)arg;
	for (;;) {
		struct pfsnitch_event ev;
		ssize_t n = read(dev, &ev, sizeof(ev));
		if (atomic_load(&stop))
			return (NULL);
		if (n != (ssize_t)sizeof(ev))
			continue;
		if (ev.proto == IPPROTO_UDP)
			atomic_fetch_add(&udp_events, 1);
		else
			atomic_fetch_add(&tcp_events, 1);

		struct pfsnitch_resolve r;
		memset(&r, 0, sizeof(r));
		r.version = PFSNITCH_ATTR_VERSION;
		r.id = ev.id;
		r.verdict = (ntohs(ev.fport) == DENY_PORT)
		    ? PFSNITCH_V_DENY : PFSNITCH_V_ALLOW;
		if (ioctl(dev, PFSNITCH_RESOLVE, &r) < 0)
			warn("RESOLVE");
	}
}

/* Attempt an operation up to ~1s, retrying while it returns EAGAIN (the miss
 * is being resolved). Returns the settled errno: 0 = allowed/succeeded,
 * EPERM = denied, or whatever else the stack returned for an allowed attempt. */
static int
attempt(int udp, int port)
{
	struct sockaddr_in d;
	memset(&d, 0, sizeof(d));
	d.sin_family = AF_INET;
	d.sin_port = htons(port);
	d.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	for (int i = 0; i < 200; i++) {
		int s = socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
		if (s < 0)
			err(1, "socket");
		int r, e;
		if (udp)
			r = sendto(s, "x", 1, 0, (struct sockaddr *)&d, sizeof(d));
		else
			r = connect(s, (struct sockaddr *)&d, sizeof(d));
		e = (r < 0) ? errno : 0;
		close(s);
		if (e != EAGAIN)
			return (e);	/* settled */
		usleep(5000);		/* miss in flight; let the daemon resolve */
	}
	return (EAGAIN);		/* never resolved */
}

static void
expect(const char *what, int got, int want)
{
	int ok = (got == want);
	printf("  %-42s got=%-16s %s\n", what, got ? strerror(got) : "ok(allowed)",
	    ok ? "PASS" : "FAIL");
	if (!ok) {
		printf("      expected %s\n", want ? strerror(want) : "ok(allowed)");
		fails++;
	}
}

/* -------- stress mode: hammer the upcall queue under concurrency -------- */

static uint32_t
xrand(uint32_t *s)
{
	*s ^= *s << 13; *s ^= *s >> 17; *s ^= *s << 5;
	return (*s);
}

/* Resolver that answers everything (allow), as fast as it can read. */
static void *
resolver_thread(void *arg)
{
	(void)arg;
	for (;;) {
		struct pfsnitch_event ev;
		ssize_t n = read(dev, &ev, sizeof(ev));
		if (atomic_load(&stop))
			return (NULL);
		if (n != (ssize_t)sizeof(ev))
			continue;
		struct pfsnitch_resolve r;
		memset(&r, 0, sizeof(r));
		r.version = PFSNITCH_ATTR_VERSION;
		r.id = ev.id;
		r.verdict = PFSNITCH_V_ALLOW;
		ioctl(dev, PFSNITCH_RESOLVE, &r);
	}
}

/* Churn connects/sendtos to random ports: each a fresh miss -> upcall ->
 * resolve -> cache, so the queue, the dedup scan, GC, and resolve-vs-hook all
 * run hot at once. */
static _Atomic long ops;
static void *
churn_thread(void *arg)
{
	uint32_t s = (uint32_t)(uintptr_t)arg * 2654435761u + 1;
	while (!atomic_load(&stop)) {
		int udp = xrand(&s) & 1;
		int port = (xrand(&s) % 50000) + 1024;
		int fd = socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
		if (fd < 0)
			continue;
		struct sockaddr_in d;
		memset(&d, 0, sizeof(d));
		d.sin_family = AF_INET;
		d.sin_port = htons(port);
		d.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (udp)
			sendto(fd, "x", 1, 0, (struct sockaddr *)&d, sizeof(d));
		else
			connect(fd, (struct sockaddr *)&d, sizeof(d));
		close(fd);
		atomic_fetch_add(&ops, 1);
	}
	return (NULL);
}

static int
stress_mode(int secs)
{
	pthread_t rd, ch[8];
	int on = 1, off = 0, i;

	ioctl(dev, PFSNITCH_VERDICT_FLUSH);
	pthread_create(&rd, NULL, resolver_thread, NULL);
	ioctl(dev, PFSNITCH_UPCALL_SET, &on);
	usleep(20000);
	for (i = 0; i < 8; i++)
		pthread_create(&ch[i], NULL, churn_thread, (void *)(uintptr_t)(i + 1));

	printf("upcall stress: 8 churn threads, %ds\n", secs);
	for (i = 0; i < secs; i++) {
		sleep(1);
		printf("\r  %ds ops=%ld   ", i + 1, atomic_load(&ops));
		fflush(stdout);
	}
	atomic_store(&stop, 1);
	for (i = 0; i < 8; i++)
		pthread_join(ch[i], NULL);
	ioctl(dev, PFSNITCH_UPCALL_SET, &off);	/* EOF the reader */
	pthread_join(rd, NULL);
	ioctl(dev, PFSNITCH_VERDICT_FLUSH);
	printf("\nupcall stress: done, ops=%ld\n", atomic_load(&ops));
	return (0);
}

/* One socket op to 127.0.0.9:port, no retry; returns errno (0 on success). */
static int
one(int udp, int port)
{
	struct sockaddr_in d;
	memset(&d, 0, sizeof(d));
	d.sin_family = AF_INET;
	d.sin_port = htons(port);
	inet_pton(AF_INET, "127.0.0.9", &d.sin_addr);
	int s = socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
	int r = udp ? sendto(s, "x", 1, 0, (struct sockaddr *)&d, sizeof(d))
		    : connect(s, (struct sockaddr *)&d, sizeof(d));
	int e = (r < 0) ? errno : 0;
	close(s);
	return (e);
}

/* Prove `pfsnitch kernel-reset` clears the upcall and flushes the cache: with
 * upcall on and a deny cached, a reset must make the deny stop enforcing and a
 * UDP miss stop upcalling. Pass the pfsnitch binary path as argv[2]. */
static int
reset_mode(const char *pfsnitch)
{
	struct pfsnitch_verdict v;
	int on = 1;

	ioctl(dev, PFSNITCH_VERDICT_FLUSH);
	ioctl(dev, PFSNITCH_UPCALL_SET, &on);

	char selfpath[1024];
	size_t l = sizeof(selfpath);
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1 };
	sysctl(mib, 4, selfpath, &l, NULL, 0);
	memset(&v, 0, sizeof(v));
	v.version = PFSNITCH_ATTR_VERSION;
	v.af = 4; v.proto = IPPROTO_TCP; v.fport = htons(9);
	inet_pton(AF_INET, "127.0.0.9", v.faddr);
	v.verdict = PFSNITCH_V_DENY;
	strlcpy(v.path, selfpath, sizeof(v.path));
	ioctl(dev, PFSNITCH_VERDICT_PUSH, &v);

	expect("before: cached TCP deny enforces", one(0, 9), EPERM);
	/* UDP miss upcalls (no reader here) -> EAGAIN. */
	expect("before: UDP miss upcalls (EAGAIN)", one(1, 4321), EAGAIN);

	char cmd[1200];
	snprintf(cmd, sizeof(cmd), "%s kernel-reset", pfsnitch);
	if (system(cmd) != 0)
		printf("  (warning: kernel-reset returned nonzero)\n");

	/* 127.0.0.9 isn't a bound local address, so the fell-through op fails at
	 * the network layer - the point is only that it is NOT EPERM/EAGAIN, i.e.
	 * the cached deny is gone and the upcall is off. */
	int te = one(0, 9);
	printf("  after reset: TCP deny flushed (not EPERM)         got=%s %s\n",
	    te ? strerror(te) : "ok", te != EPERM ? "PASS" : "FAIL");
	if (te == EPERM) fails++;
	int e = one(1, 4321);
	printf("  after reset: UDP miss falls through (not EAGAIN)  got=%s %s\n",
	    e ? strerror(e) : "ok", e != EAGAIN ? "PASS" : "FAIL");
	if (e == EAGAIN) fails++;

	printf("reset: %s\n", fails == 0 ? "ALL PASSED" : "FAILURES");
	return (fails == 0 ? 0 : 1);
}

int
main(int argc, char **argv)
{
	pthread_t th;
	int on = 1;

	setvbuf(stdout, NULL, _IONBF, 0);
	dev = open("/dev/pfsnitch", O_RDWR);
	if (dev < 0)
		err(1, "/dev/pfsnitch (is mac_pfsnitch loaded?)");
	if (argc >= 2 && strcmp(argv[1], "stress") == 0)
		return (stress_mode(argc >= 3 ? atoi(argv[2]) : 15));
	if (argc >= 2 && strcmp(argv[1], "reset") == 0)
		return (reset_mode(argc >= 3 ? argv[2] : "pfsnitch"));

	if (ioctl(dev, PFSNITCH_VERDICT_FLUSH) < 0)
		err(1, "FLUSH");

	pthread_create(&th, NULL, daemon_thread, NULL);
	if (ioctl(dev, PFSNITCH_UPCALL_SET, &on) < 0)
		err(1, "UPCALL_SET");
	usleep(50000);	/* let the reader block on read() */

	printf("utest: upcall on; toy policy allow:%d deny:%d\n",
	    ALLOW_PORT, DENY_PORT);

	/* TCP is NOT upcalled (Phase 4 gate): a miss falls straight through, so
	 * both ports just get ECONNREFUSED and the daemon never sees a TCP event.
	 * TCP stays on the divert-hold, which this isolated test does not set up. */
	printf("  [TCP allow] attempting...\n");
	expect("TCP miss falls through (allow port)", attempt(0, ALLOW_PORT), ECONNREFUSED);
	printf("  [TCP deny] attempting...\n");
	expect("TCP miss falls through (deny port)",  attempt(0, DENY_PORT), ECONNREFUSED);

	/* UDP is the case that matters. sendto() reaches the hook, so the miss
	 * upcalls; allow -> sendto succeeds, deny -> EPERM. */
	printf("  [UDP allow] attempting...\n");
	expect("UDP allow -> sendto ok",   attempt(1, ALLOW_PORT), 0);
	printf("  [UDP deny] attempting...\n");
	expect("UDP deny  -> EPERM",       attempt(1, DENY_PORT), EPERM);

	int udp_seen = atomic_load(&udp_events);
	int tcp_seen = atomic_load(&tcp_events);
	printf("  UDP events delivered: %d %s\n", udp_seen, udp_seen > 0 ? "PASS" : "FAIL");
	printf("  TCP events delivered: %d %s (must be 0: TCP is not upcalled)\n",
	    tcp_seen, tcp_seen == 0 ? "PASS" : "FAIL");
	if (udp_seen == 0 || tcp_seen != 0)
		fails++;

	atomic_store(&stop, 1);
	int off = 0;
	ioctl(dev, PFSNITCH_UPCALL_SET, &off);	/* wakes the reader */
	pthread_join(th, NULL);
	ioctl(dev, PFSNITCH_VERDICT_FLUSH);
	close(dev);

	printf("utest: %s\n", fails == 0 ? "ALL PASSED" : "FAILURES");
	return (fails == 0 ? 0 : 1);
}
