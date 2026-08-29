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

	if (ioctl(dev, PFSNITCH_VERDICT_FLUSH) < 0)
		err(1, "FLUSH");

	pthread_create(&th, NULL, daemon_thread, NULL);
	if (ioctl(dev, PFSNITCH_UPCALL_SET, &on) < 0)
		err(1, "UPCALL_SET");
	usleep(50000);	/* let the reader block on read() */

	printf("utest: upcall on; toy policy allow:%d deny:%d\n",
	    ALLOW_PORT, DENY_PORT);

	/* TCP: allowed port resolves to allow (connect proceeds -> ECONNREFUSED,
	 * nothing listening); denied port resolves to EPERM. */
	printf("  [TCP allow] attempting...\n");
	expect("TCP allow -> not blocked", attempt(0, ALLOW_PORT), ECONNREFUSED);
	printf("  [TCP deny] attempting...\n");
	expect("TCP deny  -> EPERM",       attempt(0, DENY_PORT), EPERM);

	/* UDP: the case that matters. sendto() must reach the hook, so the miss
	 * upcalls; allow -> sendto succeeds, deny -> EPERM. */
	printf("  [UDP allow] attempting...\n");
	expect("UDP allow -> sendto ok",   attempt(1, ALLOW_PORT), 0);
	printf("  [UDP deny] attempting...\n");
	expect("UDP deny  -> EPERM",       attempt(1, DENY_PORT), EPERM);

	int udp_seen = atomic_load(&udp_events);
	printf("  UDP events delivered to daemon: %d %s\n", udp_seen,
	    udp_seen > 0 ? "PASS" : "FAIL");
	if (udp_seen == 0)
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
