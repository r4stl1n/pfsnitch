/*
 * stress - hammer the label lifecycle and the lookup-during-teardown race.
 *
 * The module allocates a label at socket_create and frees it at
 * socket_destroy; the lookup path reads that label off a socket it found via
 * in_pcblookup, under the pcb read lock and the net epoch. The bug class that
 * panics a machine here is a use-after-free: a query reading a label while the
 * socket that owns it is being torn down.
 *
 * To provoke it deliberately rather than hope for it, this runs a real
 * loopback listener and:
 *   - churn threads open a connection to it, PUBLISH the exact 4-tuple into a
 *     shared table, run briefly, then close - so a socket's label is created
 *     and destroyed at high rate;
 *   - query threads read those published tuples and look them up over and over,
 *     landing ioctls on sockets precisely as they are being closed.
 * The two together keep the lookup path pointed at memory that is constantly
 * being freed, which is exactly the window a UAF lives in.
 *
 * A `fork` mode additionally spawns short-lived children that open sockets and
 * exit, so socket_create runs in many different process contexts (varying
 * p_textvp / vn_fullpath) and races its own socket_destroy on process teardown.
 *
 * Success is boring: it runs for the duration and the machine is still there.
 * On a debug kernel (INVARIANTS/WITNESS) a latent bug turns into a panic or a
 * lock-order warning; on GENERIC it takes a gross fault to show, which is still
 * worth ruling out. Leak checking is the driver's job, via vmstat -m.
 *
 *   cc -O2 -pthread -o stress stress.c
 *   ./stress [-d secs] [-c churn] [-q query] [-f forkers]
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "../pfsnitch_ioctl.h"

static int duration = 20;
static int nchurn = 6;
static int nquery = 4;
static int nfork = 2;
static int nvchurn = 2;

static _Atomic int stop;
static _Atomic long conns, queries, matches, forks, errors, pushes, flushes;
static int listen_port;

/*
 * Published live tuples. A ring of slots the churn threads fill and the query
 * threads read. Deliberately racy: a query reading a half-updated slot just
 * issues a lookup for a nonsense tuple, which is a MISS, not a crash - and
 * chasing a slot as it is overwritten is the whole point.
 */
#define NSLOTS 256
struct slot {
	_Atomic int valid;
	uint8_t af, proto;
	uint16_t lport, fport;
	uint8_t laddr[16], faddr[16];
};
static struct slot slots[NSLOTS];
static _Atomic unsigned slot_cursor;

static uint32_t
xrand(uint32_t *s)
{
	*s ^= *s << 13; *s ^= *s >> 17; *s ^= *s << 5;
	return (*s);
}

static void
publish(int fd)
{
	struct sockaddr_storage l, f;
	socklen_t ll = sizeof(l), fl = sizeof(f);

	if (getsockname(fd, (struct sockaddr *)&l, &ll) < 0)
		return;
	if (getpeername(fd, (struct sockaddr *)&f, &fl) < 0)
		return;

	unsigned idx = atomic_fetch_add(&slot_cursor, 1) % NSLOTS;
	struct slot *sl = &slots[idx];
	atomic_store(&sl->valid, 0); /* mark unstable while we write */
	struct sockaddr_in *li = (struct sockaddr_in *)&l;
	struct sockaddr_in *fi = (struct sockaddr_in *)&f;
	sl->af = 4;
	sl->proto = IPPROTO_TCP;
	sl->lport = li->sin_port;
	sl->fport = fi->sin_port;
	memcpy(sl->laddr, &li->sin_addr, 4);
	memcpy(sl->faddr, &fi->sin_addr, 4);
	atomic_store(&sl->valid, 1);
}

/* One connection to the loopback listener: create, publish, hold, close. */
static void *
churn_thread(void *arg)
{
	uint32_t s = (uint32_t)(uintptr_t)arg * 40503u + 1;
	struct sockaddr_in dst;
	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_port = htons(listen_port);
	dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	int qfd = open("/dev/pfsnitch", O_RDWR);

	while (!atomic_load(&stop)) {
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0) { atomic_fetch_add(&errors, 1); continue; }
		/* Abortive close: RST instead of FIN, so the socket (and its
		 * label) is destroyed at close() rather than lingering in
		 * TIME_WAIT. This does double duty - it stops loopback churn
		 * from exhausting ephemeral ports (which otherwise stalls the
		 * test after ~1s), and it maximises the label create/destroy
		 * rate, which is precisely the window a lookup-vs-teardown
		 * use-after-free lives in. */
		struct linger lg = { .l_onoff = 1, .l_linger = 0 };
		setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
		if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) == 0) {
			atomic_fetch_add(&conns, 1);
			publish(fd);
			/* Also self-query sometimes: an exact hit that must name
			 * this very process. */
			if (qfd >= 0 && (xrand(&s) & 3) == 0) {
				struct pfsnitch_attr q;
				memset(&q, 0, sizeof(q));
				q.version = PFSNITCH_ATTR_VERSION;
				q.af = 4; q.proto = IPPROTO_TCP;
				struct sockaddr_in ln; socklen_t sl = sizeof(ln);
				if (getsockname(fd, (struct sockaddr *)&ln, &sl) == 0) {
					q.lport = ln.sin_port;
					memcpy(q.laddr, &ln.sin_addr, 4);
					q.fport = dst.sin_port;
					memcpy(q.faddr, &dst.sin_addr, 4);
					if (ioctl(qfd, PFSNITCH_ATTR_QUERY, &q) == 0 &&
					    q.found != PFSNITCH_MISS) {
						atomic_fetch_add(&matches, 1);
						if (q.pid != getpid()) {
							fprintf(stderr,
							  "INVARIANT: self-query named pid %d not %d\n",
							  q.pid, (int)getpid());
							atomic_fetch_add(&errors, 1);
						}
					}
				}
			}
		}
		close(fd);
	}
	if (qfd >= 0)
		close(qfd);
	return (NULL);
}

/* Look up published tuples as fast as possible, chasing sockets into close(). */
static void *
query_thread(void *arg)
{
	uint32_t s = (uint32_t)(uintptr_t)arg * 2246822519u + 7;
	int fd = open("/dev/pfsnitch", O_RDWR);
	if (fd < 0) { atomic_fetch_add(&errors, 1); return (NULL); }

	while (!atomic_load(&stop)) {
		unsigned idx = xrand(&s) % NSLOTS;
		struct slot *sl = &slots[idx];
		if (!atomic_load(&sl->valid))
			continue;
		struct pfsnitch_attr q;
		memset(&q, 0, sizeof(q));
		q.version = PFSNITCH_ATTR_VERSION;
		q.af = sl->af;
		q.proto = sl->proto;
		q.lport = sl->lport;
		q.fport = sl->fport;
		memcpy(q.laddr, sl->laddr, 16);
		memcpy(q.faddr, sl->faddr, 16);
		if (ioctl(fd, PFSNITCH_ATTR_QUERY, &q) == 0) {
			atomic_fetch_add(&queries, 1);
			if (q.found != PFSNITCH_MISS) {
				atomic_fetch_add(&matches, 1);
				if (memchr(q.path, '\0', sizeof(q.path)) == NULL) {
					fprintf(stderr, "INVARIANT: path not terminated\n");
					atomic_fetch_add(&errors, 1);
				}
			}
		}
	}
	close(fd);
	return (NULL);
}

/* Short-lived children: exercise socket_create in fresh process contexts and
 * race socket_destroy against process exit. */
static void *
fork_thread(void *arg)
{
	(void)arg;
	struct sockaddr_in dst;
	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_port = htons(listen_port);
	dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	while (!atomic_load(&stop)) {
		pid_t p = fork();
		if (p == 0) {
			/* Child: open a few sockets, maybe connect, then exit
			 * WITHOUT closing - let process teardown free them. */
			for (int i = 0; i < 8; i++) {
				int fd = socket(AF_INET,
				    (i & 1) ? SOCK_DGRAM : SOCK_STREAM, 0);
				if (fd < 0)
					continue;
				if (!(i & 1))
					connect(fd, (struct sockaddr *)&dst,
					    sizeof(dst));
				else
					sendto(fd, "x", 1, 0,
					    (struct sockaddr *)&dst, sizeof(dst));
			}
			_exit(0);
		} else if (p > 0) {
			atomic_fetch_add(&forks, 1);
			waitpid(p, NULL, 0);
		} else {
			atomic_fetch_add(&errors, 1);
			usleep(1000);
		}
	}
	return (NULL);
}

/* Push and flush verdicts as fast as possible, racing the connect hook's
 * cache reads (every churn/fork connect) against the cache's writes. Half the
 * entries are keyed on our real path so lookups can actually hit; the rest are
 * random, to fill and turn over buckets. This is the Phase 2 rwlock stress and
 * the verdict-cache memory-lifecycle test in one. */
static void *
vchurn_thread(void *arg)
{
	uint32_t s = (uint32_t)(uintptr_t)arg * 22695477u + 1;
	int fd = open("/dev/pfsnitch", O_RDWR);
	if (fd < 0) { atomic_fetch_add(&errors, 1); return (NULL); }

	char selfpath[1024];
	size_t l = sizeof(selfpath);
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1 };
	if (sysctl(mib, 4, selfpath, &l, NULL, 0) < 0)
		selfpath[0] = '\0';

	while (!atomic_load(&stop)) {
		struct pfsnitch_verdict v;
		memset(&v, 0, sizeof(v));
		v.version = PFSNITCH_ATTR_VERSION;
		v.af = 4;
		v.proto = IPPROTO_TCP;
		v.fport = htons((xrand(&s) % 60000) + 1);
		uint32_t a = xrand(&s);
		memcpy(v.faddr, &a, 4);
		v.verdict = (xrand(&s) & 1) ? PFSNITCH_V_ALLOW : PFSNITCH_V_DENY;
		if ((xrand(&s) & 1) && selfpath[0])
			strlcpy(v.path, selfpath, sizeof(v.path));
		else
			snprintf(v.path, sizeof(v.path), "/x/%u", xrand(&s));
		if (ioctl(fd, PFSNITCH_VERDICT_PUSH, &v) == 0)
			atomic_fetch_add(&pushes, 1);
		/* Flush occasionally so the whole table is freed under readers. */
		if ((xrand(&s) % 512) == 0) {
			ioctl(fd, PFSNITCH_VERDICT_FLUSH);
			atomic_fetch_add(&flushes, 1);
		}
	}
	close(fd);
	return (NULL);
}

/* A loopback listener that accepts and immediately closes, so churn threads
 * get real connected sockets with stable tuples. */
static void *
listener_thread(void *arg)
{
	int ls = *(int *)arg;
	for (;;) {
		int c = accept(ls, NULL, NULL);
		if (c < 0) {
			if (atomic_load(&stop))
				return (NULL);
			continue;
		}
		close(c);
	}
}

int
main(int argc, char **argv)
{
	int c;
	while ((c = getopt(argc, argv, "d:c:q:f:v:")) != -1) {
		switch (c) {
		case 'd': duration = atoi(optarg); break;
		case 'c': nchurn = atoi(optarg); break;
		case 'q': nquery = atoi(optarg); break;
		case 'f': nfork = atoi(optarg); break;
		case 'v': nvchurn = atoi(optarg); break;
		default:
			fprintf(stderr,
			  "usage: %s [-d secs] [-c churn] [-q query] [-f forkers] [-v vchurn]\n",
			  argv[0]);
			return (2);
		}
	}
	signal(SIGCHLD, SIG_DFL);

	/* Bring up the loopback listener on an OS-chosen port. */
	int ls = socket(AF_INET, SOCK_STREAM, 0);
	if (ls < 0) { perror("socket"); return (2); }
	int one = 1;
	setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	struct sockaddr_in la;
	memset(&la, 0, sizeof(la));
	la.sin_family = AF_INET;
	la.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	la.sin_port = 0;
	if (bind(ls, (struct sockaddr *)&la, sizeof(la)) < 0) {
		perror("bind"); return (2);
	}
	socklen_t sl = sizeof(la);
	getsockname(ls, (struct sockaddr *)&la, &sl);
	listen_port = ntohs(la.sin_port);
	if (listen(ls, 128) < 0) { perror("listen"); return (2); }

	/* Verdict-cache entries live until flushed (they are not tied to a
	 * socket's lifetime like labels are), so bracket the run with flushes:
	 * a clean start, and a clean end so the leak check sees only labels. */
	int vf = open("/dev/pfsnitch", O_RDWR);
	if (vf >= 0)
		ioctl(vf, PFSNITCH_VERDICT_FLUSH);

	printf("stress: %ds  churn=%d query=%d fork=%d vchurn=%d  listener=127.0.0.1:%d\n",
	    duration, nchurn, nquery, nfork, nvchurn, listen_port);

	pthread_t lt;
	pthread_create(&lt, NULL, listener_thread, &ls);

	int total = nchurn + nquery + nfork + nvchurn;
	pthread_t *th = calloc(total, sizeof(*th));
	int n = 0;
	for (int i = 0; i < nchurn; i++)
		pthread_create(&th[n++], NULL, churn_thread, (void *)(uintptr_t)(i + 1));
	for (int i = 0; i < nquery; i++)
		pthread_create(&th[n++], NULL, query_thread, (void *)(uintptr_t)(i + 1));
	for (int i = 0; i < nfork; i++)
		pthread_create(&th[n++], NULL, fork_thread, (void *)(uintptr_t)(i + 1));
	for (int i = 0; i < nvchurn; i++)
		pthread_create(&th[n++], NULL, vchurn_thread, (void *)(uintptr_t)(i + 1));

	for (int elapsed = 0; elapsed < duration; elapsed++) {
		sleep(1);
		printf("\r  %ds: conns=%ld queries=%ld matches=%ld forks=%ld push=%ld flush=%ld err=%ld   ",
		    elapsed + 1, atomic_load(&conns), atomic_load(&queries),
		    atomic_load(&matches), atomic_load(&forks),
		    atomic_load(&pushes), atomic_load(&flushes), atomic_load(&errors));
		fflush(stdout);
	}
	atomic_store(&stop, 1);
	for (int i = 0; i < n; i++)
		pthread_join(th[i], NULL);
	shutdown(ls, SHUT_RDWR);
	close(ls);
	pthread_cancel(lt);
	pthread_join(lt, NULL);

	if (vf >= 0) {
		ioctl(vf, PFSNITCH_VERDICT_FLUSH);	/* leave the cache empty */
		close(vf);
	}

	long err = atomic_load(&errors);
	printf("\nstress: done  conns=%ld queries=%ld matches=%ld forks=%ld push=%ld flush=%ld errors=%ld\n",
	    atomic_load(&conns), atomic_load(&queries), atomic_load(&matches),
	    atomic_load(&forks), atomic_load(&pushes), atomic_load(&flushes), err);
	/* `errors` counts INVARIANT violations and hard socket failures, not
	 * misses; a nonzero count is a real problem. */
	return (err == 0 ? 0 : 1);
}
