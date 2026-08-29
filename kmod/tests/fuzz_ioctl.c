/*
 * fuzz_ioctl - throw malformed and adversarial input at /dev/pfsnitch.
 *
 * The ioctl is the module's entire userspace attack surface. _IOWR copies a
 * fixed-size struct in and out, so there is no buffer to overrun from here -
 * the risk is in what the module DOES with the field values: an af/proto it
 * did not expect, a tuple that makes in_pcblookup unhappy, a garbage version.
 *
 * This never asserts on a specific verdict (any tuple may legitimately miss).
 * It asserts on INVARIANTS the module must uphold no matter the input:
 *   - the process survives (a kernel panic takes the whole machine, which is
 *     the failure this test exists to provoke on a debug kernel);
 *   - a success return carries a `found` in {MISS, EXACT, WILDCARD};
 *   - a non-miss answer has NUL-terminated comm/path and a plausible pid.
 * A violation is reported and exits non-zero; a panic is caught by the driver
 * noticing the box went away.
 *
 *   cc -O2 -pthread -o fuzz_ioctl fuzz_ioctl.c
 *   ./fuzz_ioctl [-n iters] [-t threads] [-s seed]
 */

#include <sys/ioctl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "../pfsnitch_ioctl.h"

static long iters = 200000;
static int nthreads = 4;
static unsigned base_seed = 1;
static _Atomic long violations;

/* A cheap per-thread PRNG so threads do not contend on rand(). */
static uint32_t
xrand(uint32_t *s)
{
	*s ^= *s << 13;
	*s ^= *s >> 17;
	*s ^= *s << 5;
	return (*s);
}

/* Fill the struct with one of several flavours of hostile input. */
static void
poison(struct pfsnitch_attr *q, uint32_t *s)
{
	uint32_t mode = xrand(s) % 6;

	/* Start from uniform random bytes, then constrain per flavour. */
	unsigned char *p = (unsigned char *)q;
	for (size_t i = 0; i < sizeof(*q); i++)
		p[i] = (unsigned char)xrand(s);

	switch (mode) {
	case 0:
		/* Fully random - exercises the version/af/proto rejection. */
		break;
	case 1:
		/* Valid framing, random tuple: drives in_pcblookup with junk. */
		q->version = PFSNITCH_ATTR_VERSION;
		q->af = (xrand(s) & 1) ? 4 : 6;
		q->proto = (xrand(s) & 1) ? IPPROTO_TCP : IPPROTO_UDP;
		break;
	case 2:
		/* Right version, deliberately out-of-range af/proto. */
		q->version = PFSNITCH_ATTR_VERSION;
		q->af = (unsigned char)xrand(s);
		q->proto = (unsigned char)xrand(s);
		break;
	case 3:
		/* Boundary tuples: all-zero and all-ones addresses/ports. */
		q->version = PFSNITCH_ATTR_VERSION;
		q->af = (xrand(s) & 1) ? 4 : 6;
		q->proto = (xrand(s) & 1) ? IPPROTO_TCP : IPPROTO_UDP;
		memset(q->laddr, (xrand(s) & 1) ? 0x00 : 0xff, sizeof(q->laddr));
		memset(q->faddr, (xrand(s) & 1) ? 0x00 : 0xff, sizeof(q->faddr));
		q->lport = (xrand(s) & 1) ? 0 : 0xffff;
		q->fport = (xrand(s) & 1) ? 0 : 0xffff;
		break;
	case 4:
		/* Wrong version but otherwise valid - must be rejected, not read. */
		q->version = xrand(s);
		q->af = 4;
		q->proto = IPPROTO_TCP;
		break;
	case 5:
		/* Loopback tuple: most likely to actually resolve a socket, so
		 * the answer-copy path (strlcpy of comm/path) gets exercised. */
		q->version = PFSNITCH_ATTR_VERSION;
		q->af = 4;
		q->proto = (xrand(s) & 1) ? IPPROTO_TCP : IPPROTO_UDP;
		q->laddr[0] = 127; q->laddr[1] = 0; q->laddr[2] = 0; q->laddr[3] = 1;
		q->faddr[0] = 127; q->faddr[1] = 0; q->faddr[2] = 0; q->faddr[3] = 1;
		q->lport = (uint16_t)xrand(s);
		q->fport = (uint16_t)xrand(s);
		break;
	}
}

static void
check_answer(const struct pfsnitch_attr *q)
{
	if (q->found != PFSNITCH_MISS &&
	    q->found != PFSNITCH_MATCH_EXACT &&
	    q->found != PFSNITCH_MATCH_WILDCARD) {
		fprintf(stderr, "INVARIANT: found=%u out of range\n", q->found);
		atomic_fetch_add(&violations, 1);
		return;
	}
	if (q->found == PFSNITCH_MISS)
		return;
	/* A named answer must be safe to print: both strings NUL-terminated
	 * inside their fields, and a pid that is at least not negative. */
	if (memchr(q->comm, '\0', sizeof(q->comm)) == NULL) {
		fprintf(stderr, "INVARIANT: comm not NUL-terminated\n");
		atomic_fetch_add(&violations, 1);
	}
	if (memchr(q->path, '\0', sizeof(q->path)) == NULL) {
		fprintf(stderr, "INVARIANT: path not NUL-terminated\n");
		atomic_fetch_add(&violations, 1);
	}
	if (q->pid < 0) {
		fprintf(stderr, "INVARIANT: pid %d < 0\n", q->pid);
		atomic_fetch_add(&violations, 1);
	}
}

static void *
worker(void *arg)
{
	uint32_t s = base_seed ^ (uint32_t)(uintptr_t)arg * 2654435761u;
	if (s == 0)
		s = 1;
	int fd = open("/dev/pfsnitch", O_RDWR);
	if (fd < 0) {
		perror("open /dev/pfsnitch");
		atomic_fetch_add(&violations, 1);
		return (NULL);
	}
	for (long i = 0; i < iters; i++) {
		struct pfsnitch_attr q;
		poison(&q, &s);

		/* Mostly the real command; sometimes a random ioctl number to
		 * exercise the ENOTTY path and any generic cdev handling. */
		unsigned long cmd = (xrand(&s) % 16 == 0)
		    ? (unsigned long)xrand(&s)
		    : (unsigned long)PFSNITCH_ATTR_QUERY;

		if (ioctl(fd, cmd, &q) == 0 && cmd == PFSNITCH_ATTR_QUERY)
			check_answer(&q);
	}
	close(fd);
	return (NULL);
}

int
main(int argc, char **argv)
{
	int c;
	while ((c = getopt(argc, argv, "n:t:s:")) != -1) {
		switch (c) {
		case 'n': iters = atol(optarg); break;
		case 't': nthreads = atoi(optarg); break;
		case 's': base_seed = (unsigned)atol(optarg); break;
		default:
			fprintf(stderr, "usage: %s [-n iters] [-t threads] [-s seed]\n",
			    argv[0]);
			return (2);
		}
	}
	if (nthreads < 1)
		nthreads = 1;

	printf("fuzz_ioctl: %d threads x %ld iters, seed %u\n",
	    nthreads, iters, base_seed);

	pthread_t *th = calloc(nthreads, sizeof(*th));
	for (int i = 0; i < nthreads; i++)
		pthread_create(&th[i], NULL, worker, (void *)(uintptr_t)(i + 1));
	for (int i = 0; i < nthreads; i++)
		pthread_join(th[i], NULL);
	free(th);

	long v = atomic_load(&violations);
	printf("fuzz_ioctl: done, %ld invariant violations\n", v);
	return (v == 0 ? 0 : 1);
}
