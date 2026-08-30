/*
 * kquery - poke /dev/pfsnitch by hand.
 *
 * Diagnostic for the mac_pfsnitch module, not part of the daemon:
 *
 *   kquery selftest [host port]   connect a TCP socket (default 127.0.0.1:22),
 *                                 then ask the kernel who owns it. The right
 *                                 answer is this process and this binary.
 *   kquery udptest [host port]    same, with an unconnected UDP sendto, which
 *                                 must come back as a wildcard match.
 *   kquery tcp|udp <laddr> <lport> <faddr> <fport>
 *                                 query an arbitrary tuple.
 *
 * cc -o kquery kquery.c
 */

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pfsnitch_ioctl.h"

static const char *
foundstr(int f)
{
	switch (f) {
	case PFSNITCH_MATCH_EXACT:	return "exact";
	case PFSNITCH_MATCH_WILDCARD:	return "wildcard";
	default:			return "miss";
	}
}

static int
query(struct pfsnitch_attr *q)
{
	int fd;

	fd = open("/dev/pfsnitch", O_RDWR);
	if (fd < 0)
		err(1, "/dev/pfsnitch (is mac_pfsnitch.ko loaded?)");
	q->version = PFSNITCH_ATTR_VERSION;
	if (ioctl(fd, PFSNITCH_ATTR_QUERY, q) < 0)
		err(1, "PFSNITCH_ATTR_QUERY");
	close(fd);

	printf("%s pid=%d uid=%u comm=%s path=%s\n",
	    foundstr(q->found), (int)q->pid, (unsigned)q->uid,
	    q->comm[0] ? q->comm : "-", q->path[0] ? q->path : "-");
	return (q->found == PFSNITCH_MISS ? 1 : 0);
}

/* Fill laddr/lport and faddr/fport from a socket's own view of itself. */
static void
tuple_of(int s, struct pfsnitch_attr *q, int want_peer)
{
	struct sockaddr_storage ss;
	socklen_t len;

	len = sizeof(ss);
	if (getsockname(s, (struct sockaddr *)&ss, &len) < 0)
		err(1, "getsockname");
	if (ss.ss_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
		q->af = 4;
		q->lport = sin->sin_port;
		memcpy(q->laddr, &sin->sin_addr, 4);
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
		q->af = 6;
		q->lport = sin6->sin6_port;
		memcpy(q->laddr, &sin6->sin6_addr, 16);
	}
	if (!want_peer)
		return;
	len = sizeof(ss);
	if (getpeername(s, (struct sockaddr *)&ss, &len) < 0)
		err(1, "getpeername");
	if (ss.ss_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
		q->fport = sin->sin_port;
		memcpy(q->faddr, &sin->sin_addr, 4);
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
		q->fport = sin6->sin6_port;
		memcpy(q->faddr, &sin6->sin6_addr, 16);
	}
}

static int
selftest(int argc, char **argv, int udp)
{
	struct pfsnitch_attr q;
	struct sockaddr_in dst;
	const char *host = argc > 2 ? argv[2] : "127.0.0.1";
	int port = argc > 3 ? atoi(argv[3]) : 22;
	int s;

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_port = htons(port);
	if (inet_pton(AF_INET, host, &dst.sin_addr) != 1)
		errx(1, "bad address %s", host);

	s = socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
	if (s < 0)
		err(1, "socket");

	memset(&q, 0, sizeof(q));
	if (udp) {
		/* Unconnected: sendto() binds an ephemeral port but records
		 * no peer, so the kernel must fall back to the wildcard walk. */
		if (sendto(s, "x", 1, 0, (struct sockaddr *)&dst,
		    sizeof(dst)) < 0)
			err(1, "sendto");
		q.proto = 17;
		tuple_of(s, &q, 0);
		q.fport = dst.sin_port;
		memcpy(q.faddr, &dst.sin_addr, 4);
	} else {
		if (connect(s, (struct sockaddr *)&dst, sizeof(dst)) < 0)
			err(1, "connect %s:%d", host, port);
		q.proto = 6;
		tuple_of(s, &q, 1);
	}

	printf("querying own %s socket -> ", udp ? "udp" : "tcp");
	int rc = query(&q);
	if (rc == 0 && q.pid != getpid()) {
		printf("FAIL: kernel names pid %d, but we are %d\n",
		    (int)q.pid, (int)getpid());
		rc = 1;
	}
	close(s);
	return (rc);
}

int
main(int argc, char **argv)
{
	struct pfsnitch_attr q;

	if (argc >= 2 && strcmp(argv[1], "selftest") == 0)
		return (selftest(argc, argv, 0));
	if (argc >= 2 && strcmp(argv[1], "udptest") == 0)
		return (selftest(argc, argv, 1));

	if (argc != 6)
		errx(1, "usage: kquery selftest|udptest [host port]\n"
		    "       kquery tcp|udp <laddr> <lport> <faddr> <fport>");

	memset(&q, 0, sizeof(q));
	q.proto = strcmp(argv[1], "udp") == 0 ? 17 : 6;
	q.af = strchr(argv[2], ':') ? 6 : 4;
	if (inet_pton(q.af == 4 ? AF_INET : AF_INET6, argv[2], q.laddr) != 1)
		errx(1, "bad local address");
	if (inet_pton(q.af == 4 ? AF_INET : AF_INET6, argv[4], q.faddr) != 1)
		errx(1, "bad foreign address");
	q.lport = htons(atoi(argv[3]));
	q.fport = htons(atoi(argv[5]));
	return (query(&q));
}
