/*
 * vtest - functional test of the Phase 2 verdict cache and connect hook.
 *
 * Independent of the daemon and pf: it pushes verdicts straight into the module
 * and checks that connect() honours them. The socket is created after the push,
 * so its label carries this process's own exec path, which is exactly the path
 * the verdict is scoped to.
 *
 * Checks:
 *   1. a cached DENY makes connect() fail with EPERM, before any packet;
 *   2. a destination with no entry is NOT EPERM (misses fall through);
 *   3. a cached ALLOW is NOT EPERM;
 *   4. FLUSH clears the deny — connect() is no longer EPERM.
 *
 *   cc -o vtest vtest.c && doas ./vtest
 */

#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../pfsnitch_ioctl.h"

static int dev;
static char path[1024];
static int fails;

static void
mypath(void)
{
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1 };
	size_t l = sizeof(path);
	if (sysctl(mib, 4, path, &l, NULL, 0) < 0)
		err(1, "sysctl KERN_PROC_PATHNAME");
}

static void
vpush(const char *ip, int port, int verdict)
{
	struct pfsnitch_verdict v;
	memset(&v, 0, sizeof(v));
	v.version = PFSNITCH_ATTR_VERSION;
	v.af = 4;
	v.proto = IPPROTO_TCP;
	v.fport = htons(port);
	inet_pton(AF_INET, ip, v.faddr);
	v.verdict = verdict;
	strlcpy(v.path, path, sizeof(v.path));
	if (ioctl(dev, PFSNITCH_VERDICT_PUSH, &v) < 0)
		err(1, "PFSNITCH_VERDICT_PUSH");
}

/* Return errno from a blocking connect to a loopback port (nothing listens, so
 * a permitted attempt refuses fast); 0 if it somehow connected. */
static int
try_connect(const char *ip, int port)
{
	struct sockaddr_in d;
	int s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		err(1, "socket");
	memset(&d, 0, sizeof(d));
	d.sin_family = AF_INET;
	d.sin_port = htons(port);
	inet_pton(AF_INET, ip, &d.sin_addr);
	int r = connect(s, (struct sockaddr *)&d, sizeof(d));
	int e = (r == 0) ? 0 : errno;
	close(s);
	return (e);
}

static void
expect(const char *what, int got, int want)
{
	int ok = (got == want);
	printf("  %-46s got=%-14s %s\n", what, strerror(got),
	    ok ? "ok" : "FAIL");
	if (!ok) {
		printf("      expected %s\n", strerror(want));
		fails++;
	}
}

int
main(void)
{
	dev = open("/dev/pfsnitch", O_RDWR);
	if (dev < 0)
		err(1, "/dev/pfsnitch (is mac_pfsnitch loaded?)");
	mypath();
	printf("vtest: my path = %s\n", path);

	/* Clean slate. */
	if (ioctl(dev, PFSNITCH_VERDICT_FLUSH) < 0)
		err(1, "FLUSH");

	vpush("127.0.0.1", 9, PFSNITCH_V_DENY);
	vpush("127.0.0.1", 11, PFSNITCH_V_ALLOW);

	expect("cached DENY -> connect() EPERM",
	    try_connect("127.0.0.1", 9), EPERM);
	expect("no entry -> not EPERM (miss falls through)",
	    try_connect("127.0.0.1", 10), ECONNREFUSED);
	expect("cached ALLOW -> not EPERM",
	    try_connect("127.0.0.1", 11), ECONNREFUSED);

	if (ioctl(dev, PFSNITCH_VERDICT_FLUSH) < 0)
		err(1, "FLUSH");
	expect("after FLUSH, former DENY -> not EPERM",
	    try_connect("127.0.0.1", 9), ECONNREFUSED);

	close(dev);
	printf("vtest: %s\n", fails == 0 ? "ALL PASSED" : "FAILURES");
	return (fails == 0 ? 0 : 1);
}
