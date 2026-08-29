/*
 * pfsnitch_ioctl.h - the ABI between mac_pfsnitch.ko and the daemon.
 *
 * This struct crosses the kernel/userspace boundary by value, so it is all
 * fixed-size fields, no pointers, and explicitly padded. The Rust side
 * (src/kernattr.rs) mirrors it field-for-field with #[repr(C)]; any change
 * here must bump PFSNITCH_ATTR_VERSION and be made in both places.
 */

#ifndef _PFSNITCH_IOCTL_H_
#define _PFSNITCH_IOCTL_H_

#include <sys/ioccom.h>

#define PFSNITCH_ATTR_VERSION	1

/* found */
#define PFSNITCH_MISS		0	/* no socket, or one we never labeled */
#define PFSNITCH_MATCH_EXACT	1	/* full 4-tuple matched a connected socket */
#define PFSNITCH_MATCH_WILDCARD	2	/* bound-socket match (unconnected UDP) */

struct pfsnitch_attr {
	/* query - filled by the daemon */
	uint32_t	version;	/* PFSNITCH_ATTR_VERSION, rejected otherwise */
	uint8_t		af;		/* 4 or 6 - the packet's family, not AF_* */
	uint8_t		proto;		/* IPPROTO_TCP or IPPROTO_UDP */
	uint16_t	lport;		/* network byte order, as on the wire */
	uint16_t	fport;		/* network byte order */
	uint8_t		_pad0[2];
	uint8_t		laddr[16];	/* v4 uses the first 4 bytes */
	uint8_t		faddr[16];

	/* answer - filled by the kernel */
	uint8_t		found;		/* PFSNITCH_MISS / _MATCH_* */
	uint8_t		_pad1[3];
	int32_t		pid;		/* of the process that created the socket */
	uint32_t	uid;		/* effective uid at creation */
	uint8_t		_pad2[4];
	char		comm[24];	/* p_comm at creation, NUL-terminated */
	char		path[1024];	/* executable path; "" if unresolvable */
};

#define PFSNITCH_ATTR_QUERY	_IOWR('F', 1, struct pfsnitch_attr)

/*
 * Phase 2: in-kernel verdict cache.
 *
 * The daemon PUSHes a settled decision for one (binary, destination) pair; the
 * module caches it and, in socket_check_connect, answers a cached DENY by
 * failing connect() with EPERM - no packet, no divert. A cached ALLOW or a miss
 * returns 0 (the flow proceeds and, for now, still takes the divert path).
 *
 * The cache is address-keyed on purpose: the kernel has no resolver and no
 * wildcard matcher, so the daemon resolves hostnames to addresses and pushes
 * concrete entries. FLUSH abandons the whole cache - the daemon calls it on any
 * policy reload, the same moment it clears its own decided-verdict map.
 */
#define PFSNITCH_V_ALLOW	1
#define PFSNITCH_V_DENY		2

struct pfsnitch_verdict {
	uint32_t	version;	/* PFSNITCH_ATTR_VERSION */
	uint8_t		af;		/* 4 or 6 */
	uint8_t		proto;		/* IPPROTO_TCP or IPPROTO_UDP */
	uint16_t	fport;		/* destination port, network byte order */
	uint8_t		faddr[16];	/* destination address; v4 in first 4 bytes */
	uint8_t		verdict;	/* PFSNITCH_V_ALLOW / PFSNITCH_V_DENY */
	uint8_t		_pad[3];
	char		path[1024];	/* the binary this verdict is scoped to */
};

#define PFSNITCH_VERDICT_PUSH	_IOW('F', 2, struct pfsnitch_verdict)
#define PFSNITCH_VERDICT_FLUSH	_IO('F', 3)

#endif /* _PFSNITCH_IOCTL_H_ */
