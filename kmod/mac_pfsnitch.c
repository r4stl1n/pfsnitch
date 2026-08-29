/*-
 * mac_pfsnitch - kernel-side socket attribution for pfsnitch.
 *
 * The userspace attribution path (libprocstat) reconstructs "which process
 * owns this 4-tuple" backwards from a packet, by scanning every process's
 * file table. That is racy by construction: a process that connects and
 * exits is gone before the scan runs, and a scan is milliseconds of work
 * per miss.
 *
 * This module records identity FORWARDS, at the moment it is unambiguous:
 * socket creation runs in the creating process's own context, so pid, uid,
 * command and executable path are simply read off curproc - no scan, no
 * race, exact even for a process that exits immediately after connecting.
 * The identity rides the socket in its MAC label slot until the socket dies.
 *
 * The daemon asks questions through /dev/pfsnitch: "who owns proto X,
 * laddr:lport -> faddr:fport?" The lookup uses in_pcblookup(), the same
 * hash the stack itself resolves packets with, then reads our label off
 * the socket found.
 *
 * This is an OPTIONAL backend. The daemon works without this module loaded,
 * and falls back to libprocstat for any socket the module cannot answer for
 * (chiefly: sockets created before it was loaded, and accepted sockets,
 * which are born inside the kernel rather than by a syscall - acceptable
 * for an EGRESS tool, since accepted sockets never initiate a flow).
 *
 * Known limit, stated rather than hidden: identity is captured at
 * creation. A socket passed to another process over a unix socket, or
 * inherited across fork/exec, still names its creator. The userspace path
 * has the mirror-image ambiguity (it names whoever holds the fd at scan
 * time); neither is strictly stronger, but "creator" is the useful answer
 * for an egress prompt.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/rwlock.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/ucred.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet6/in6_pcb.h>

#include <security/mac/mac_policy.h>

#include "pfsnitch_ioctl.h"

static MALLOC_DEFINE(M_PFSNITCH, "pfsnitch", "pfsnitch socket attribution");

/*
 * Identity of a socket's creator, allocated at socket_create and freed at
 * label destruction. Kept on a global list so that module unload can free
 * whatever is still alive - after unregistering, the framework will never
 * call our destroy_label again, and freeing the malloc type with live
 * allocations is a panic.
 */
struct pfsn_info {
	TAILQ_ENTRY(pfsn_info)	link;
	pid_t			pid;
	uid_t			uid;
	char			comm[MAXCOMLEN + 1];
	char			path[];		/* NUL-terminated, may be "" */
};

static TAILQ_HEAD(, pfsn_info)	pfsn_all = TAILQ_HEAD_INITIALIZER(pfsn_all);
static struct mtx		pfsn_mtx;
static int			pfsn_slot;
static struct cdev		*pfsn_dev;

#define	SLOT(l)		((struct pfsn_info *)mac_label_get((l), pfsn_slot))
#define	SLOT_SET(l, v)	mac_label_set((l), pfsn_slot, (uintptr_t)(v))

/*
 * Verdict cache (Phase 2). One entry per (binary, destination) the daemon has
 * decided. Read on every connect(), written only when the daemon pushes or
 * flushes - so an rwlock, read-mostly. Keyed by hashing (proto, faddr, fport);
 * the owning binary path disambiguates within a bucket.
 */
struct pfsn_verdict {
	LIST_ENTRY(pfsn_verdict)	link;
	uint8_t		af;
	uint8_t		proto;
	uint8_t		verdict;	/* PFSNITCH_V_ALLOW / PFSNITCH_V_DENY */
	uint16_t	fport;		/* network byte order */
	uint8_t		faddr[16];
	uint16_t	pathlen;	/* strlen(path) + 1 */
	char		path[];
};

#define	PFSN_VHASH	1024		/* buckets, power of two */
#define	PFSN_VMAX	8192		/* entry cap; full cache just misses */

static LIST_HEAD(pfsn_vbucket, pfsn_verdict) pfsn_vtab[PFSN_VHASH];
static struct rwlock	pfsn_vlock;
static u_int		pfsn_vcount;

static void pfsn_cache_insert(uint8_t af, uint8_t proto, const uint8_t *faddr,
    uint16_t fport, uint8_t verdict, const char *path, size_t plen);

static uint32_t
pfsn_vhash(uint8_t af, uint8_t proto, const uint8_t *faddr, uint16_t fport)
{
	uint32_t h = 2166136261u;	/* FNV-1a */
	int i, n = (af == 4) ? 4 : 16;

	h = (h ^ proto) * 16777619u;
	h = (h ^ (fport & 0xff)) * 16777619u;
	h = (h ^ (fport >> 8)) * 16777619u;
	for (i = 0; i < n; i++)
		h = (h ^ faddr[i]) * 16777619u;
	return (h & (PFSN_VHASH - 1));
}

/* Caller holds pfsn_vlock (read). Returns 0 on miss. */
static int
pfsn_verdict_lookup(uint8_t af, uint8_t proto, const uint8_t *faddr,
    uint16_t fport, const char *path)
{
	struct pfsn_verdict *v;
	uint32_t b = pfsn_vhash(af, proto, faddr, fport);
	int n = (af == 4) ? 4 : 16;

	LIST_FOREACH(v, &pfsn_vtab[b], link) {
		if (v->af == af && v->proto == proto && v->fport == fport &&
		    memcmp(v->faddr, faddr, n) == 0 &&
		    strcmp(v->path, path) == 0)
			return (v->verdict);
	}
	return (0);
}

/* Insert one (binary, destination) verdict, deduping. Caller must NOT hold
 * pfsn_vlock; may hold pfsn_pmtx (lock order is pmtx -> vlock). */
static void
pfsn_cache_insert(uint8_t af, uint8_t proto, const uint8_t *faddr,
    uint16_t fport, uint8_t verdict, const char *path, size_t plen)
{
	struct pfsn_verdict *v;
	uint32_t b;
	int n = (af == 4) ? 4 : 16;

	if (plen == 0 || plen > 1024)
		return;
	b = pfsn_vhash(af, proto, faddr, fport);
	rw_wlock(&pfsn_vlock);
	LIST_FOREACH(v, &pfsn_vtab[b], link) {
		if (v->af == af && v->proto == proto && v->fport == fport &&
		    memcmp(v->faddr, faddr, n) == 0 &&
		    v->pathlen == plen && memcmp(v->path, path, plen) == 0) {
			v->verdict = verdict;		/* update in place */
			rw_wunlock(&pfsn_vlock);
			return;
		}
	}
	if (pfsn_vcount >= PFSN_VMAX) {
		rw_wunlock(&pfsn_vlock);
		return;
	}
	/* M_NOWAIT: cannot sleep holding the rwlock. */
	v = malloc(sizeof(*v) + plen, M_PFSNITCH, M_NOWAIT | M_ZERO);
	if (v == NULL) {
		rw_wunlock(&pfsn_vlock);
		return;
	}
	v->af = af;
	v->proto = proto;
	v->verdict = verdict;
	v->fport = fport;
	memcpy(v->faddr, faddr, sizeof(v->faddr));
	v->pathlen = plen;
	memcpy(v->path, path, plen);
	LIST_INSERT_HEAD(&pfsn_vtab[b], v, link);
	pfsn_vcount++;
	rw_wunlock(&pfsn_vlock);
}

static void
pfsn_verdict_push(const struct pfsnitch_verdict *pv)
{
	size_t plen = strnlen(pv->path, sizeof(pv->path));

	if (plen == 0 || plen >= sizeof(pv->path))
		return;			/* need a NUL-terminated, non-empty path */
	pfsn_cache_insert(pv->af, pv->proto, pv->faddr, pv->fport, pv->verdict,
	    pv->path, plen + 1);
}

static void
pfsn_verdict_flush(void)
{
	struct pfsn_verdict *v;
	int i;

	rw_wlock(&pfsn_vlock);
	for (i = 0; i < PFSN_VHASH; i++) {
		while ((v = LIST_FIRST(&pfsn_vtab[i])) != NULL) {
			LIST_REMOVE(v, link);
			free(v, M_PFSNITCH);
		}
	}
	pfsn_vcount = 0;
	rw_wunlock(&pfsn_vlock);
}

/*
 * ---------------------------------------------------------------------------
 * Phase 3: the fail-fast upcall.
 *
 * A cache miss becomes a request the daemon answers into the cache. The hook
 * never sleeps (it runs under the MAC framework's NOSLEEP rmlock): it enqueues
 * the request, wakes the daemon, and returns EAGAIN. The daemon read()s the
 * request, decides, and RESOLVEs it - inserting the verdict so the app's retry
 * hits. Requests are addressed by a monotonic id, never a pointer, so a resolve
 * racing a GC'd request is a harmless no-op.
 * ---------------------------------------------------------------------------
 */
#define	PFSN_REQ_MAX	2048		/* cap; full queue applies failmode */
#define	PFSN_REQ_GCAGE	150		/* seconds before an unanswered req is swept */

struct pfsn_req {
	TAILQ_ENTRY(pfsn_req)	link;
	uint64_t	id;
	uint8_t		af, proto, nonblock, delivered;
	uint16_t	fport;
	uint8_t		faddr[16];
	int		pid;
	uint32_t	uid;
	time_t		born;
	uint16_t	pathlen;
	char		path[];
};

static TAILQ_HEAD(, pfsn_req)	pfsn_reqs = TAILQ_HEAD_INITIALIZER(pfsn_reqs);
static struct mtx	pfsn_pmtx;
static uint64_t		pfsn_next_id = 1;
static u_int		pfsn_nreq;
static int		pfsn_unloading;
static int		pfsn_upcall_on;		/* daemon is servicing upcalls */
static int		pfsn_failmode = PFSNITCH_FAIL_OPEN;

static SYSCTL_NODE(_security_mac, OID_AUTO, pfsnitch,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0, "pfsnitch");
SYSCTL_INT(_security_mac_pfsnitch, OID_AUTO, failmode, CTLFLAG_RW,
    &pfsn_failmode, 0, "verdict when the daemon does not answer: 0=open 1=closed");
SYSCTL_UINT(_security_mac_pfsnitch, OID_AUTO, pending, CTLFLAG_RD,
    &pfsn_nreq, 0, "connect/send requests awaiting a verdict");

static int
pfsn_failverdict(void)
{
	return (pfsn_failmode == PFSNITCH_FAIL_CLOSED ? EPERM : 0);
}

/* Free requests the daemon never answered. Caller holds pfsn_pmtx. */
static void
pfsn_req_gc(void)
{
	struct pfsn_req *r, *tmp;
	time_t now = time_uptime;

	TAILQ_FOREACH_SAFE(r, &pfsn_reqs, link, tmp) {
		if ((now - r->born) > PFSN_REQ_GCAGE) {
			TAILQ_REMOVE(&pfsn_reqs, r, link);
			pfsn_nreq--;
			free(r, M_PFSNITCH);
		}
	}
}

/*
 * A verdict-cache miss reached the hook. Enqueue it for the daemon and return
 * EAGAIN (retry). Never sleeps. Deduplicates: a second miss for a request
 * already pending just returns EAGAIN without queuing another.
 */
static int
pfsn_upcall(uint8_t af, uint8_t proto, const uint8_t *faddr, uint16_t fport,
    const struct pfsn_info *info, int nonblock)
{
	struct pfsn_req *r;
	size_t plen;
	int n = (af == 4) ? 4 : 16;

	plen = strnlen(info->path, 1024);
	if (plen == 0 || plen >= 1024)
		return (0);			/* nothing to key on; let it pass */
	plen += 1;

	mtx_lock(&pfsn_pmtx);
	if (pfsn_unloading) {
		mtx_unlock(&pfsn_pmtx);
		return (pfsn_failverdict());
	}
	TAILQ_FOREACH(r, &pfsn_reqs, link) {
		if (r->af == af && r->proto == proto && r->fport == fport &&
		    memcmp(r->faddr, faddr, n) == 0 &&
		    r->pathlen == plen && memcmp(r->path, info->path, plen) == 0) {
			mtx_unlock(&pfsn_pmtx);
			return (EAGAIN);	/* already asked; retry later */
		}
	}
	if (pfsn_nreq >= PFSN_REQ_MAX) {
		mtx_unlock(&pfsn_pmtx);
		return (pfsn_failverdict());
	}
	pfsn_req_gc();
	/* M_NOWAIT: the hook must not sleep. */
	r = malloc(sizeof(*r) + plen, M_PFSNITCH, M_NOWAIT | M_ZERO);
	if (r == NULL) {
		mtx_unlock(&pfsn_pmtx);
		return (pfsn_failverdict());
	}
	r->id = pfsn_next_id++;
	r->af = af;
	r->proto = proto;
	r->nonblock = nonblock ? 1 : 0;
	r->fport = fport;
	memcpy(r->faddr, faddr, sizeof(r->faddr));
	r->pid = info->pid;
	r->uid = info->uid;
	r->born = time_uptime;
	r->pathlen = plen;
	memcpy(r->path, info->path, plen);
	TAILQ_INSERT_TAIL(&pfsn_reqs, r, link);
	pfsn_nreq++;
	wakeup(&pfsn_reqs);			/* nudge the daemon's read() */
	mtx_unlock(&pfsn_pmtx);
	return (EAGAIN);
}

/* Daemon answers request `id`: cache the verdict and drop the request. An
 * unknown id (already GC'd, or a stale answer) is a harmless no-op. */
static void
pfsn_resolve(uint64_t id, uint8_t verdict)
{
	struct pfsn_req *r;

	mtx_lock(&pfsn_pmtx);
	TAILQ_FOREACH(r, &pfsn_reqs, link) {
		if (r->id != id)
			continue;
		pfsn_cache_insert(r->af, r->proto, r->faddr, r->fport, verdict,
		    r->path, r->pathlen);
		TAILQ_REMOVE(&pfsn_reqs, r, link);
		pfsn_nreq--;
		free(r, M_PFSNITCH);
		break;
	}
	mtx_unlock(&pfsn_pmtx);
}

/* Deliver the next undelivered request to the daemon. Blocks (legally - this is
 * the daemon's read() thread, not the hook) until one exists or unload/EINTR. */
static int
pfsn_read(struct cdev *dev, struct uio *uio, int flags)
{
	struct pfsn_req *r;
	struct pfsnitch_event ev;
	int error;

	if (uio->uio_resid < (ssize_t)sizeof(ev))
		return (EINVAL);

	mtx_lock(&pfsn_pmtx);
	for (;;) {
		/* EOF when unloading, or when the daemon has turned upcalls off
		 * (its own signal to stop reading) - so a blocked read() returns
		 * instead of wedging the daemon's shutdown. */
		if (pfsn_unloading || !pfsn_upcall_on) {
			mtx_unlock(&pfsn_pmtx);
			return (0);
		}
		TAILQ_FOREACH(r, &pfsn_reqs, link) {
			if (!r->delivered)
				break;
		}
		if (r != NULL)
			break;
		error = msleep(&pfsn_reqs, &pfsn_pmtx, PCATCH, "pfsnrd", 0);
		if (error != 0) {
			mtx_unlock(&pfsn_pmtx);
			return (error);		/* EINTR */
		}
	}
	r->delivered = 1;
	memset(&ev, 0, sizeof(ev));
	ev.id = r->id;
	ev.af = r->af;
	ev.proto = r->proto;
	ev.fport = r->fport;
	memcpy(ev.faddr, r->faddr, sizeof(ev.faddr));
	ev.nonblock = r->nonblock;
	ev.pid = r->pid;
	ev.uid = r->uid;
	strlcpy(ev.path, r->path, sizeof(ev.path));
	mtx_unlock(&pfsn_pmtx);

	return (uiomove(&ev, sizeof(ev), uio));	/* outside the lock: may fault */
}

/*
 * ---------------------------------------------------------------------------
 * Label lifecycle.
 * ---------------------------------------------------------------------------
 */

static int
pfsn_socket_init_label(struct label *label, int flag)
{
	SLOT_SET(label, NULL);
	return (0);
}

static void
pfsn_socket_destroy_label(struct label *label)
{
	struct pfsn_info *info;

	info = SLOT(label);
	if (info == NULL)
		return;
	SLOT_SET(label, NULL);
	mtx_lock(&pfsn_mtx);
	TAILQ_REMOVE(&pfsn_all, info, link);
	mtx_unlock(&pfsn_mtx);
	free(info, M_PFSNITCH);
}

/*
 * socket(2) is running: curproc IS the owner. Capture it.
 *
 * socreate() is a sleepable context, so the M_WAITOK allocation and the
 * vn_fullpath() name-cache walk are both fine here.
 */
static void
pfsn_socket_create(struct ucred *cred, struct socket *so, struct label *solabel)
{
	struct pfsn_info *info;
	struct proc *p;
	struct vnode *vp;
	char *retbuf, *freebuf;
	size_t plen;

	if (solabel == NULL)
		return;

	p = curproc;

	/* Executable path via the name cache. May legitimately fail - a
	 * kernel thread has no text vnode - in which case path stays "". */
	retbuf = NULL;
	freebuf = NULL;
	PROC_LOCK(p);
	vp = p->p_textvp;
	if (vp != NULL)
		vref(vp);
	PROC_UNLOCK(p);
	if (vp != NULL) {
		if (vn_fullpath(vp, &retbuf, &freebuf) != 0) {
			retbuf = NULL;
			freebuf = NULL;
		}
		vrele(vp);
	}

	plen = (retbuf != NULL) ? strlen(retbuf) + 1 : 1;
	info = malloc(sizeof(*info) + plen, M_PFSNITCH, M_WAITOK | M_ZERO);
	info->pid = p->p_pid;
	info->uid = cred->cr_uid;
	strlcpy(info->comm, p->p_comm, sizeof(info->comm));
	if (retbuf != NULL)
		memcpy(info->path, retbuf, plen);
	if (freebuf != NULL)
		free(freebuf, M_TEMP);

	mtx_lock(&pfsn_mtx);
	TAILQ_INSERT_TAIL(&pfsn_all, info, link);
	mtx_unlock(&pfsn_mtx);
	SLOT_SET(solabel, info);
}

/*
 * connect(2) is running for `so`. If the daemon has already pushed a DENY for
 * this socket's owning binary to this destination, fail the connect now - no
 * packet leaves, nothing diverts. A cached ALLOW or a miss returns 0: the flow
 * proceeds, and (until divert is retired in a later phase) is still governed by
 * the divert path, so this hook can only ever turn a connect into EPERM, never
 * admit something the daemon has not seen.
 *
 * Identity comes from the socket's own label - the creator recorded at
 * socket() - to match how attribution names a flow, not from curproc at
 * connect (which may differ if the fd was passed between processes).
 */
static int
pfsn_socket_check_connect(struct ucred *cred, struct socket *so,
    struct label *solabel, struct sockaddr *sa)
{
	struct pfsn_info *info;
	uint8_t af, proto, faddr[16];
	uint16_t fport;
	int verdict;

	if (sa == NULL || solabel == NULL)
		return (0);

	switch (so->so_type) {
	case SOCK_STREAM:	proto = IPPROTO_TCP; break;
	case SOCK_DGRAM:	proto = IPPROTO_UDP; break;
	default:		return (0);
	}

	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)sa;
		af = 4;
		fport = sin->sin_port;
		memcpy(faddr, &sin->sin_addr, 4);
	} else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
		af = 6;
		fport = sin6->sin6_port;
		memcpy(faddr, &sin6->sin6_addr, 16);
	} else
		return (0);

	/* No label means a socket from before the module loaded - let the
	 * divert path handle it, exactly as attribution would miss it. The
	 * label's fields are stable while we hold this socket in connect(). */
	info = SLOT(solabel);
	if (info == NULL || info->path[0] == '\0')
		return (0);

	rw_rlock(&pfsn_vlock);
	verdict = pfsn_verdict_lookup(af, proto, faddr, fport, info->path);
	rw_runlock(&pfsn_vlock);

	if (verdict == PFSNITCH_V_DENY)
		return (EPERM);
	if (verdict == PFSNITCH_V_ALLOW)
		return (0);

	/* Miss. If the daemon is servicing upcalls (Phase 3), ask it: enqueue and
	 * return EAGAIN so the app retries once the answer is cached. Otherwise
	 * fall through (return 0) and let the divert path decide, as in Phase 2. */
	if (pfsn_upcall_on)
		return (pfsn_upcall(af, proto, faddr, fport, info,
		    (so->so_state & SS_NBIO) != 0));
	return (0);
}

/*
 * ---------------------------------------------------------------------------
 * The query device.
 * ---------------------------------------------------------------------------
 */

/*
 * Find the inpcb for a query the way the stack would, and copy its
 * creator's identity into the answer. Runs under the net epoch; the
 * lookup returns the inpcb read-locked, which is what keeps
 * inp_socket stable (detach requires the write lock) and therefore
 * keeps the label - freed only after detach - alive while we read it.
 */
static void
pfsn_lookup(struct pfsnitch_attr *q)
{
	struct epoch_tracker et;
	struct inpcbinfo *pcbinfo;
	struct inpcb *inp;
	struct pfsn_info *info;
	struct socket *so;

	q->found = PFSNITCH_MISS;
	q->pid = 0;
	q->uid = 0;
	q->comm[0] = '\0';
	q->path[0] = '\0';

	pcbinfo = (q->proto == IPPROTO_TCP) ? &V_tcbinfo : &V_udbinfo;

	NET_EPOCH_ENTER(et);
	if (q->af == 4) {
		struct in_addr laddr, faddr;

		memcpy(&laddr, q->laddr, sizeof(laddr));
		memcpy(&faddr, q->faddr, sizeof(faddr));
		inp = in_pcblookup(pcbinfo, faddr, q->fport, laddr, q->lport,
		    INPLOOKUP_RLOCKPCB, NULL);
		if (inp != NULL)
			q->found = PFSNITCH_MATCH_EXACT;
		else if (q->proto == IPPROTO_UDP) {
			/* Unconnected UDP: match the bound socket, the same
			 * wildcard walk an inbound datagram would take. */
			inp = in_pcblookup(pcbinfo, faddr, q->fport, laddr,
			    q->lport, INPLOOKUP_WILDCARD | INPLOOKUP_RLOCKPCB,
			    NULL);
			if (inp != NULL)
				q->found = PFSNITCH_MATCH_WILDCARD;
		}
	} else {
		struct in6_addr laddr6, faddr6;

		memcpy(&laddr6, q->laddr, sizeof(laddr6));
		memcpy(&faddr6, q->faddr, sizeof(faddr6));
		inp = in6_pcblookup(pcbinfo, &faddr6, q->fport, &laddr6,
		    q->lport, INPLOOKUP_RLOCKPCB, NULL);
		if (inp != NULL)
			q->found = PFSNITCH_MATCH_EXACT;
		else if (q->proto == IPPROTO_UDP) {
			inp = in6_pcblookup(pcbinfo, &faddr6, q->fport,
			    &laddr6, q->lport,
			    INPLOOKUP_WILDCARD | INPLOOKUP_RLOCKPCB, NULL);
			if (inp != NULL)
				q->found = PFSNITCH_MATCH_WILDCARD;
		}
	}

	if (inp != NULL) {
		so = inp->inp_socket;
		if (so != NULL && so->so_label != NULL &&
		    (info = SLOT(so->so_label)) != NULL) {
			q->pid = info->pid;
			q->uid = info->uid;
			strlcpy(q->comm, info->comm, sizeof(q->comm));
			strlcpy(q->path, info->path, sizeof(q->path));
		} else {
			/* The socket exists but predates the module (or was
			 * born via accept). Report the miss honestly so the
			 * daemon falls back to its userspace path. */
			q->found = PFSNITCH_MISS;
		}
		INP_RUNLOCK(inp);
	}
	NET_EPOCH_EXIT(et);
}

static int
pfsn_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	struct pfsnitch_attr *q;

	if (cmd == PFSNITCH_VERDICT_PUSH) {
		struct pfsnitch_verdict *pv = (struct pfsnitch_verdict *)data;

		if (pv->version != PFSNITCH_ATTR_VERSION)
			return (EINVAL);
		if (pv->af != 4 && pv->af != 6)
			return (EINVAL);
		if (pv->proto != IPPROTO_TCP && pv->proto != IPPROTO_UDP)
			return (EINVAL);
		if (pv->verdict != PFSNITCH_V_ALLOW &&
		    pv->verdict != PFSNITCH_V_DENY)
			return (EINVAL);
		pfsn_verdict_push(pv);
		return (0);
	}
	if (cmd == PFSNITCH_VERDICT_FLUSH) {
		pfsn_verdict_flush();
		return (0);
	}
	if (cmd == PFSNITCH_RESOLVE) {
		struct pfsnitch_resolve *pr = (struct pfsnitch_resolve *)data;

		if (pr->version != PFSNITCH_ATTR_VERSION)
			return (EINVAL);
		if (pr->verdict != PFSNITCH_V_ALLOW &&
		    pr->verdict != PFSNITCH_V_DENY)
			return (EINVAL);
		pfsn_resolve(pr->id, pr->verdict);
		return (0);
	}
	if (cmd == PFSNITCH_UPCALL_SET) {
		int on = *(int *)data;

		mtx_lock(&pfsn_pmtx);
		pfsn_upcall_on = on ? 1 : 0;
		if (!pfsn_upcall_on)
			wakeup(&pfsn_reqs);	/* release a blocked reader */
		mtx_unlock(&pfsn_pmtx);
		return (0);
	}
	if (cmd != PFSNITCH_ATTR_QUERY)
		return (ENOTTY);
	q = (struct pfsnitch_attr *)data;
	if (q->version != PFSNITCH_ATTR_VERSION)
		return (EINVAL);
	if (q->af != 4 && q->af != 6)
		return (EINVAL);
	if (q->proto != IPPROTO_TCP && q->proto != IPPROTO_UDP)
		return (EINVAL);

	CURVNET_SET(TD_TO_VNET(td));
	pfsn_lookup(q);
	CURVNET_RESTORE();
	return (0);
}

static struct cdevsw pfsn_cdevsw = {
	.d_version =	D_VERSION,
	.d_name =	"pfsnitch",
	.d_ioctl =	pfsn_ioctl,
	.d_read =	pfsn_read,
};

/*
 * ---------------------------------------------------------------------------
 * Policy registration.
 * ---------------------------------------------------------------------------
 */

static void
pfsn_init(struct mac_policy_conf *conf)
{
	int i;

	mtx_init(&pfsn_mtx, "pfsnitch", NULL, MTX_DEF);
	mtx_init(&pfsn_pmtx, "pfsnitch pend", NULL, MTX_DEF);
	rw_init(&pfsn_vlock, "pfsnitch vcache");
	for (i = 0; i < PFSN_VHASH; i++)
		LIST_INIT(&pfsn_vtab[i]);
	pfsn_dev = make_dev(&pfsn_cdevsw, 0, UID_ROOT, GID_WHEEL, 0600,
	    "pfsnitch");
}

static void
pfsn_destroy(struct mac_policy_conf *conf)
{
	struct pfsn_info *info;
	struct pfsn_req *r;

	/* Release the daemon's blocked read() BEFORE destroy_dev, or destroy_dev
	 * waits forever on it. Fail-fast has no sleeping hook waiters to drain -
	 * the only sleeper is the reader - so this is all it takes. New hook
	 * upcalls cannot arrive: the policy is already unregistered by the time
	 * mpo_destroy runs. */
	mtx_lock(&pfsn_pmtx);
	pfsn_unloading = 1;
	wakeup(&pfsn_reqs);
	while ((r = TAILQ_FIRST(&pfsn_reqs)) != NULL) {
		TAILQ_REMOVE(&pfsn_reqs, r, link);
		free(r, M_PFSNITCH);
	}
	pfsn_nreq = 0;
	mtx_unlock(&pfsn_pmtx);

	if (pfsn_dev != NULL)
		destroy_dev(pfsn_dev);
	mtx_destroy(&pfsn_pmtx);

	/* Sockets that outlive the module keep a stale slot value nobody
	 * will ever read (only this module reads the slot); their info is
	 * freed here so the malloc type is empty when it is torn down. */
	mtx_lock(&pfsn_mtx);
	while ((info = TAILQ_FIRST(&pfsn_all)) != NULL) {
		TAILQ_REMOVE(&pfsn_all, info, link);
		free(info, M_PFSNITCH);
	}
	mtx_unlock(&pfsn_mtx);
	mtx_destroy(&pfsn_mtx);

	/* Free the verdict cache too, for the same reason: the malloc type
	 * must be empty before it is torn down. */
	pfsn_verdict_flush();
	rw_destroy(&pfsn_vlock);
}

static struct mac_policy_ops pfsn_ops = {
	.mpo_init = pfsn_init,
	.mpo_destroy = pfsn_destroy,
	.mpo_socket_init_label = pfsn_socket_init_label,
	.mpo_socket_destroy_label = pfsn_socket_destroy_label,
	.mpo_socket_create = pfsn_socket_create,
	.mpo_socket_check_connect = pfsn_socket_check_connect,
};

MAC_POLICY_SET(&pfsn_ops, mac_pfsnitch, "pfsnitch socket attribution",
    MPC_LOADTIME_FLAG_UNLOADOK, &pfsn_slot);
MODULE_VERSION(mac_pfsnitch, 1);
