# Kernel module roadmap

The plan for taking `mac_pfsnitch` from an attribution helper to an in-kernel
filter that decides TCP and UDP per packet without the divert round trip. This
is the **kernel route only** — the pf state-bypass alternative (“Option A”) is
deliberately out of scope here.

The guiding principle is unchanged from Phase 1: **the kernel stays a cache, the
daemon stays the brain.** Policy — hostnames, wildcards, modes, per-binary rules —
is expressed in userspace and always will be. Each phase moves a *decision that
has already been made* closer to the packet, never the decision-making itself.
Every phase must survive the stress/fuzz harness under the debug kernel
(`kmod/tests/`, `GENERIC-DEBUG`) before it is called done.

## Status

| Phase | Goal | Status |
|---|---|---|
| 1 | Attribution oracle | **Done** — tested under INVARIANTS/WITNESS |
| 2 | In-kernel verdict cache (cached deny → EPERM at connect) | **Done** — tested under INVARIANTS/WITNESS |
| 3 | Fail-fast upcall — decide misses in-kernel, no divert | **Done** — kernel + daemon reader, tested end-to-end (TCP+UDP) |
| 4 | Slim the divert — in-kernel per-packet **UDP** (keep TCP on divert) | **Done** — UDP divert retired via a daemon-controlled sub-anchor; the per-packet win |
| 5 | Failmode + hardening (watchdog, stale cache, KBI) | Next |

> **The key realisation.** The destination-bearing hook `socket_check_connect`
> is not only fired on `connect(2)`: `kern_sendit` calls it on every
> `sendto`/`sendmsg` that carries a destination —
> `if (mp->msg_name != NULL) mac_socket_check_connect(cred, so, mp->msg_name)`.
> So **unconnected UDP datagrams reach the same hook, with the destination**,
> on every send. That means the cache we built already sees all outbound flow
> starts *and* unconnected UDP, and once the divert rules are slimmed (Phase 4)
> each datagram is decided by an in-kernel cache lookup instead of a userspace
> round trip. This is the path to the per-packet UDP overhead that started all
> of this — reachable through the hook we already have.
>
> (An earlier version of this doc concluded the opposite, on the false premise
> that unconnected UDP never reaches a destination-bearing hook. It does.)

**On blocking:** we never sleep in the hook — `socket_check_connect` runs under
the MAC framework's `MAC_POLICY_CHECK_NOSLEEP` rmlock, so `msleep` there is
illegal. We do not need to: on a miss the hook enqueues the request and returns
immediately (`EAGAIN`), the daemon decides asynchronously and caches, and the
app's retry resolves. A dropped first packet is carried by the protocol's own
retransmission — TCP's SYN retries, QUIC's datagram retries — so the connection
survives the decision window without a packet leaking before approval.

**Phase 2 as built** enforces the *deny* side in the hook — a cached deny fails
`connect()`/`sendto()` with `EPERM`, before any packet. A cached allow and a
miss return 0 and (for now) still take the divert path. The daemon pushes
verdicts only while enforcing and flushes on every policy reload, so visibility
never blocks and a cached verdict never outlives its rule. See
`kmod/tests/vtest.c` (functional) and the verdict-cache stress in
`kmod/tests/stress.c`.

## The one constraint that shapes everything

**The kernel only ever sees addresses; policy is written in hostnames.** A rule
like `allow-host-from github.com /usr/local/bin/git` cannot be evaluated in the
kernel — the module has no resolver and no wildcard matcher, and must not grow
one. So from Phase 2 on, the in-kernel table is an **address-keyed cache of
decisions the daemon already made**. The daemon resolves names to addresses (it
already builds this map in `dns.rs`) and pushes concrete address entries down.

Consequence to hold onto: the kernel can answer “is `10.0.0.2:443` for
`/usr/bin/foo` allowed?” but never “does this match `*.example.com`?”. A flow
whose verdict the daemon has not yet pushed is a **cache miss**, and a miss is
always resolved in userspace.

---

## Phase 2 — In-kernel verdict cache

**Goal.** Decide *known* flows in the kernel at `connect()` time, with no upcall
and no divert round trip. Unknown flows keep falling through to the existing
divert path exactly as today.

**Kernel work.**
- A flow→verdict hash table (key: proto + faddr + fport + owning-binary
  identity; value: allow/deny + generation). Reuse the label’s binary identity
  so the key ties a destination to a specific executable, matching how policy is
  scoped.
- Consult it in `mpo_socket_check_connect` (covers TCP and connected UDP). Hit →
  return `0` (allow) or `EPERM` (deny) with no upcall. Miss → return `0` and let
  the packet reach the divert path, where the daemon decides as it does now.
- New ioctls on `/dev/pfsnitch` for the daemon to **push** and **invalidate**
  entries, plus a generation/epoch counter so a policy reload can flush the whole
  cache in one step.

**Daemon work.**
- When a verdict settles (approved, denied, or learned), resolve it to concrete
  addresses and push an entry down. Hostname rules expand to one entry per known
  address from the DNS cache; a newly-learned address for a wildcard rule pushes
  a new entry as it is seen.
- On any policy reload or mode switch, bump the generation so the kernel cache is
  abandoned wholesale — mirrors how the daemon already clears its `decided` map.

**Flow change.** A repeat connection to an already-decided destination never
diverts — the verdict is returned inside `connect()`. First contact with a new
destination is unchanged (divert → daemon → push verdict → subsequent connects
are in-kernel).

**Risks / decisions.**
- **Keying granularity.** Per-(binary, dst, dport) matches policy scoping but
  multiplies entries; a coarser key risks under-enforcing. Start binary-scoped.
- **`EPERM` vs synthesized RST.** The daemon today answers a settled deny with a
  crafted RST so the app sees `Connection refused`. `EPERM` from `connect()` is
  the same user-visible outcome and simpler — adopt it for the in-kernel deny.
- **Invalidation correctness.** A stale allow after a rule is removed is a
  security failure. The generation counter must gate every lookup.

**Done when.** Known flows show zero diverts (verify with the divert counter);
cache survives the stress/fuzz harness; a removed rule provably stops matching
before the next connection.

---

## Phase 3 — Fail-fast upcall (decide misses in-kernel)

**Goal.** Let the hook resolve a cache miss without the divert path: enqueue the
request, return immediately, and let the daemon decide asynchronously and cache
the verdict for the retry. No thread ever sleeps in the hook.

**Why fail-fast, not a hold.** `socket_check_connect` runs under
`MAC_POLICY_CHECK_NOSLEEP` (an rmlock read lock), so `msleep` in the hook is
illegal — it would panic under INVARIANTS. Fail-fast never sleeps: `mtx_lock` →
enqueue → `wakeup` the daemon → `mtx_unlock` → return. Taking a mutex and waking
under the rmlock is fine (Phase 2's hook already takes a lock there); only
*sleeping* is banned. This also makes the phase simpler than a hold — no waiter,
no timeout, no in-flight drain on unload.

**Kernel work.**
- On a miss, allocate a pending request (id, flow, owning identity from the
  label), queue it, `wakeup` the daemon, and return an errno: `EAGAIN` (retry).
  A cached deny still returns `EPERM`, a cached allow `0` (Phase 2 unchanged).
- Deliver requests to the daemon via `read()` on `/dev/pfsnitch` (a blocking
  read in the daemon's own thread — sleeping there is fine, it is not the hook).
  The daemon answers with a `RESOLVE` ioctl (id + verdict), which inserts the
  verdict into the Phase 2 cache; the app's retry then hits it.
- A cap on outstanding requests and a GC of orphans (daemon never answered), so
  a dead or slow daemon cannot grow the queue without bound. Requests addressed
  by **id**, never pointer, so a resolve racing a GC'd request is a no-op.
- A `failmode` (open/closed) applied when the queue is full or the daemon is
  absent, mirroring `failopen.conf`.

**Daemon work.** A dedicated thread `read()`s pending requests, runs them through
the existing decide/prompt logic, and `RESOLVE`s them. It shares the main loop's
policy state (locking required), and toggles an `UPCALL` flag on when its reader
is up and off on shutdown — while off, a hook miss falls through to divert
(Phase 2 behaviour), so the transition is safe.

**Flow change.** First contact with a new destination is decided by the hook +
upcall instead of by divert. The first packet is dropped (the `sendto`/`connect`
returns `EAGAIN`); the protocol's own retransmission — TCP SYN, QUIC datagram —
carries it, and the retry resolves against the now-populated cache.

**Risks / decisions.**
- **The retry contract.** A blocking `connect()` returning `EAGAIN` is unusual;
  most apps and all event loops retry, but confirm against real clients.
- **Pending-request lifecycle** (resolve vs GC vs unload) with no use-after-free.
- **Daemon-side concurrency:** the upcall thread and the divert loop both touch
  policy state and the cache; they must be serialised.

**Done when.** A miss is decided in-kernel with no divert; a denied first packet
is dropped and never leaks; a full queue or absent daemon applies the failmode;
survives the stress/fuzz harness under `GENERIC-DEBUG`.

---

## Phase 4 — Slim the divert (the per-packet UDP win)

**Goal.** Remove the **UDP** `divert-to` rule so unconnected UDP is decided by an
in-kernel lookup per datagram instead of a userspace round trip. **This is where
the per-packet UDP overhead goes away.**

**Refined by the Phase 3 integration test — keep TCP on divert.** Fail-fast
returns `EAGAIN` with no packet sent, so:
- **UDP is a natural fit.** QUIC's retransmission *is* re-calling `sendto`, which
  re-enters the hook — so a first-datagram `EAGAIN` is carried transparently, and
  once cached every datagram is an in-kernel lookup. The overhead is gone.
- **TCP is not.** No SYN is sent on the `EAGAIN`, so nothing retransmits the
  `connect()` — the app must retry it, which not all clients do. Meanwhile the
  existing **divert-hold already handles TCP connect transparently** (the SYN is
  sent, dropped, and carried by TCP's own retries) and costs only one round trip
  *per connection*, which was never the overhead. So leave TCP on divert.

Net: the hook upcalls for **UDP only**; TCP misses fall through to the divert
path as today.

**Kernel / daemon work.**
- Gate the hook's upcall on `proto == IPPROTO_UDP`; a TCP miss returns 0 (divert).
- Drop the general **UDP** `divert-to` rule from the anchor; keep the TCP-SYN
  rule and the **DNS (port 53) pair** (hostname learning needs the answer
  payload, which no hook exposes).
- Verify the steady state: each UDP datagram to an already-decided destination is
  one `socket_check_connect` → cache lookup → `0`/`EPERM`, entirely in-kernel.
  Make that lookup cheap — move the cache to an `rmlock` (read-mostly) if the
  `rwlock` contends at high packet rates.

**Risks / decisions.**
- **Do not silently drop a class of traffic.** Confirm every UDP path that
  matters carries `msg_name` to the hook (connected UDP that then `send()`s
  without a name is decided once at its `connect`; verify), and that removing the
  UDP divert rule leaves no unconnected-UDP path ungoverned.
- **Per-packet hook cost.** A cache lookup per datagram is far cheaper than a
  divert round trip, but not free — measure it, `rmlock` if needed.

---

## Phase 5 — Failmode + hardening

**Goal.** Make the in-kernel path safe to run unattended and maintainable across
releases.

**Kernel / daemon work.**
- **Failmode when the daemon dies.** With decisions and misses in the hook, a
  dead daemon means unanswerable misses and a frozen cache. The hook's built-in
  open/closed default (Phase 3) must mirror `failopen.conf`; and a cached deny
  must not enforce forever with nobody to revise it — the daemon flushes on clean
  exit and/or the module ages entries.
- Boot load-ordering (`kld_list` before things worth attributing); version/KBI
  pinning so a module built for one FreeBSD release refuses to load into another
  rather than misbehaving.
- A panic-safety review of every hook path added in 3–4.

**Risks / decisions.** Matching the existing failopen semantics exactly;
per-release KBI maintenance as an ongoing cost; the sharper blast radius of a bug
being a panic, not a daemon restart.

---

## Cross-cutting

- **Testing is per-phase, not at the end.** Extend `kmod/tests/` (fuzz new
  ioctls, stress the cache and the upcall queue under churn) and run under
  `GENERIC-DEBUG` before a phase is done. The rig exists precisely so that
  adding in-kernel logic is survivable.
- **Read the framework before assuming.** Two near-misses came from assuming
  rather than checking the source: an *earlier* blocking design would have
  panicked on `msleep` under the `NOSLEEP` rmlock (caught by reading
  `mac_internal.h`), and the whole "UDP is unreachable" conclusion was wrong
  until reading `kern_sendit` showed `sendto` routes through
  `socket_check_connect` with the destination. Verify hook context and call
  sites in `/usr/src` before building on them.
- **Slot budget.** Each `kldload` consumes a MAC label slot for the boot
  (`security.mac.max_slots` = 4, never reclaimed on unload). Dev reload cycles are
  bounded; production loads once at boot. Unchanged by these phases, but every
  phase’s dev loop lives inside it.
- **Keep the userspace path working.** `attribution procstat` and the full divert
  daemon must remain a complete, supported backend throughout — the kernel route
  is opt-in, and a miss at any layer falls back to it.

## Open decisions

1. **Phase 3 miss errno** — `EAGAIN` (transient, retry) is the plan; confirm real
   clients retry a `connect`/`sendto` that fails this way, especially blocking
   `connect()`.
2. **Phase 4 UDP coverage** — verify every UDP path that matters delivers a
   destination to the hook via `msg_name`; anything that does not keeps a divert
   lane. Measure the per-datagram hook cost and move the cache to `rmlock` if it
   contends at high packet rates.
3. **DNS learning** — the port-53 divert lane stays (payload inspection). Confirm
   that is the only lane that must survive Phase 4.
