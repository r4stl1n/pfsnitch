# Kernel module roadmap

The plan for taking `mac_pfsnitch` from an attribution helper to an in-kernel
filter. This is the **kernel route only** — the pf state-bypass alternative
(“Option A”) is deliberately out of scope here.

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
| 3 | Blocking upcall — retire the SYN-retransmit hold | Next |
| 4 | Retire divert; close the UDP / DNS gaps | Planned |
| 5 | Failmode, policy sync, productionization | Planned |

**Phase 2 as built** enforces only the *deny* side in the hook — a cached deny
fails `connect()` with `EPERM`, before any packet. A cached allow and a miss
return 0 and still take the divert path, because the hook cannot yet handle a
miss on its own; that (and therefore the allow-side divert removal) waits for
the blocking upcall in Phase 3. The daemon pushes verdicts only while enforcing
and flushes on every policy reload, so visibility never blocks and a cached
verdict never outlives its rule. See `kmod/tests/vtest.c` (functional) and the
verdict-cache stress in `kmod/tests/stress.c`.

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

## Phase 3 — Blocking upcall

**Goal.** Replace the drop-and-retransmit hold (see `docs/` Fig 3 / the
SYN-retransmit note) with a genuinely blocked syscall, so a prompt no longer
relies on TCP retrying.

**Kernel work.**
- On a cache miss, post an event (tuple + owning identity) to the daemon over the
  cdev and `msleep` the connecting thread with a bounded timeout; wake it when
  the daemon writes the verdict back, then insert into the Phase 2 cache and
  return `0`/`EPERM`.
- A default action for timeout and for “no daemon listening”, from the failmode
  (Phase 5).

**Flow change.** The connection is *held in the syscall*, not dropped — works for
UDP too, which the retransmit trick never could. The divert path is no longer the
mechanism for unknown flows.

**Risks / decisions — settle before writing code.**
- **Blocking vs non-blocking sockets — the load-bearing UX call.** A synchronous
  block stalls a non-blocking app’s entire event loop, not one connection. Options:
  block with a short bound then fall back; return `EPERM` immediately on miss and
  prompt asynchronously (lose “answer in 60s and the original attempt succeeds”);
  or blend by reading `SS_NBIO` and blocking only truly-blocking sockets. **This
  decision gates the whole phase.**
- Sleeping in a MAC hook: confirm the hook’s context may sleep, handle signals
  and timeouts, and never wedge a thread if the daemon dies mid-wait.

**Done when.** A prompt holds a real `connect()` to completion; a non-blocking
socket behaves per the chosen policy; killing the daemon mid-prompt falls back to
the failmode rather than hanging.

---

## Phase 4 — Retire divert; close the UDP / DNS gaps

**Goal.** Remove the TCP divert rules now that Phases 2–3 carry those decisions,
and decide the fate of the two things divert still does.

**Kernel / daemon work.**
- Drop the TCP `divert-to` rule from the anchor. The anchor shrinks toward
  DNS-answer learning only.
- **Unconnected UDP** (`sendto()` with no `connect()`) is the real gap:
  `mpo_socket_check_send` does **not** carry the destination, so per-destination
  UDP decisions can’t be made there. Choose: keep a slim divert lane for
  unconnected UDP (hybrid, honest, probably fine since QUIC stacks mostly
  `connect()` their sockets), or patch the framework to add a destination-bearing
  send hook and carry that upstream.
- **DNS hostname learning** needs the packet payload, which no MAC hook exposes —
  so the DNS-answer divert lane almost certainly stays regardless.

**Flow change.** TCP is fully syscall-gated; UDP is syscall-gated for connected
sockets and either divert-gated or hook-gated for unconnected ones; DNS answers
still ride a minimal divert lane to feed the hostname map.

**Risks / decisions.** The unconnected-UDP choice is a scope fork (hybrid vs
kernel patch). Don’t let removing divert silently drop a class of traffic — every
lane removed must have a proven replacement first.

---

## Phase 5 — Failmode, sync, productionization

**Goal.** Make the in-kernel path safe to run unattended and maintainable across
releases.

**Kernel / daemon work.**
- **In-kernel failmode.** With decisions in the hook, a dead daemon means misses
  with no listener — the hook needs a built-in open/closed default mirroring
  `failopen.conf`. Today a dead daemon is handled by the watchdog flushing the
  anchor; that safety net shrinks as divert does, so the failmode moves into the
  module.
- Robust cache invalidation and generation handling; boot load-ordering
  (`kld_list` before things worth attributing); version/KBI pinning so a module
  built for one FreeBSD release refuses to load into another rather than
  misbehaving.
- A panic-safety review of every hook path added in 2–4.

**Risks / decisions.** Matching the existing failopen semantics exactly;
accepting per-release KBI maintenance as ongoing cost; the sharper blast radius
of a bug now being a panic, not a daemon restart.

---

## Cross-cutting

- **Testing is per-phase, not at the end.** Extend `kmod/tests/` (fuzz the new
  ioctls, stress the cache under churn, add hooks for the blocking path) and run
  under `GENERIC-DEBUG` before each phase is done. The rig exists precisely so
  that adding in-kernel decision logic is survivable.
- **Slot budget.** Each `kldload` consumes a MAC label slot for the boot
  (`security.mac.max_slots` = 4, never reclaimed on unload). Dev reload cycles are
  bounded; production loads once at boot. Unchanged by these phases, but every
  phase’s dev loop lives inside it.
- **Keep the userspace path working.** `attribution procstat` and the full divert
  daemon must remain a complete, supported backend throughout — the kernel route
  is opt-in, and a miss at any layer falls back to it.

## Open decisions

1. **Phase 2 cache key granularity** — binary-scoped (recommended) vs coarser.
2. **Phase 3 blocking policy** — block-with-timeout, fail-fast-and-prompt, or
   `SS_NBIO`-aware blend. Gates Phase 3.
3. **Phase 4 unconnected UDP** — keep a slim divert lane (hybrid) vs patch the
   MAC framework for a destination-bearing send hook.
