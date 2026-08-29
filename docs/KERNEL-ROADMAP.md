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
| 3 | Blocking upcall — retire the SYN-retransmit hold | **Not feasible via the MAC hook** — see below |
| 4 | Retire divert; close the UDP / DNS gaps | **Blocked** by Phase 3; divert is load-bearing |
| 5 | Failmode, policy sync (of the Phase 2 cache) | Still worthwhile |

> **Where the kernel route actually tops out.** Phases 1–2 ship: exact,
> race-free attribution and a fast in-kernel *deny* at connect. Phase 3 as
> designed is **not buildable** (the reason is below), and because it is the
> thing that would let divert be retired, Phase 4 falls with it. So this MAC
> `socket_check_connect` route does **not** remove the per-packet divert
> overhead that started this — divert stays as the hold-and-miss mechanism.
> Addressing that overhead needs a different lever (the pf state-bypass, or a
> `pfil(9)`-based redesign), out of scope here.

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

## Phase 3 — Blocking upcall — NOT FEASIBLE via this hook

**The idea was:** on a cache miss, block the connecting thread in the hook until
the daemon answers (or fail-fast with `EAGAIN` for non-blocking sockets, the
chosen policy), replacing the drop-and-SYN-retransmit hold.

**Why it cannot be built.** `mac_socket_check_connect` is dispatched by
`MAC_POLICY_CHECK_NOSLEEP` (`security/mac/mac_internal.h`), which walks the
dynamic policy list under an **rmlock read lock** (`mac_policy_slock_nosleep`,
an `rm_priotracker`). A dynamically-loaded policy's hook therefore runs holding
that non-sleepable lock, and **`msleep`/`tsleep`/`cv_wait` there is illegal** —
it panics under INVARIANTS ("sleeping thread owns a non-sleepable lock"). It is
irrelevant that `kern_connectat` itself holds no socket lock at the call site;
the framework's own dispatch lock is the blocker. There is no sleepable
connect-check entry point to use instead.

**And it is not needed.** The existing divert + SYN-retransmit path already
provides the hold, correctly, for both socket kinds:
- a **blocking** connect sleeps in the kernel's *own* connect-wait loop
  (`msleep(&so->so_timeo, …)` in `kern_connectat`, legally, outside any MAC
  lock) while the SYN is dropped and retransmitted until the user answers;
- a **non-blocking** connect returns `EINPROGRESS` immediately (no event-loop
  stall) and completes asynchronously when the verdict arrives — which is
  *better* than the `EAGAIN`-retry this phase would have introduced.

So the blocking upcall is both impossible here and redundant. It is dropped.

**Consequence for Phase 4.** Retiring divert depended on the hook handling
misses. It cannot, so **divert stays** as the miss/hold mechanism (and it is
still required for unconnected UDP and DNS learning regardless). Phase 4 as
written does not happen.

**If in-kernel per-packet filtering is still wanted**, it needs a different
mechanism than MAC socket checks — a `pfil(9)` hook with its own in-kernel flow
verdict table (the old "Option B"), or the userspace pf state-bypass ("Option
A"). Both are separate designs, out of scope for this module.

**Done when.** A prompt holds a real `connect()` to completion; a non-blocking
socket behaves per the chosen policy; killing the daemon mid-prompt falls back to
the failmode rather than hanging.

---

## Phase 4 — Retire divert; close the UDP / DNS gaps

**Goal.** Remove the TCP divert rules now that Phases 2–3 carry those decisions,
and decide the fate of the two things divert still does.

> **Blocked.** This phase assumed Phase 3 let the hook handle misses, so the TCP
> divert rule could go. Phase 3 is not feasible (above), so divert remains the
> miss/hold mechanism and this phase does not happen. The notes below stand only
> as a record of what removing divert *would* have required — chiefly that
> unconnected UDP and DNS learning keep divert regardless.

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

## Phase 5 — Hardening the Phase 2 cache (still worthwhile)

**Goal.** Make the shipped Phases 1–2 robust to run unattended and maintainable
across releases. This stands on its own now that 3–4 are off the table.

**Kernel / daemon work.**
- **Stale-cache safety when the daemon dies.** The Phase 2 cache can hold a
  cached deny; if the daemon exits, that deny keeps failing connects with EPERM
  with nobody able to revise it. Decide the intended behaviour — e.g. the daemon
  flushes on clean exit, and/or the module ages entries — so a gone daemon does
  not leave stale enforcement. (The divert-path failmode is still the watchdog's
  job; this is specifically about the verdict cache.)
- Boot load-ordering (`kld_list` before things worth attributing); version/KBI
  pinning so a module built for one FreeBSD release refuses to load into another
  rather than misbehaving.
- A panic-safety review of the Phase 2 hook paths.

**Risks / decisions.** Per-release KBI maintenance as an ongoing cost; the
sharper blast radius of a bug being a panic, not a daemon restart.

---

## Cross-cutting

- **Testing is per-phase, not at the end.** Extend `kmod/tests/` (fuzz new
  ioctls, stress the cache under churn) and run under `GENERIC-DEBUG` before a
  phase is done. The rig exists precisely so that adding in-kernel logic is
  survivable — and it is also what would have caught the Phase 3 sleep-under-
  rmlock panic on first load, had the source read not caught it first.
- **Slot budget.** Each `kldload` consumes a MAC label slot for the boot
  (`security.mac.max_slots` = 4, never reclaimed on unload). Dev reload cycles are
  bounded; production loads once at boot. Unchanged by these phases, but every
  phase’s dev loop lives inside it.
- **Keep the userspace path working.** `attribution procstat` and the full divert
  daemon must remain a complete, supported backend throughout — the kernel route
  is opt-in, and a miss at any layer falls back to it.

## Open decisions

1. **Is there a Phase 5 worth doing**, or is Phase 2 the endpoint? The
   stale-deny-when-daemon-dies question is the main real item.
2. **If the per-packet overhead still matters**, which non-MAC lever: the pf
   state-bypass (Option A, userspace, lowest risk) or a `pfil(9)` redesign
   (Option B, in-kernel per-packet). Both are separate efforts from this module.

*(Resolved/moot: the Phase 3 blocking policy and the Phase 4 unconnected-UDP
fork both fell away when Phase 3 proved infeasible — see Phase 3 above.)*
