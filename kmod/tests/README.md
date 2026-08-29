# mac_pfsnitch stress and fuzz tests

A kernel module panics the whole machine when it goes wrong, so it is tested
harder than a userspace crash would justify. These harnesses drive the two
things that can panic this module — the ioctl input path and the socket-label
lifecycle under concurrency — and check both that the box survives and that it
does not leak.

## Running

```sh
kldload ./mac_pfsnitch.ko          # from kmod/
doas sh tests/run.sh               # full run (~2 min)
doas sh tests/run.sh -q            # quick run (~40 s)
```

`run.sh` builds the harnesses, records a malloc-accounting baseline, fuzzes the
ioctl, runs the concurrency stress, then judges the result on three axes:

* **invariants** — every answer the module returns is well-formed (`found` in
  range, strings NUL-terminated, pid sane, a self-query names the querying
  process);
* **no leak** — the `pfsnitch` malloc type drains back to its baseline after
  the run; every label allocated at `socket_create` was freed at
  `socket_destroy`;
* **kernel health** — no panic, fault, lock-order reversal, or leak warning
  appears in `dmesg` during the run.

## The harnesses

**`fuzz_ioctl.c`** — the ioctl is the module's whole userspace attack surface.
`_IOWR` copies a fixed struct in and out, so there is no buffer to overflow;
the risk is what the module does with the field values. It throws six flavours
of input — fully random, valid-framing/random-tuple, out-of-range af/proto,
boundary addresses, wrong version, loopback tuples that actually resolve — plus
occasional random ioctl command numbers, single- and multi-threaded.

**`stress.c`** — the panic risk in the lookup path is a use-after-free: reading
a socket's label while the socket is torn down. To force that window instead of
hoping for it, a real loopback listener runs while churn threads open
connections, publish their exact 4-tuples, and abortively close (`SO_LINGER 0`,
so the label is freed *now*), while query threads look those very tuples up as
fast as they can. Fork threads add short-lived children that create sockets and
exit, exercising `socket_create` across process contexts and racing process
teardown. A recent run drove ~2M socket create/destroy cycles against ~9M
concurrent lookups.

**`vtest.c`** — functional test of the Phase 2 verdict cache and connect hook,
independent of the daemon and pf. It pushes verdicts straight into the module
and checks that `connect()` honours them: a cached DENY fails with `EPERM`, a
miss falls through, a cached ALLOW does not block, and FLUSH clears the deny.

**`utest.c`** — functional test of the Phase 3 fail-fast upcall. Plays the daemon
in a thread: `read()`s events, resolves them by a toy policy, and checks that a
miss returns `EAGAIN` and the retry gets the cached verdict — for TCP *and* for
unconnected UDP `sendto`, proving the destination-bearing hook covers UDP.
`utest stress <secs>` hammers the upcall queue: a resolver thread against many
churn threads connecting/sending to random ports.

The stress harness also runs verdict-cache writers (`-v`), pushing and flushing
verdicts as fast as it can while every churn/fork `connect()` reads the cache in
the hook — the Phase 2 rwlock stress.

> **Environment caveat.** These are loopback-only kernel tests and do not need
> pf. But do **not** leave pf enabled with the pfsnitch divert anchor loaded and
> the daemon stopped: every non-loopback SYN then diverts to a dead socket and
> is blackholed, which looks exactly like a hung machine (SSH included) even
> though the kernel is fine. In production the watchdog flushes the anchor when
> the daemon dies; killing the daemon by hand bypasses that. Disable pf
> (`pfctl -d`) or keep the daemon running.

## Why a debug kernel matters

On a stock GENERIC/RELEASE kernel these harnesses catch gross faults, hangs and
leaks — but a *subtle* use-after-free or lock-order bug can pass unseen, because
nothing is checking. `build_debug_kernel.sh` builds and installs a
GENERIC-DEBUG kernel (INVARIANTS, WITNESS, DEADLKRES, QUEUE_MACRO_DEBUG_TRASH)
and rebuilds the module to match its KBI. Under that kernel the same harnesses
turn a latent bug into an immediate panic or a printed lock-order warning —
which is the entire point of running them.

```sh
doas sh build_debug_kernel.sh build       # long; run detached
doas sh build_debug_kernel.sh install     # installs kernel + KBI-matched module
# reboot, then re-run run.sh under the debug kernel
```

Recovery if the debug kernel misbehaves: boot `kernel.old` from the loader
prompt (the installer keeps it), or roll back the VM snapshot.
