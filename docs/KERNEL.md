# The kernel attribution backend

pfsnitch has two ways to answer "which binary owns this connection?", and you
choose between them at runtime:

```sh
pfsnitch attribution kernel      # ask mac_pfsnitch.ko
pfsnitch attribution procstat    # scan the process table (the default)
```

Like `mode`, the setting lives in the policy file and the daemon picks it up
within a second — no restart, no gap in coverage.

## Why it exists

The userspace path works backwards: a packet arrives carrying a 4-tuple and no
identity, so the daemon scans every process's file table (libprocstat) looking
for the socket. That scan costs milliseconds and **races against process
exit** — a binary that connects and quits is gone before the scan runs, and
its traffic comes out `none`.

The kernel module records identity *forwards*, at the one moment it is
unambiguous: `socket(2)` runs in the creating process's own context, so the
module simply reads pid, uid, command and executable path off `curproc` and
attaches them to the socket's MAC label. They ride the socket until it dies.
When the daemon asks about a flow — one ioctl on `/dev/pfsnitch` — the module
finds the socket with `in_pcblookup()`, the same hash the stack itself resolves
packets with, and reads the answer back. No scan, no race, exact even for a
process that exited immediately after connecting.

Connections named this way show the `kernel` tier in the daemon log and at
the prompt. (`pfsnitch probe` is a snapshot of the socket table and keeps
using the procstat walk — the module answers per-flow questions, it does not
enumerate.)

## What it decides, and what it does not

Policy stays in the daemon: it alone evaluates hostnames, wildcards, modes and
per-binary rules. The module holds no policy and resolves nothing — it caches
*decisions the daemon already made*. As of Phase 2 (see
[KERNEL-ROADMAP.md](KERNEL-ROADMAP.md)) it does two jobs: attribute a flow to its
owning binary, and — when the daemon has pushed a settled **deny** for that
(binary, destination) — fail the `connect()` with `EPERM` in the socket hook,
before any packet leaves. A cached *allow* or an unknown flow is not blocked;
it proceeds and is still governed by the divert path. The daemon pushes verdicts
only while enforcing and flushes the cache on every policy reload, so visibility
mode never blocks and a cached verdict never outlives its rule.

The daemon works exactly as before without the module — and
even with `attribution kernel` set, any socket the module cannot answer for
falls back to the procstat scan. Expect that for:

* sockets created **before the module loaded** (ntpd from boot, your sshd
  session) — they carry no label;
* sockets born inside the kernel rather than by a syscall (accepted
  connections; harmless for an egress tool, since they never initiate a flow).

One honest caveat: identity is captured at *creation*. A socket passed to
another process over a unix socket, or inherited across fork, still names its
creator. The procstat path has the mirror-image ambiguity — it names whoever
holds the fd at scan time — so neither is strictly stronger; "creator" is the
more useful answer for an egress prompt.

Where this is going: the module is the first phase of a longer plan to move
filtering into the kernel — see [KERNEL-ROADMAP.md](KERNEL-ROADMAP.md).

## Building and loading

Requires `/usr/src` matching the running kernel.

```sh
cd kmod
make
kldload ./mac_pfsnitch.ko        # as root
pfsnitch attribution kernel
```

`make install` puts it in `/boot/modules`; to load it at boot add to
`/etc/rc.conf`:

```
kld_list="mac_pfsnitch"
```

Load it **before** things you want attributed — a socket created earlier has
no label. Boot-time loading is the intended shape; the fallback covers the
stragglers.

## Unloading, and a hard limit on reloading

`kldunload mac_pfsnitch` is safe at any time: the running daemon notices the
device die (it logs `went away`), falls back to procstat, and quietly retries
once a second — load the module again and it reconnects on its own within a
second or two.

But note: the MAC framework hands each label-using policy a **slot**
(`security.mac.max_slots`, 4, compile-time), and deliberately never reclaims
slots on unload — a live socket could still carry a stale value in that slot.
So each `kldload` of this module consumes a slot for good, and the fifth load
since boot fails with `MOD_LOAD ... error 12` (ENOMEM). Nothing is wrong; the
slots are simply gone until reboot. In production you load once at boot and
never notice. When developing against the module, budget your reload cycles or
reboot freely.

## Interface

`/dev/pfsnitch` (root-only, 0600) speaks one ioctl, defined in
`kmod/pfsnitch_ioctl.h` and mirrored in `src/kernattr.rs`. The struct is
versioned; the module rejects a version it does not speak rather than
misreading the bytes, and the Rust side pins the layout with a test
(`abi_layout_matches_the_c_header`). Change one side and the other must change
with it.

`kmod/kquery.c` is a standalone diagnostic for poking the ioctl without the
daemon:

```sh
cc -o kquery kquery.c
./kquery selftest        # connect somewhere, ask the kernel who owns it
./kquery udptest         # same, unconnected UDP -> wildcard match
```
