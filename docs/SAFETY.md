# Safety model

pfsnitch sits in the packet path. Getting it wrong takes the machine off the
network, and every failure looks the same from outside: a host that answers
nothing.

This document is written from things that actually went wrong, not from
theory.

## How you lose the network

1. **Divert rules with no daemon behind them.** A `divert-to` rule whose socket
   nobody is reading drops every packet it matches. A crashed, hung, or killed
   daemon is indistinguishable from a black hole.
2. **`pf.conf` blocks outbound by design.** The ruleset denies outbound and
   depends on the `pfsnitch` anchor to re-open it (see below). Anything that
   leaves the anchor empty while the daemon is down leaves the machine silent.
3. **Historical: `kldload ipfw`** activates rule 65535 `deny ip from any to any`
   immediately. This happened once during development, over SSH, and required
   console recovery. pfsnitch no longer uses ipfw — it uses pf divert, which the
   `divert(4)` man page does not document but the kernel fully supports — and
   `/boot/loader.conf` still sets `net.inet.ip.fw.default_to_accept=1` so that
   mistake cannot repeat.

## Recovery: `pfsnitch-panic`

In base PATH, no arguments, no dependencies beyond base. Stops the service, the
daemon and the watchdog, flushes the anchor, and **disables pf outright**.

Reloading `/etc/pf.conf` is *not* a rescue and must not be treated as one: that
ruleset is what blocks outbound, and anchor contents survive a main-ruleset
reload — so reloading pf with the daemon dead leaves divert rules pointing at a
socket nobody holds. An earlier version of this script did exactly that and
would have deepened a lockout rather than fixing it.

Verified against a real black hole: daemon killed with divert rules live,
outbound dead, `pfsnitch-panic` restored connectivity.

Putting it back is one command:

```sh
service pfsnitch start
```

which re-enables pf if it is disabled — pfsnitch enforces *through* pf, so a
running daemon with pf off is a daemon enforcing nothing.

## Design choices that exist for safety

- **Packets are never buffered.** An unapproved SYN is dropped, and TCP's own
  retransmission carries the connection while the user decides
  (`net.inet.tcp.keepinit`, 75 s). Nothing queues up in the daemon, so a slow or
  absent answer cannot exhaust memory.
- **`panic = "abort"` in release builds.** A partially-live daemon still holding
  the divert socket is worse than a dead one, because the kernel keeps handing
  it packets.
- **`libc` is the only dependency.** A firewall is the wrong place to widen a
  supply chain for convenience.
- **A prompt that cannot ask prints `timeout`, never `block`.** `timeout` drops
  the packet but persists no rule, so walking away from the screen cannot
  permanently lock an application out, and an unattended machine cannot silently
  accumulate deny rules for software no human ever judged.
- **Policy is keyed on the executable path**, never the process name: a name is
  trivially spoofable and the kernel truncates it to 19 characters anyway.
- **...and an approval pins that binary's hash.** A path is not an identity;
  replacing the file would otherwise hand the replacement every rule the
  original earned. If the hash later differs, those rules are ignored and the
  connection falls back to asking.
- **A settled deny is rejected, not dropped.** The application gets
  `ECONNREFUSED` at once instead of a 75 second silence, because a hang reads as
  a broken network rather than as a decision. A packet held while a prompt is
  open is still dropped, since its retransmission is what carries the connection
  until the user answers.

## Boot: nothing escapes before the daemon is up

`/etc/pf.conf` blocks outbound by default and relies on the `pfsnitch` anchor to
re-open it:

```
block out all
pass out quick on $ext_if proto udp from port 68 to port 67 keep state   # DHCP
...
anchor "pfsnitch"
```

At boot the anchor has never been loaded, so it is empty and **nothing outbound
is permitted**. `anchor.conf` ends with `pass out all keep state`, so traffic is
re-opened only once pfsnitch has actually started and installed its rules.
Verified by emptying the anchor and confirming TCP, DNS and ICMP are all
refused.

Two things deliberately survive the closed state:

- **Inbound SSH.** It is admitted by its own rule and its replies match state,
  so a remote session keeps working even with everything outbound blocked. If
  pfsnitch fails to start, the machine is still reachable to fix it.
- **DHCP renewal.** Explicitly passed, because losing the lease would take the
  interface down and the SSH session with it.

Note that a plain `pfctl -f /etc/pf.conf` does **not** re-close the gate: anchor
contents are a separate ruleset and survive a main-ruleset reload. Only an
explicit `pfctl -a pfsnitch -F rules`, or a boot, empties it. Use
`service pfsnitch reload` after editing `anchor.conf`.

### Boot is closed, a crash is not

`pfsnitch_failmode` in `rc.conf` governs what the watchdog does when a **running**
daemon dies:

| value | behaviour |
|---|---|
| `open` (default) | loads `failopen.conf` — traffic flows unfiltered, machine keeps working |
| `closed` | flushes the anchor — no outbound until pfsnitch is back |

These are deliberately different defaults. At boot, nothing has connected yet, so
blocking costs nothing and guarantees no unseen traffic. Mid-session, stranding a
working machine is a real cost, so the default restores connectivity and logs it.

Because the anchor being empty now means *blocked*, failing open can no longer be
done by flushing it — the watchdog loads `failopen.conf` instead. Flushing is now
the fail-**closed** action. Getting these backwards would either strand the
machine or silently drop the firewall, which is why the mode is an explicit
setting rather than implied by the code path.

## Scope: the whole machine, every user

pf filters packets, not sessions, so interception covers every process and every
user — verified with the same request made as an unprivileged user, as root, and
as `nobody`; all three were intercepted and attributed.

Two limits worth knowing:

- **`set skip on lo0`** — loopback traffic is not filtered at all.
- **The prompt goes to the console session.** The daemon is machine-wide, but it
  asks whichever Wayland session is running. On a multi-user box, a connection
  made by someone over SSH raises a dialog on the *console* user's screen. That
  is the wrong person to be deciding. For a shared machine, set
  `pfsnitch_prompt_backend="deny"` or `"file"` and manage rules out of band.

## UDP, and what it costs

TCP is easy to make a DECISION about: a SYN is an unambiguous "starting a
connection", and it retransmits for 75 s, so holding it while the user decides
is reliable. That is about the decision, not about the cost - see
[what this costs](#what-this-costs) below, because both protocols are dearer
than they look.

UDP has none of that, and pfsnitch originally diverted **only DNS**. Everything
else — QUIC/HTTP3 on port 443 above all, plus NTP, mDNS, WireGuard — flowed
without pfsnitch seeing a packet. For a per-application firewall that was a
bypass, not a limitation: a browser speaking HTTP/3 reached the internet
unobserved.

`anchor.conf` now diverts outbound UDP generally. Three things are worth knowing
before you rely on it:

**Every packet is diverted, not just the first.** `keep state` stops later
packets re-evaluating other rules; it does not exempt them from the divert
action. Verified directly: a 30-datagram flow showed `9:2 pkts` on the pf state
and produced exactly 9 diversions. So the cost scales with packet rate, not with
flow count. The daemon logs each flow **once** rather than once per datagram —
otherwise a video call would fill the disk describing a decision already made.

**A dropped datagram is simply lost.** TCP is carried by SYN retransmission
while a prompt is open. UDP has no equivalent: a protocol that sends once and
gives up loses that datagram. Protocols that retry (DNS, QUIC) recover; some do
not.

**Everything that speaks UDP now prompts.** NTP, mDNS, and DHCP on other
interfaces all become decisions.

Comment the rule out of `anchor.conf` to return to TCP+DNS only. That is a
smaller and more predictable tool — but QUIC then bypasses pfsnitch entirely,
and it should be a choice you make knowingly rather than a default you inherit.

### Still not covered

ICMP, and any IP protocol that is neither TCP nor UDP, are not diverted. They
are also not "an application connecting somewhere" in the sense this tool
models, but a determined tunnel could use them.

## What this costs

Measured, not estimated, on a 9 MB HTTP download over a ~35 Mbit/s link:

| | throughput | diversions | daemon CPU |
|---|---|---|---|
| pfsnitch out of the path | 34–35 Mbit/s | — | — |
| pfsnitch in the path | 27–31 Mbit/s | **10,110** | ~0.15 s |

**Every packet of every connection goes through userspace, in both
directions** — not just the SYN. 10,110 diversions for a 9 MB transfer is
approximately its entire packet count.

The reason is that `divert-to` combined with `keep state` stores the divert
action *in the pf state*. Once that state exists, every packet matching it is
diverted, and pf states are bidirectional, so inbound data is diverted too.
`keep state` prevents later packets re-evaluating other rules; it does not
exempt them from the divert.

That works out at roughly **15 µs of CPU per packet**, which puts a
single-core ceiling somewhere near 800 Mbit/s at a 1500-byte MTU. On this link
the cost is a 10–20% throughput reduction. On a gigabit link the daemon would be
the bottleneck, and on a busy server it would be a serious one.

### Why not divert only the SYN

The obvious fix is `no state` on the TCP divert rule, so only the SYN matches and
everything else falls through to the catch-all. **It does not work**, and it
fails in a way worth recording: the SYN is consumed by the quick divert rule, no
state is ever created, and the returning SYN-ACK therefore has nothing to match
and is dropped by `block in all`. Tested: the transfer stalled for the full 75 s
of SYN retransmission and then failed.

The outbound `keep state` is not incidental — it is what admits the return
traffic. Any scheme for reducing the per-packet cost has to create that state
some other way, for instance by having the daemon add approved flows to a pf
table that is passed before the divert rule. That is unimplemented.

### What this means in practice

- On a laptop on domestic broadband, the cost is real but small.
- On a fast link or a server, this design will limit throughput.
- If that matters more to you than seeing traffic, the TCP and UDP divert rules
  in `anchor.conf` are one line each and are documented for removal.
