# Writing a pfsnitch frontend

pfsnitch has no client library, no socket and no IPC protocol. A frontend needs
two plain-text touchpoints and nothing else, so a shell script, a TUI, a web
page and a Wayland widget are all equally first-class. The bundled eww widget is
one frontend, not a requirement — nothing in the daemon knows it exists.

The two jobs are independent. A frontend may do either alone.

---

# 1. Managing rules

The policy file is the single source of truth. It is plain text, it keeps its
comments, and **the daemon re-reads it within one second of any change** — no
matter who made it: the CLI, `vi`, a shell redirect, or your program. There is
nothing to signal and no daemon to find.

```sh
pfsnitch rules --json     # flat list
pfsnitch apps  --json     # the same rules grouped by application
pfsnitch status --json    # daemon state, mode, counts

pfsnitch allow host github.com --from /usr/local/bin/git
pfsnitch allow app  /usr/local/bin/curl
pfsnitch allow dest 2606:4700:4700::1111
pfsnitch deny  host metrics.example.com --from /usr/local/bin/someapp
pfsnitch rm    allow-host-from github.com /usr/local/bin/git
```

`rm` takes the kind spelled exactly as `rules` prints it, so listing output can
be fed straight back. Adding a rule twice is a no-op rather than a duplicate,
and hostnames and addresses are compared in canonical form — `EXAMPLE.com` and
`2606:0:0::1` match rules you already have.

Writing the file directly is equally supported: `allow-host example.com` on its
own line is a complete rule. Hand-editing is an interface, not a workaround.

## Rule kinds

| kind | matches | notes |
|---|---|---|
| `allow-host-from` | a hostname, **for one binary** | what *Allow connection* writes |
| `deny-host-from`  | a hostname, **for one binary** | what *Block connection* writes |
| `allow-dest-from` | one address, **for one binary** | used when no hostname was seen |
| `deny-dest-from`  | one address, **for one binary** | as above |
| `allow-app`       | one binary, every destination and port | |
| `deny-app`        | one binary, every destination and port | the big hammer |
| `allow-host`      | a hostname, **any binary** | infrastructure: a resolver, a gateway |
| `deny-host`       | a hostname, any binary | |
| `allow-dest`      | one address, any binary | |
| `app-id`          | pins a binary's sha256 | see *Binary identity* below |

Hostname rules are preferred over addresses: one rule covers every address a
site answers on, instead of re-prompting for each rotating CDN address.
Wildcards are supported as `*.example.com`, in scoped and unscoped rules alike.

### Ports

Every host and address rule may name a port. A rule without one means **any
port**, which is what a bare host has always meant - so a policy file written
before ports existed keeps its meaning exactly.

```
allow-host-from github.com:443            /usr/local/bin/git   # just HTTPS
allow-host-from github.com                /usr/local/bin/git   # any port
allow-dest-from [2606:4700:4700::1111]:853 /usr/bin/drill      # DoT only
allow-dest      1.1.1.1:53                                     # any binary, DNS only
```

IPv6 needs the bracket form when you want a port. A bare `2606:4700::1111` is
full of colons and must not be read as a host and a port - so brackets are the
only way to say which is which, exactly as in a URL.

An approval made from a prompt covers **the port it was asked about**, not every
port on that host. Approving a browser's HTTPS access should not also hand it
SSH.

Scoped rules are written **destination first**:

```
deny-host-from metrics.example.com /usr/local/bin/someapp
```

That order is not cosmetic — a hostname or address can never contain
whitespace while an executable path can, so splitting on the first space is
unambiguous in this order and would not be in the other.

Policy is keyed on the **executable path**, never the process name: a name is
trivially spoofable and the kernel truncates it to 19 characters anyway.

## Rules are per-binary by default

Approving a host for one program does not open it for every other program, and
blocking one destination leaves the app otherwise working — an app that phones a
metrics endpoint should lose the metrics endpoint, not the network.

The unscoped `allow-host` / `allow-dest` forms still match every binary. They
are the right choice for genuine infrastructure, where every program
legitimately needs the same destination.

### Precedence

A scoped deny is the most specific rule there is, so it is checked first and
beats every broader allow — including `allow-app` for that binary and an
`allow-host` some other approval created. Without that ordering, approving a
host for one program would silently re-open it for one you had blocked.

1. `deny-dest-from` / `deny-host-from` — this binary, this destination
2. `deny-host` — this host, any binary
3. `deny-app` — this binary, anywhere
4. `allow-dest-from` / `allow-host-from` — this binary, this destination
5. `allow-app` — this binary, anywhere
6. `allow-host` / `allow-dest`
7. the `default`

### When the binary is unknown

Attribution can fail: a short-lived process may exit between its SYN and the
scan that identifies it. A per-binary rule cannot match a connection with no
binary attached, so those fall through to the `default` rather than being
allowed — the safe direction, but worth knowing.

When *Allow connection* is answered for a connection that could not be
attributed, pfsnitch falls back to an unscoped rule and marks it
`# unattributed connection`, because it is broader than you asked for and should
be easy to find on review.

## Binary identity

Policy keys on the executable path, because that is the only stable handle pf
and libprocstat give us. But a path is not an identity: replace the file and the
replacement inherits every rule the original earned.

An approval therefore pins the binary's hash:

```
app-id 311447b0a7dd05377167c9ca97a36176...	/usr/local/bin/git	# identity when approved
```

If the binary later differs, **its rules are ignored** and the connection falls
back to asking. The prompt says so in red, and receives `changed` as an optional
7th argument - a backend written before that existed simply ignores it. An
approval given while it says `changed` re-pins the new hash: you have just said
the new binary is the one you meant.

FreeBSD binaries are generally unsigned, so a content hash stands in for the code
signature Little Snitch uses. Hashing is `sha256(1)` from base rather than a
crypto crate, cached on (mtime, size) so a binary is hashed once and again only
when it actually changes.

Only explicit approvals pin an identity - never a rule learned in visibility
mode. Pinning something nobody looked at would give the pin a weight it has not
earned.

## Grouped by application

Since rules are per-binary, the useful view is usually "what is this app allowed
to reach". `pfsnitch apps` does that grouping, so every frontend groups
identically instead of each reimplementing it:

```json
{"apps":[
  {"app":"/usr/local/bin/git","dir":"/usr/local/bin/","dir_short":"/usr/local/bin/",
   "name":"git","allow":2,"deny":0,"total":2,
   "rules":[{"kind":"allow-host-from","value":"github.com /usr/local/bin/git",
             "dest":"github.com","effect":"allow","comment":null}]},
  {"app":"","name":"any application","allow":5,"deny":0,"total":5,"rules":[]}
]}
```

Each rule carries the fields a UI wants: `dest` is the destination in human
terms (for `allow-app` it reads "all destinations"), and `effect` is `allow` or
`deny` so a row can be coloured without parsing the kind.

The path is also pre-split: `dir` and `name` let a UI show the directory quietly
and the binary loudly, and `dir_short` is the directory shortened from the LEFT
(`…/chromium/lib/`). Truncating a path from the right hides the deepest
directory, which is the part that identifies the program - `/usr/local/share/c…`
could be anything. `value` is still
exactly what `pfsnitch rm` expects, so a delete button can pass `kind` and
`value` straight through.

Rules matching every binary are collected under an app of `""`, named "any
application". **Watch for that empty string if you key anything off `app`** — it
is a real group, not a missing value. The bundled panel uses a `::none::`
sentinel for "nothing expanded" for exactly this reason: an empty default would
silently expand the global group.

---

# 2. Answering prompts

When the daemon needs a decision it runs one program. That program's contract is
the entire interface:

```
argv:   EXE PID COMMAND DST DPORT [HOSTNAME]
stdout: exactly one word — allow-conn | allow-app | block-conn | block-app | timeout
exit:   0
```

Point `prompt` in `policy.conf`, `$PFSNITCH_PROMPT`, or `pfsnitch_prompt` in
`rc.conf` at any executable honouring that, and you have replaced the prompt.

## Verdicts

| verdict | effect |
|---|---|
| `allow-conn` | allow **this destination for this binary** — writes `allow-host-from`, or `allow-dest-from` when no hostname was seen |
| `allow-app`  | allow the binary everywhere — writes `allow-app` |
| `block-conn` | deny **this destination to this binary** — writes `deny-host-from` / `deny-dest-from` |
| `block-app`  | deny the binary everything — writes `deny-app` |
| `timeout`    | drop the packet, **write nothing** |

A settled deny is **rejected, not dropped**: the daemon synthesises a TCP RST so
the application gets `ECONNREFUSED` immediately instead of waiting out a 75
second timeout. A packet held while a prompt is still open is dropped silently,
because its retransmission is what carries the connection until you answer.

`timeout` deliberately persists no rule. Walking away from a prompt must not
lock you out of an application, and an unattended machine must not accumulate
permanent deny rules for software no human ever judged. **A backend that cannot
ask the user must print `timeout`, never `block-conn`.**

`block` is still accepted as an alias for `block-conn`.

## Without writing a program

Use the bundled `file` backend, which publishes the request and waits:

```sh
pfsnitch_prompt_backend="file"    # in rc.conf
```

```sh
# appears only while a decision is pending
cat /var/run/pfsnitch/pending.json
# {"nonce":"fd24…","exe":"/usr/bin/curl","pid":"4242","command":"curl",
#  "dst":"93.184.216.34","dport":"443","hostname":"updates.example.com"}

pfsnitch-answer allow-conn
```

Read one JSON file, run one command. That is the whole integration.

## Answering safely

`pfsnitch-answer` writes `<nonce> <verdict>`, and the backend accepts an answer
only if the nonce matches the prompt it actually raised. Without that, an answer
left behind by an abandoned prompt would be consumed by the *next* prompt —
approving a connection with a click the user made about something else. If you
bypass `pfsnitch-answer` and write the answer file yourself, copy the nonce from
`pending.json`.

Because an unanswered SYN is dropped rather than buffered, the connection is
carried by TCP retransmission while the user decides
(`net.inet.tcp.keepinit`, 75 s by default). Answer within ~60 s and the
connection succeeds; answer later and the application sees an ordinary
connection failure.

## Bundled backends

| backend | when |
|---|---|
| `eww`  | Wayland session; draws a real dialog |
| `tty`  | console or headless; asks on the first logged-in terminal |
| `file` | publishes `pending.json` for any frontend |
| `deny` | unattended; never asks, never writes a rule |

`auto` (the default) picks `eww`, then `tty`, then `file`. `deny` is never
chosen automatically — it is opt-in.

Each backend sets its own complete `PATH`. The daemon is started by `rc.d` with
`PATH=/sbin:/bin:/usr/sbin:/usr/bin` — no `/usr/local/bin`, which is where `eww`
and every other port lives — so a prompt that inherited its caller's environment
would fail silently and time out every connection.

---

# 3. Modes

| mode | behaviour |
|---|---|
| `visibility` | watch and learn: reinjects everything, recording each new destination as an allow rule. No prompts. |
| `enforcement` | drops what is not approved, prompting for each new destination |

```sh
pfsnitch mode                 # show
pfsnitch mode enforcement     # switch
```

The mode lives in the policy file as a `mode` directive, not in argv, so it can
be changed at runtime. The daemon re-reads the file within a second, which means
**switching never restarts the daemon and never drops the divert socket** —
there is no window in which traffic passes unfiltered. Writing `mode
enforcement` into the file by any means has exactly the same effect as the
command. `status --json` reports the current mode, so a frontend can render a
toggle from it.

The older names `listen` and `enforce` are still accepted everywhere a mode is
parsed, so existing `rc.conf` entries and scripts keep working.

## Why prompts only appear in enforcement

In `visibility` every packet is reinjected regardless of the verdict, so a
dialog would be asking a question whose answer changes nothing. Instead the
daemon records what it saw — `allow-host-from` when it observed the DNS lookup,
`allow-dest-from` otherwise — which is the same rule a user clicking *Allow
connection* would have produced.

Learned rules are marked `# learned from <binary>` rather than `# approved for
<binary>`, because the two deserve different amounts of trust: one means a human
looked at a dialog and chose, the other means the traffic simply happened while
nobody was watching. **Anything that connects during visibility gets a permanent
allow rule**, so treat the learned set as a draft to review, not a finished
policy.

## Binary details

`pfsnitch-appinfo <path>` reports what a rule's target actually is, as JSON. It
is computed on demand rather than polled — none of it changes second to second,
and hashing a binary on a timer would be a silly thing to do to a laptop.

```json
{"path":"/usr/local/bin/git","name":"git","kind":"binary","exists":true,
 "size":"3.8M","modified":"2026-08-17 18:33","owner":"root:wheel",
 "mode":"-rwxr-xr-x","writable":false,"setuid":false,
 "sha":"311447b0a7dd05377167c9ca97a36176","running":0,"pids":""}
```

The fields are chosen for reviewing a rule, not for admiring a file. A rule is a
standing permission attached to a path, so what matters is:

| field | why it matters |
|---|---|
| `exists` | a rule pointing at a deleted path is dead weight — and if something later takes that name, a permission waiting to be inherited |
| `sha` | if this differs from last time, the binary behind the rule is not the one you approved |
| `modified` | the cheap version of the same question |
| `writable` | group- or world-writable means someone other than root can swap the binary out from under a rule that trusts this path |
| `setuid` | worth knowing before granting it network access |
| `running` / `pids` | is it active right now |

`kind` is `binary`, or `global` for the catch-all group (which has no path).
When `exists` is false, only `path`, `name`, `kind` and `exists` are present —
a frontend must not assume the rest.

## When a rule was last used

`pfsnitch apps` reports `last_seen` (unix seconds, or `null`) and a short
`last_seen_ago` for every rule and every application:

```json
{"kind":"allow-host-from","dest":"github.com","effect":"allow",
 "last_seen":1787533666,"last_seen_ago":"40s ago", ...}
```

This is deliberately **not** traffic accounting. Only the first packet of a TCP
connection ever reaches userspace — the rest matches pf state — so byte counts
would be UDP-only and quietly misleading about everything else. A timestamp is
something we can observe for every protocol, and it answers the question people
actually ask of a rule list: is this still in use, or left over from something I
did months ago?

The daemon keeps the table at `/var/run/pfsnitch/lastseen` (`<unixtime>` TAB
`<destination>` TAB `<binary>`), rewritten at most once every 10 seconds because
this sits on the packet path. It is **seeded from that file at startup** — a
restart that reset every timestamp to "never" would be worse than recording
nothing, because it would look like real data.

An unscoped rule is not owned by any binary, so its timestamp is the most recent
time *any* binary used that destination.
