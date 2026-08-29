//! pfsnitch - pre-connection egress control for FreeBSD.
//!
//! pf `divert-to` hands outbound connection attempts to this daemon, which
//! attributes each to a process and applies policy. Unknown binaries produce a
//! prompt; the answer is persisted.
//!
//! Packets are never buffered. An unapproved SYN is simply dropped, and TCP's
//! own retransmission (net.inet.tcp.keepinit = 75s here) carries the
//! connection while the user decides. Approve in time and the next retry goes
//! through; that is what makes this feel like interception without the daemon
//! holding state per pending packet.

mod dns;
mod divert;
mod identity;
mod kernattr;
mod policy;
mod procinfo;
mod seen;

use policy::{Answer, Verdict};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const DIVERT_PORT: u16 = 8668;
const POLICY_PATH: &str = "/usr/local/etc/pfsnitch/policy.conf";
const PROMPT_BIN: &str = "/usr/local/libexec/pfsnitch-prompt";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str).unwrap_or("help") {
        "probe" => probe(),
        "visibility" | "listen" => run(policy::Mode::Visibility),
        "enforcement" | "enforce" => run(policy::Mode::Enforcement),
        "rules" | "list" => cmd_rules(&args),
        "allow" => cmd_add(&args, "allow"),
        "deny" => cmd_add(&args, "deny"),
        "rm" | "remove" => cmd_rm(&args),
        "status" => cmd_status(&args),
        "mode" => cmd_mode(&args),
        "attribution" => cmd_attribution(&args),
        "apps" => cmd_apps(&args),
        "forget" => cmd_forget(&args),
        "clear" => cmd_clear(&args),
        "help" | "-h" | "--help" => usage(0),
        other => {
            eprintln!("pfsnitch: unknown command {other:?}");
            usage(64);
        }
    }
}

fn usage(code: i32) -> ! {
    eprintln!(
        "\
pfsnitch - per-application outbound firewall

daemon:
  pfsnitch visibility         watch and learn: reinject everything, recording new
                              destinations as allow rules. No prompts.
  pfsnitch enforcement        drop what is not approved, prompting for new destinations
  pfsnitch probe              list attributable connections, then exit

rules (any frontend can drive these - see --json):
  pfsnitch rules [--json]     list every rule in the policy file
  pfsnitch apps  [--json]     the same rules grouped by application
  pfsnitch status [--json]    policy summary and rule counts
  pfsnitch mode [visibility|enforcement]
                              show or switch mode; takes effect within a second,
                              with no restart and no gap in coverage
  pfsnitch attribution [kernel|procstat]
                              show or switch how flows are matched to processes:
                              procstat scans the process table from userspace;
                              kernel asks mac_pfsnitch.ko, which recorded the
                              owner at socket creation (exact, race-free, and
                              falls back to procstat for unlabeled sockets)
  pfsnitch allow host <name>  approve a hostname, and every address it resolves to
  pfsnitch allow app <path>   approve a binary for all destinations
  pfsnitch allow dest <ip>    approve one address (v4 or v6)
  pfsnitch deny  host <name>  block a hostname
  pfsnitch deny  app <path>   block a binary
  pfsnitch rm <kind> <value>  remove rules, e.g. rm allow-host example.com
  pfsnitch forget <binary>    remove every rule for one binary (keeps a backup)
  pfsnitch clear --yes        remove ALL rules (keeps a backup)

The policy file is plain text and is re-read automatically within a second of
changing, so editing it by hand or from a script works exactly as well as these
commands. No socket, no signal, no daemon discovery."
    );
    std::process::exit(code);
}

fn json_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

fn cmd_rules(args: &[String]) {
    let path = Path::new(POLICY_PATH);
    let rs = policy::rules(path);
    if args.iter().any(|a| a == "--json") {
        // Hand-rolled rather than pulling in serde: this crate deliberately
        // depends on libc alone, and a firewall is the wrong place to widen a
        // dependency tree for the sake of one array of flat records.
        println!("[");
        for (i, r) in rs.iter().enumerate() {
            let comment = match &r.comment {
                Some(c) => format!("\"{}\"", json_escape(c)),
                None => "null".to_string(),
            };
            println!(
                "  {{\"kind\":\"{}\",\"value\":\"{}\",\"comment\":{}}}{}",
                json_escape(&r.kind),
                json_escape(&r.value),
                comment,
                if i + 1 == rs.len() { "" } else { "," }
            );
        }
        println!("]");
        return;
    }
    if rs.is_empty() {
        println!("no rules in {}", path.display());
        return;
    }
    for r in &rs {
        match &r.comment {
            Some(c) => println!("{:<11} {:<44} # {c}", r.kind, r.value),
            None => println!("{:<11} {}", r.kind, r.value),
        }
    }
}

fn cmd_add(args: &[String], verb: &str) {
    let (what, value) = match (args.get(2), args.get(3)) {
        (Some(w), Some(v)) => (w.as_str(), v.as_str()),
        _ => {
            eprintln!("usage: pfsnitch {verb} <host|app|dest> <value>");
            std::process::exit(64);
        }
    };
    let from = args
        .iter()
        .position(|a| a == "--from")
        .and_then(|i| args.get(i + 1))
        .map(String::as_str);
    // `--from` with nothing after it must not quietly fall back to a GLOBAL
    // deny: the user asked to scope the rule, and silently widening it is the
    // opposite of what they asked for.
    if args.iter().any(|a| a == "--from") && from.is_none() {
        eprintln!("pfsnitch: --from needs a binary path");
        std::process::exit(64);
    }
    let kind = match (verb, what, from.is_some()) {
        ("allow", "host", false) => "allow-host",
        ("allow", "host", true) => "allow-host-from",
        ("allow", "dest", true) | ("allow", "ip", true) => "allow-dest-from",
        ("allow", "app", _) => "allow-app",
        ("allow", "dest", false) | ("allow", "ip", false) => "allow-dest",
        ("deny", "host", false) => "deny-host",
        ("deny", "host", true) => "deny-host-from",
        ("deny", "dest", true) | ("deny", "ip", true) => "deny-dest-from",
        ("deny", "app", _) => "deny-app",
        ("deny", "dest", false) | ("deny", "ip", false) => "deny-dest",
        _ => {
            eprintln!("pfsnitch: cannot `{verb} {what}`{}", if from.is_some() { " --from ..." } else { "" });
            eprintln!("  allow: host | app | dest | host <name> --from <binary> | dest <ip> --from <binary>");
            eprintln!("  deny:  host | app | dest | host <name> --from <binary> | dest <ip> --from <binary>");
            std::process::exit(64);
        }
    };
    // Scoped rules carry both halves in the value, destination first.
    let scoped;
    let value = match from {
        Some(e) if kind.ends_with("-from") => {
            scoped = format!("{value} {e}");
            scoped.as_str()
        }
        _ => value,
    };
    let note = args
        .iter()
        .position(|a| a == "--note")
        .and_then(|i| args.get(i + 1))
        .map(String::as_str);
    match policy::add_rule(Path::new(POLICY_PATH), kind, value, note) {
        Ok(true) => println!("added: {kind} {value}"),
        Ok(false) => println!("already present: {kind} {value}"),
        Err(e) => {
            eprintln!("pfsnitch: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_rm(args: &[String]) {
    let (kind, value) = match (args.get(2), args.get(3)) {
        (Some(k), Some(v)) => (k.as_str(), v.as_str()),
        _ => {
            eprintln!("usage: pfsnitch rm <kind> <value>");
            eprintln!("  kinds: {}", policy::KINDS.join(", "));
            eprintln!("  the kind is spelled exactly as `pfsnitch rules` prints it");
            std::process::exit(64);
        }
    };
    if !policy::KINDS.contains(&kind) {
        eprintln!("pfsnitch: unknown rule type {kind:?}");
        eprintln!("  kinds: {}", policy::KINDS.join(", "));
        std::process::exit(64);
    }
    // A scoped rule is two words, and `pfsnitch rules` prints them that way, so
    // accept them as separate arguments and rejoin - copy-paste has to work.
    let joined = args[3..].join(" ");
    let value = if kind.ends_with("-from") { joined.as_str() } else { value };

    match policy::remove_rule(Path::new(POLICY_PATH), kind, value) {
        Ok(0) => {
            println!("no such rule: {kind} {value}");
            std::process::exit(1);
        }
        Ok(n) => println!("removed {n} rule{}", if n == 1 { "" } else { "s" }),
        Err(e) => {
            eprintln!("pfsnitch: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_status(args: &[String]) {
    let path = Path::new(POLICY_PATH);
    let pol = policy::Policy::load(path);
    let rs = policy::rules(path);
    let count = |k: &str| rs.iter().filter(|r| r.kind == k).count();

    // Liveness by looking for the daemon in the process table, NOT by trying to
    // bind its divert port. The port test is definitive but needs root, so
    // every unprivileged frontend got "unknown" - and more than one of them
    // rendered that as "not running", telling the user the firewall was off
    // while it was running. This answers for everyone.
    let running_s = if procinfo::daemon_running() {
        "running"
    } else {
        "stopped"
    };

    if args.iter().any(|a| a == "--json") {
        println!(
            "{{\"daemon\":\"{}\",\"mode\":\"{}\",\"policy\":\"{}\",\"prompt\":\"{}\",\"rules\":{{{}}},\"total\":{}}}",
            running_s,
            pol.mode(policy::Mode::Visibility).as_str(),
            json_escape(&path.display().to_string()),
            json_escape(&pol.prompt_bin(PROMPT_BIN)),
            policy::KINDS
                .iter()
                .map(|k| format!("\"{k}\":{}", count(k)))
                .collect::<Vec<_>>()
                .join(","),
            rs.len()
        );
        return;
    }
    println!("daemon:  {running_s}");
    println!("mode:    {}", pol.mode(policy::Mode::Visibility).as_str());
    println!("policy:  {}", path.display());
    println!("prompt:  {}", pol.prompt_bin(PROMPT_BIN));
    println!("default: {}", pol.summary());
    for k in policy::KINDS {
        println!("  {:<11} {}", k, count(k));
    }
    println!("  {:<11} {}", "total", rs.len());
}

fn probe() {
    let snap = procinfo::snapshot();
    println!("{:<16} {:>7}  {:<40} {:<26} {}", "COMMAND", "PID", "PATH", "REMOTE", "HOW");
    let mut rows = snap.entries();
    rows.sort_by(|a, b| {
        a.owner.command.cmp(&b.owner.command).then(a.lport.cmp(&b.lport))
    });
    for e in &rows {
        let remote = match e.peer {
            Some((ip, port)) => format!("{ip}:{port}"),
            // An unconnected socket has no peer at all. What identifies it is
            // the address and port it is bound to, so show those - otherwise
            // several sockets of one process render as identical rows.
            None => format!("(unconnected) {}:{}", e.local, e.lport),
        };
        println!(
            "{:<16} {:>7}  {:<40} {:<26} {}",
            e.owner.command, e.owner.pid, e.owner.path, remote, e.confidence.as_str()
        );
    }
    eprintln!("\n  {} attributable sockets", rows.len());
}

/// A prompt that has been raised and not yet answered.
struct Pending {
    host: Option<String>,
    exe: Option<String>,
    dst: IpAddr,
    // Carried through the prompt so the recorded rule names the port that was
    // actually asked about, not whichever one happens to come back first.
    dport: u16,
}

/// Open the kernel attribution device if the policy asks for it, saying what
/// happened either way: a policy naming a module that is not loaded must be
/// noticed, not silently downgraded to the userspace path.
fn kern_backend(pol: &policy::Policy) -> Option<kernattr::KernAttr> {
    if pol.attribution() != policy::AttributionMode::Kernel {
        return None;
    }
    match kernattr::KernAttr::open() {
        Ok(k) => {
            eprintln!("pfsnitch: attribution: kernel (mac_pfsnitch.ko), procstat as fallback");
            // Start from a known-empty cache: the daemon's policy is the
            // authority, and any entries a previous daemon left behind must not
            // outlive it.
            k.flush_verdicts();
            Some(k)
        }
        Err(e) => {
            eprintln!("pfsnitch: attribution kernel requested but /dev/pfsnitch: {e}");
            eprintln!("  using procstat until the module is loaded (kldload mac_pfsnitch)");
            None
        }
    }
}

fn run(fallback_mode: policy::Mode) {
    let policy_path = Path::new(POLICY_PATH);
    let mut pol = policy::Policy::load(policy_path);
    let mut mode = pol.mode(fallback_mode);
    let mut kern = kern_backend(&pol);
    let mut pol_mtime = policy::mtime(policy_path);
    let mut last_check = Instant::now();
    // Resolved once: env var, then the policy file's `prompt` directive, then
    // the default. Any executable honouring the documented argv/stdout contract
    // works here, which is what keeps this daemon independent of any desktop.
    let prompt_bin = pol.prompt_bin(PROMPT_BIN);

    let d = match divert::Divert::bind(DIVERT_PORT) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("pfsnitch: cannot bind divert port {DIVERT_PORT}: {e}");
            eprintln!("  needs root; ipdivert.ko must be loaded");
            std::process::exit(1);
        }
    };

    eprintln!(
        "pfsnitch: divert {DIVERT_PORT}  mode={}  policy: {}",
        mode.as_str(),
        pol.summary()
    );
    if !mode.enforcing() {
        eprintln!("  visibility: every packet is reinjected. New destinations are recorded as");
        eprintln!("  allow rules rather than prompted for, so the policy learns what this machine");
        eprintln!("  talks to. Prompts appear only in enforcement, where there is a decision to make.");
    }

    // Keep the loop ticking without divert traffic so the upcall channel and
    // periodic work are serviced promptly.
    let _ = d.set_read_timeout(100);

    // Answers arrive from prompt threads; the read loop must never block on one.
    let (tx, rx) = mpsc::channel::<(Answer, Pending)>();

    // Phase 3 upcall: the reader thread delivers cache-miss events here; the
    // main loop decides and RESOLVEs them, keeping all policy state single-
    // threaded. `upcall_on` tracks whether the hook is asking us (enabled only
    // with the kernel backend, in enforcement - visibility must never block).
    // `pending_upcalls` holds event ids awaiting a prompt answer, keyed exactly
    // like `asking`, so one answer resolves every miss it covers.
    let (utx, urx) = mpsc::channel::<kernattr::KernEvent>();
    let mut upcall_on = false;
    let mut pending_upcalls: HashMap<(String, String), Vec<u64>> = HashMap::new();

    let mut res = procinfo::Resolver::new();
    let mut ident = identity::Identity::new();
    let mut seen = seen::Seen::new();
    // Binaries already reported as changed, so the warning is loud once rather
    // than once per retransmitted packet.
    let mut id_warned: HashSet<String> = HashSet::new();
    let mut names = dns::DnsCache::new();
    // One prompt per (binary, destination) in flight. Without this, a browser
    // opening thirty sockets to one host would raise thirty identical prompts.
    //
    // Keyed on the HOSTNAME when one is known, not the address. Keying on the
    // address raised a separate prompt per A record, so a single `curl
    // example.org` produced four prompt processes - and because they share one
    // nonce and one answer file, the newest overwrote the nonce and the rest
    // became unanswerable. The rule that gets written is `allow-host-from`,
    // which already covers every address the name resolves to, so the extra
    // prompts asked a question whose answer was going to cover them anyway.
    let mut asking: HashSet<(String, String)> = HashSet::new();
    // Flows already written to the log. See the note at the println below.
    let mut logged: HashSet<(u8, IpAddr, u16, IpAddr, u16)> = HashSet::new();
    // Settled verdicts, keyed on the flow. See the note in the packet loop.
    let mut decided: HashMap<(u8, IpAddr, u16, IpAddr, u16), Verdict> = HashMap::new();
    let mut logged_cleared = Instant::now();
    let mut buf = vec![0u8; 65_535];

    loop {
        // Drain any answers first so policy is current before the next verdict.
        while let Ok((ans, p)) = rx.try_recv() {
            let key = (p.exe.clone().unwrap_or_default(), ask_key(p.host.as_deref(), p.dst));
            asking.remove(&key);
            // Any upcall misses that were waiting on this prompt get the answer
            // now, so their retries resolve. Do this before pol.record so the
            // kernel cache and the policy file settle together.
            if let Some(ids) = pending_upcalls.remove(&key) {
                let allow = matches!(ans, Answer::AllowConn | Answer::AllowApp);
                if let Some(k) = kern.as_ref() {
                    for id in ids {
                        k.resolve(id, allow);
                    }
                }
            }
            if let Some(e) = p.exe.as_deref() {
                if matches!(ans, Answer::AllowConn | Answer::AllowApp) {
                    // Re-pin: if this approval follows a change warning, the
                    // user has just said the new binary is the one they want.
                    pol.forget_id(e);
                    id_warned.remove(e);
                    if let Some(sha) = ident.hash(e) {
                        pol.record_id(policy_path, e, &sha);
                    }
                }
            }
            pol.record(policy_path, ans, p.exe.as_deref(), p.dst, p.host.as_deref(), p.dport, policy::Origin::Approved);
            eprintln!("  decision: {:?} for {} -> {}", ans, p.exe.as_deref().unwrap_or("?"), p.dst);
        }

        // Drain kernel upcalls: cache misses the hook is asking us to decide.
        // Attribution is already done (the event carries the owning binary), so
        // this is policy only, then RESOLVE - allow/deny answer at once, ask
        // spawns a prompt and answers when the user does. Enforcement only:
        // upcalls are never enabled in visibility.
        while let Ok(ev) = urx.try_recv() {
            if ev.path.is_empty() {
                if let Some(k) = kern.as_ref() { k.resolve(ev.id, true); }
                continue;
            }
            let host = names.name_for(&ev.dst).map(|s| s.to_string());
            let mut id_changed = false;
            if let Some(expected) = pol.expected_id(&ev.path).map(str::to_string) {
                if let Some(actual) = ident.hash(&ev.path) {
                    if actual != expected {
                        id_changed = true;
                        if id_warned.insert(ev.path.clone()) {
                            eprintln!(
                                "pfsnitch: BINARY CHANGED {}\n  approved {expected}\n  now      {actual}\n  its rules are being ignored until you approve it again",
                                ev.path
                            );
                        }
                    }
                }
            }
            let verdict = if id_changed {
                Verdict::Ask
            } else {
                pol.decide(Some(&ev.path), ev.dst, host.as_deref(), ev.dport)
            };
            match verdict {
                Verdict::Allow => { if let Some(k) = kern.as_ref() { k.resolve(ev.id, true); } }
                Verdict::Deny => { if let Some(k) = kern.as_ref() { k.resolve(ev.id, false); } }
                Verdict::Ask => {
                    let hostname = host.clone().unwrap_or_default();
                    let key = (
                        ev.path.clone(),
                        ask_key(if hostname.is_empty() { None } else { Some(&hostname) }, ev.dst),
                    );
                    if asking.insert(key.clone()) {
                        let cmd = ev.path.rsplit('/').next().unwrap_or(&ev.path).to_string();
                        spawn_prompt(
                            prompt_bin.clone(), id_changed, tx.clone(),
                            Some(ev.path.clone()), ev.pid, cmd,
                            ev.dst, ev.dport, hostname, "kernel".to_string(),
                        );
                    }
                    // Answered when the prompt returns; see the rx drain above.
                    pending_upcalls.entry(key).or_default().push(ev.id);
                }
            }
            let dest = host.as_deref().unwrap_or("-");
            eprintln!("  upcall {verdict:?}  {} -> {} ({dest}) :{}", ev.path, ev.dst, ev.dport);
        }

        // Pick up edits from any source - our own CLI, an editor, a frontend.
        // Polling the mtime beats a signal or a socket: nothing has to find the
        // daemon, so a frontend needs no privileges and no protocol.
        // Forget logged flows periodically: bounds memory, and lets a
        // long-running flow reappear in the log rather than vanishing after
        // its first packet.
        // Rate-limited inside; this is just the tick that lets it happen.
        seen.flush(Duration::from_secs(10));

        if logged_cleared.elapsed() >= Duration::from_secs(120) || logged.len() > 8192 {
            logged.clear();
            logged_cleared = Instant::now();
        }

        if last_check.elapsed() >= Duration::from_secs(1) {
            last_check = Instant::now();

            // Keep the kernel backend honest. kldunload revokes the open fd
            // (every ioctl becomes ENXIO), and a re-loaded module is a NEW
            // device the old fd will never reach - so a dead handle is dropped
            // loudly, and while the policy still asks for kernel attribution
            // the open is retried each tick, silently on failure (once a
            // second is not worth a log line) and loudly on recovery.
            if pol.attribution() == policy::AttributionMode::Kernel {
                if kern.as_ref().is_some_and(|k| k.is_dead()) {
                    eprintln!("pfsnitch: /dev/pfsnitch went away (module unloaded?); using procstat");
                    kern = None;
                } else if kern.is_none() {
                    if let Ok(k) = kernattr::KernAttr::open() {
                        eprintln!("pfsnitch: attribution: kernel (mac_pfsnitch.ko reconnected)");
                        // A reloaded module has an empty cache already; flush is
                        // belt and braces so the daemon and kernel never disagree.
                        k.flush_verdicts();
                        kern = Some(k);
                    }
                }
            }

            let m = policy::mtime(policy_path);
            if m != pol_mtime {
                pol_mtime = m;
                let was_attr = pol.attribution();
                pol = policy::Policy::load(policy_path);
                let was = mode;
                mode = pol.mode(fallback_mode);
                if pol.attribution() != was_attr {
                    // Same runtime-switch contract as mode: takes effect within
                    // a second, never restarts the daemon or drops the socket.
                    kern = kern_backend(&pol);
                    if pol.attribution() == policy::AttributionMode::Procstat {
                        eprintln!("pfsnitch: attribution: procstat (userspace)");
                    }
                }
                // Every cached verdict was derived from the policy that just
                // changed. Keeping them would mean a rule you added or removed
                // silently not applying to traffic already in flight.
                decided.clear();
                // The kernel cache is derived from the policy that just changed,
                // so it must be abandoned at the same instant as the daemon's own
                // decided map - a cached allow or deny outliving its rule is a
                // correctness failure. Flows re-populate it as they recur.
                if let Some(k) = kern.as_ref() {
                    k.flush_verdicts();
                }
                eprintln!("pfsnitch: policy reloaded: {}", pol.summary());
                if mode != was {
                    // Worth its own line: this is the one setting that changes
                    // whether packets actually get dropped.
                    eprintln!("pfsnitch: mode {} -> {}", was.as_str(), mode.as_str());
                }
            }

            // Reconcile the upcall: on only with the kernel backend, in
            // enforcement - visibility must never drop a first packet. The
            // reader thread is (re)spawned on enable and exits on the EOF that
            // disabling (or unload) produces.
            let want_upcall = kern.is_some() && mode.enforcing();
            if want_upcall && !upcall_on {
                match kernattr::KernReader::open() {
                    Ok(rd) => {
                        if let Some(k) = kern.as_ref() { k.set_upcall(true); }
                        let utx2 = utx.clone();
                        std::thread::spawn(move || {
                            while let Ok(Some(ev)) = rd.read_event() {
                                if utx2.send(ev).is_err() { break; }
                            }
                        });
                        upcall_on = true;
                        eprintln!("pfsnitch: upcall enabled - misses decided in-kernel");
                    }
                    Err(e) => eprintln!("pfsnitch: upcall reader open failed: {e}"),
                }
            } else if !want_upcall && upcall_on {
                if let Some(k) = kern.as_ref() { k.set_upcall(false); }
                upcall_on = false;
                // Any waiters will never be answered now; drop them - their apps
                // fall back to the divert path on retry.
                pending_upcalls.clear();
                eprintln!("pfsnitch: upcall disabled");
            }
        }

        let (n, from) = match d.recv(&mut buf) {
            Ok(v) => v,
            // Timed out with no packet: loop back to service the channels.
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => { eprintln!("recv: {e}"); continue; }
        };

        let mut allow = true;
        // Distinct from !allow: a packet held while a prompt is open must be
        // dropped silently, because its retransmission is what carries the
        // connection until the user answers. Only a settled deny is rejected.
        let mut reject = false;

        if let Some(f) = divert::parse(&buf[..n]) {
            // DNS answers teach us hostnames. Handled before the verdict
            // path: a reply from port 53 is evidence, not a connection
            // attempt, and must never raise a prompt.
            if f.proto == 17 && f.sport == 53 {
                if let Some(off) = divert::payload_offset(&buf[..n]) {
                    if off < n {
                        names.observe(&buf[off..n]);
                    }
                }
                if let Err(e) = d.reinject(&buf[..n], &from) { eprintln!("reinject: {e}"); }
                continue;
            }

            // An INBOUND packet is not a connection attempt, and must never be
            // judged as one.
            //
            // pf stores the divert action in the state, and states are
            // bidirectional, so replies come back through here too. The tuple is
            // then reversed - the reply to a QUIC request reads as
            // `<server>:443 -> 10.0.0.2:<ephemeral>`, an "outbound connection" to
            // our own address on a port no process is listening on. Nothing owns
            // that, so it prompted, and approving it wrote
            // `allow-dest 10.0.0.2:<ephemeral>` - a machine-wide rule naming this
            // host on a port that never recurs. 33 such rules had accumulated,
            // every one of them already dead: `last: never`, because an ephemeral
            // port is not reused.
            //
            // Judging the outbound direction is what enforcement means; the reply
            // was already decided when its flow was. Unsolicited inbound cannot
            // reach here anyway - pf.conf blocks in before this anchor, and the
            // only inbound divert rule is for DNS answers, handled above.
            if from.sin_addr.s_addr != 0 {
                if let Err(e) = d.reinject(&buf[..n], &from) { eprintln!("reinject: {e}"); }
                continue;
            }

            if f.syn_only || f.proto == 17 {
                // pf diverts EVERY packet of a flow, in both directions - the
                // divert action lives in the pf state, not just on the rule. So
                // this path runs per packet, and deriving the same verdict again
                // for the ten-thousandth packet of a download is pure waste.
                //
                // It is also not cheap waste: the derivation allocates several
                // strings per packet and scans every scoped rule doing
                // case-insensitive comparisons. One video was enough to peg a
                // core. A settled verdict cannot change until the policy does,
                // so remember it and let the rest of the flow skip all of it.
                let flow = (f.proto, f.src, f.sport, f.dst, f.dport);

                if let Some(v) = decided.get(&flow) {
                    match v {
                        Verdict::Allow => allow = true,
                        Verdict::Deny => {
                            allow = false;
                            reject = true;
                        }
                        // Never cached: an Ask is a question in flight, and its
                        // answer is exactly what is about to change.
                        Verdict::Ask => {}
                    }
                } else {
                    let t = procinfo::Tuple {
                        proto: f.proto, src: f.src, sport: f.sport, dst: f.dst, dport: f.dport,
                    };
                    // Everything reaching here is outbound: inbound was
                    // reinjected above. The flag stays explicit because the weak
                    // attribution tiers key on the packet's SOURCE as the local
                    // end, which is only true outbound - see procinfo::Tables::get.
                    //
                    // The kernel backend is asked first when configured; a miss
                    // there is normal (a socket from before the module loaded)
                    // and falls through to the procstat scan, with the
                    // confidence tier recording which one answered.
                    let att = kern
                        .as_ref()
                        .and_then(|k| k.query(&t))
                        .or_else(|| res.resolve(&t, true));
                    let owner = att.as_ref().map(|a| a.owner.clone());
                    let exe = owner.as_ref().map(|o| o.path.clone());
                    // "none" is not just a weaker "local": it is what turns an
                    // accepted prompt into a rule binding EVERY binary, so the
                    // prompt has to be able to say so.
                    let scope = att.as_ref().map(|a| a.confidence.as_str()).unwrap_or("none");
                    let hostname = names.name_for(&f.dst).map(|s| s.to_string());
                    // A rule is a standing permission attached to a PATH, but the
                    // file behind a path can be replaced. If the binary is not the
                    // one that was approved, the rules it earned do not apply to
                    // whatever is there now - fall back to asking.
                    let mut id_changed = false;
                    if let Some(e) = exe.as_deref() {
                        if let Some(expected) = pol.expected_id(e).map(str::to_string) {
                            if let Some(actual) = ident.hash(e) {
                                if actual != expected {
                                    id_changed = true;
                                    if id_warned.insert(e.to_string()) {
                                        eprintln!(
                                            "pfsnitch: BINARY CHANGED {e}\n  approved {expected}\n  now      {actual}\n  its rules are being ignored until you approve it again"
                                        );
                                    }
                                }
                            }
                        }
                    }

                    let verdict = if id_changed {
                        Verdict::Ask
                    } else {
                        pol.decide(exe.as_deref(), f.dst, hostname.as_deref(), f.dport)
                    };

                    // What the log will call this. Ask becomes Learn in
                    // visibility, because nothing is being asked - we are
                    // writing the rule.
                    let mut label = format!("{verdict:?}");

                    match verdict {
                        Verdict::Allow => allow = true,
                        Verdict::Deny => { allow = false; reject = true; }
                        Verdict::Ask if mode.enforcing() => {
                            allow = false; // hold it: the SYN will be retried
                            let host = names.name_for(&f.dst).unwrap_or("").to_string();
                            let key = (
                                exe.clone().unwrap_or_default(),
                                ask_key(if host.is_empty() { None } else { Some(&host) }, f.dst),
                            );
                            if asking.insert(key) {
                                spawn_prompt(
                                    prompt_bin.clone(),
                                    id_changed,
                                    tx.clone(),
                                    exe.clone(),
                                    owner.as_ref().map(|o| o.pid).unwrap_or(0),
                                    owner.as_ref().map(|o| o.command.clone()).unwrap_or_default(),
                                    f.dst,
                                    f.dport,
                                    host,
                                    scope.to_string(),
                                );
                            }
                        }
                        Verdict::Ask => {
                            // Visibility learns instead of asking. The point of
                            // this mode is to see everything the machine talks to
                            // and end up with a rule set describing it, so a
                            // dialog here would be noise: there is nothing to
                            // decide when the packet is going to be reinjected
                            // either way.
                            allow = true;
                            pol.record(
                                policy_path,
                                Answer::AllowConn,
                                exe.as_deref(),
                                f.dst,
                                hostname.as_deref(),
                                f.dport,
                                policy::Origin::Learned,
                            );
                            // We just wrote the file ourselves, so move our
                            // watermark past that write. Otherwise the next tick
                            // sees a changed mtime and re-reads a file we already
                            // agree with - once per learned connection.
                            pol_mtime = policy::mtime(policy_path);
                            label = "Learn".to_string();
                        }
                    }

                    // Only a settled verdict is worth remembering. Caching an Ask
                    // would freeze the flow in the state of not yet knowing.
                    if matches!(verdict, Verdict::Allow | Verdict::Deny) {
                        if decided.len() > 16_384 {
                            decided.clear();
                        }
                        decided.insert(flow, verdict);

                        // Phase 2: push the settled verdict into the kernel's
                        // cache, so a later connect() to this (binary,
                        // destination) is answered in the socket hook - a cached
                        // deny fails connect() with EPERM, before any packet.
                        //
                        // Only while enforcing. Visibility must never block, but
                        // the kernel hook has no notion of mode and enforces a
                        // cached deny unconditionally - so nothing is pushed while
                        // observing, and the mode switch itself flushes the cache.
                        if mode.enforcing() {
                            if let (Some(k), Some(p)) = (kern.as_ref(), exe.as_deref()) {
                                k.push_verdict(f.proto, f.dst, f.dport, p, matches!(verdict, Verdict::Allow));
                            }
                        }
                    }

                    // DNS-over-HTTPS, which we cannot observe.
                    let host = names.name_for(&f.dst).unwrap_or("-");

                    // Note the contact. Spelled the way a rule spells it -
                    // hostname when we saw one, address otherwise - so
                    // `pfsnitch apps` can join these against rules without a
                    // second matching scheme that could disagree with the first.
                    if let Some(e) = exe.as_deref() {
                        let dest = if host == "-" { f.dst.to_string() } else { host.to_string() };
                        seen.touch(e, &dest);
                    }

                    if logged.insert(flow) {
                        // The tier says which backend did the naming (kernel /
                        // exact / local / port), which is how you verify that
                        // `attribution kernel` is actually answering rather
                        // than silently falling back to the procstat scan.
                        println!(
                            "{:<6} {}:{} -> {} ({}) :{}  {}",
                            label,
                            f.src, f.sport, f.dst, host, f.dport,
                            owner.as_ref()
                                .map(|o| format!("{} [{}] {} ({scope})", o.command, o.pid, o.path))
                                .unwrap_or_else(|| "<unattributed>".into()),
                        );
                    }
                }
            }
        }
        // Observe mode never drops: that is the entire point of having it.
        if mode.enforcing() && reject {
            // Tell the application no, now, the way a closed port would. Left to
            // time out instead, a blocked connection reads as a broken network
            // rather than a decision - 75 seconds of nothing by default.
            if let Some(rst) = divert::tcp_rst(&buf[..n]) {
                if let Err(e) = d.reinject_inbound(&rst) {
                    eprintln!("reset: {e}");
                }
            }
        }
        if !mode.enforcing() || allow {
            if let Err(e) = d.reinject(&buf[..n], &from) {
                eprintln!("reinject: {e}");
            }
        }
    }
}

/// What counts as "the same question" for prompt de-duplication.
///
/// The hostname when we have one, because the approval is written as
/// `allow-host-from` and covers every address behind that name. Falling back to
/// the address is right only when no name was seen - then the address really is
/// the identity of the destination.
fn ask_key(host: Option<&str>, dst: IpAddr) -> String {
    match host {
        Some(h) if !h.is_empty() && h != "-" => h.to_lowercase(),
        _ => dst.to_string(),
    }
}

/// Raise a prompt on a thread. The read loop must keep servicing the divert
/// socket while the user thinks - a blocked loop means a stalled network.
fn spawn_prompt(
    prompt_bin: String,
    id_changed: bool,
    tx: mpsc::Sender<(Answer, Pending)>,
    exe: Option<String>,
    pid: i32,
    cmd: String,
    dst: IpAddr,
    dport: u16,
    host: String,
    scope: String,
) {
    std::thread::spawn(move || {
        // keep a copy: the arg below moves the original into the command
        let host2 = host.clone();
        let out = Command::new(&prompt_bin)
            .arg(exe.clone().unwrap_or_else(|| "<unknown>".into()))
            .arg(pid.to_string())
            .arg(if cmd.is_empty() { "<unknown>".into() } else { cmd })
            .arg(dst.to_string())
            .arg(dport.to_string())
            .arg(if host.is_empty() { "-".to_string() } else { host })
            // Optional 7th argument. A backend that does not know about it just
            // ignores it, which is why it goes last.
            .arg(if id_changed { "changed" } else { "ok" })
            // Optional 8th argument: how the owner was attributed - exact,
            // local, port, or none. Backends written before it ignore it.
            .arg(&scope)
            .output();

        let ans = match out {
            Ok(o) => Answer::parse(&String::from_utf8_lossy(&o.stdout)).unwrap_or(Answer::Timeout),
            Err(e) => {
                eprintln!("prompt failed: {e}");
                Answer::Timeout
            }
        };
        let _ = tx.send((ans, Pending { exe, dst, dport, host: if host2.is_empty() { None } else { Some(host2) } }));
    });
}

fn cmd_attribution(args: &[String]) {
    let path = Path::new(POLICY_PATH);
    let pol = policy::Policy::load(path);
    match args.get(2) {
        None => println!("{}", pol.attribution().as_str()),
        Some(want) => {
            let a = match policy::AttributionMode::parse(want) {
                Some(a) => a,
                None => {
                    eprintln!("pfsnitch: unknown attribution backend {want:?}");
                    eprintln!("  want: kernel | procstat");
                    std::process::exit(64);
                }
            };
            if a == policy::AttributionMode::Kernel && !Path::new("/dev/pfsnitch").exists() {
                // Not fatal - the module may be loaded later, and the daemon
                // falls back to procstat until it is - but silently accepting
                // a setting that does nothing yet would read as it working.
                eprintln!("pfsnitch: note: /dev/pfsnitch not present (kldload mac_pfsnitch)");
                eprintln!("  the daemon will use procstat until the module is loaded");
            }
            match policy::set_attribution(path, a) {
                Ok(()) => {
                    println!("attribution: {}", a.as_str());
                    match a {
                        policy::AttributionMode::Kernel => {
                            println!("  flows are named by mac_pfsnitch.ko, recorded at socket");
                            println!("  creation; procstat remains the fallback for a miss");
                        }
                        policy::AttributionMode::Procstat => {
                            println!("  flows are named by scanning the process table (userspace)");
                        }
                    }
                    println!("  the running daemon picks this up within a second");
                }
                Err(e) => {
                    eprintln!("pfsnitch: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}

fn cmd_mode(args: &[String]) {
    let path = Path::new(POLICY_PATH);
    let pol = policy::Policy::load(path);
    match args.get(2) {
        None => println!("{}", pol.mode(policy::Mode::Visibility).as_str()),
        Some(want) => {
            let m = match policy::Mode::parse(want) {
                Some(m) => m,
                None => {
                    eprintln!("pfsnitch: unknown mode {want:?}");
                    eprintln!("  want: visibility | enforcement");
                    std::process::exit(64);
                }
            };
            match policy::set_mode(path, m) {
                Ok(()) => {
                    println!("mode: {}", m.as_str());
                    // Say what changed in terms of consequence, not state: the
                    // whole point of the switch is whether packets get dropped.
                    if m.enforcing() {
                        println!("  unapproved connections are now blocked");
                    } else {
                        println!("  decisions are logged; nothing is blocked");
                    }
                    println!("  the running daemon picks this up within a second");
                }
                Err(e) => {
                    eprintln!("pfsnitch: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}

/// A rule broken into the parts a frontend actually wants to show.
struct Split {
    app: String,   // owning binary, or "" for rules that match every binary
    dest: String,  // what the rule is about, in human terms
    effect: &'static str,
}

/// Decompose a rule into (owning app, destination, allow/deny).
///
/// The policy file stores rules by kind; a UI almost always wants them by
/// application. Doing that split here rather than in each frontend means eww, a
/// TUI and a shell one-liner all group them identically.
fn split_rule(kind: &str, value: &str) -> Split {
    let effect = if kind.starts_with("deny") { "deny" } else { "allow" };
    match kind {
        // The value IS the binary, and the rule covers everywhere it connects.
        "allow-app" | "deny-app" => Split {
            app: value.to_string(),
            dest: "all destinations".to_string(),
            effect,
        },
        // "<destination> <binary>" - destination first, since it can never
        // contain whitespace and a path can.
        "allow-host-from" | "allow-dest-from" | "deny-host-from" | "deny-dest-from" => {
            let mut it = value.splitn(2, char::is_whitespace);
            let dest = it.next().unwrap_or("").to_string();
            let app = it.next().unwrap_or("").trim().to_string();
            Split { app, dest, effect }
        }
        // Everything else matches any binary.
        _ => Split { app: String::new(), dest: value.to_string(), effect },
    }
}

fn cmd_apps(args: &[String]) {
    let path = Path::new(POLICY_PATH);
    let rs = policy::rules(path);
    // Written by the daemon; absent if it has never run. A missing table means
    // "never", not an error.
    let last = seen::load();

    // Preserve first-seen order within a group, but sort the groups themselves,
    // so the list does not reshuffle every time a rule is added.
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<(policy::Rule, Split)>> = HashMap::new();
    for r in rs {
        let s = split_rule(&r.kind, &r.value);
        let key = s.app.clone();
        if !groups.contains_key(&key) {
            order.push(key.clone());
        }
        groups.entry(key).or_default().push((r, s));
    }
    // Named applications first, alphabetically by basename; the catch-all group
    // last, because it is infrastructure rather than something you tune.
    order.sort_by_key(|a| {
        let base = a.rsplit('/').next().unwrap_or(a).to_lowercase();
        (a.is_empty(), base)
    });

    // A rule names a destination and possibly a port; the daemon records only
    // the destination, so strip the port before joining. An app-wide rule has
    // no single destination, so it takes the most recent of anything that
    // binary did.
    let rule_seen = |app: &str, s: &Split| -> Option<u64> {
        // An unscoped rule is not owned by any binary, so the useful answer is
        // the most recent time ANY binary used that destination. Reporting
        // "never" for a rule that is plainly in use would be worse than useless.
        if app.is_empty() {
            let (host, _) = policy::split_target(&s.dest);
            let h = host.to_lowercase();
            return last.iter().filter(|((_, d), _)| *d == h).map(|(_, t)| *t).max();
        }
        if s.dest == "all destinations" {
            return last
                .iter()
                .filter(|((e, _), _)| e == app)
                .map(|(_, t)| *t)
                .max();
        }
        let (host, _) = policy::split_target(&s.dest);
        last.get(&(app.to_string(), host.to_lowercase())).copied()
    };

    let json = args.iter().any(|a| a == "--json");
    if !json {
        for app in &order {
            let rules = &groups[app];
            let label = if app.is_empty() { "(any application)" } else { app.as_str() };
            let allow = rules.iter().filter(|(_, s)| s.effect == "allow").count();
            let deny = rules.len() - allow;
            // For the catch-all group, the most recent of the destinations it
            // actually covers - otherwise the header reads "never" above rules
            // that plainly are not.
            let app_last = if app.is_empty() {
                rules.iter().filter_map(|(_, s)| rule_seen(app, s)).max()
            } else {
                last.iter().filter(|((e, _), _)| e == app).map(|(_, t)| *t).max()
            };
            println!("{label}  [{allow} allow, {deny} deny]  last: {}", seen::ago(app_last));
            for (r, s) in rules {
                println!(
                    "    {:<5} {:<40} {:<10} {}",
                    s.effect,
                    s.dest,
                    seen::ago(rule_seen(app, s)),
                    r.kind
                );
            }
        }
        if order.is_empty() {
            println!("no rules in {}", path.display());
        }
        return;
    }

    println!("{{\"apps\":[");
    for (i, app) in order.iter().enumerate() {
        let rules = &groups[app];
        let allow = rules.iter().filter(|(_, s)| s.effect == "allow").count();
        let deny = rules.len() - allow;
        // Split the path so a UI can show the directory quietly and the binary
        // loudly. The directory is the security-relevant half - /tmp/git and
        // /usr/local/bin/git are different programs with different rules, and a
        // view showing only "git" cannot tell them apart.
        let (dir, name) = if app.is_empty() {
            (String::new(), "any application".to_string())
        } else {
            match app.rfind('/') {
                Some(i) => (app[..=i].to_string(), app[i + 1..].to_string()),
                None => (String::new(), app.clone()),
            }
        };
        println!("  {{");
        println!("    \"app\":\"{}\",", json_escape(app));
        println!("    \"dir\":\"{}\",", json_escape(&dir));
        println!("    \"dir_short\":\"{}\",", json_escape(&short_dir(&dir, 15)));
        println!("    \"name\":\"{}\",", json_escape(&name));
        let app_last = if app.is_empty() {
            rules.iter().filter_map(|(_, s)| rule_seen(app, s)).max()
        } else {
            last.iter().filter(|((e, _), _)| e == app).map(|(_, t)| *t).max()
        };
        println!("    \"allow\":{allow},\"deny\":{deny},\"total\":{},", rules.len());
        println!(
            "    \"last_seen\":{},\"last_seen_ago\":\"{}\",",
            app_last.map(|t| t.to_string()).unwrap_or_else(|| "null".into()),
            json_escape(&seen::ago(app_last))
        );
        println!("    \"rules\":[");
        for (j, (r, s)) in rules.iter().enumerate() {
            let comment = match &r.comment {
                Some(c) => format!("\"{}\"", json_escape(c)),
                None => "null".to_string(),
            };
            let ls = rule_seen(app, s);
            println!(
                "      {{\"kind\":\"{}\",\"value\":\"{}\",\"dest\":\"{}\",\"effect\":\"{}\",\"last_seen\":{},\"last_seen_ago\":\"{}\",\"comment\":{}}}{}",
                json_escape(&r.kind),
                json_escape(&r.value),
                json_escape(&s.dest),
                s.effect,
                ls.map(|t| t.to_string()).unwrap_or_else(|| "null".into()),
                json_escape(&seen::ago(ls)),
                comment,
                if j + 1 == rules.len() { "" } else { "," }
            );
        }
        println!("    ]");
        println!("  }}{}", if i + 1 == order.len() { "" } else { "," });
    }
    println!("]}}");
}

/// Shorten a directory for display, keeping the END rather than the start.
///
/// Truncating a path from the right hides the deepest directory, which is the
/// part that actually identifies the program: "/usr/local/share/c..." could be
/// anything, while ".../chromium/lib/" tells you what you are looking at. Cuts
/// on a separator so the result still reads as a path rather than a fragment.
fn short_dir(dir: &str, max: usize) -> String {
    let n = dir.chars().count();
    if n <= max {
        return dir.to_string();
    }
    let keep = max.saturating_sub(1);
    let tail: String = dir.chars().skip(n - keep).collect();
    match tail.find('/') {
        Some(i) => format!("\u{2026}{}", &tail[i..]),
        None => format!("\u{2026}{tail}"),
    }
}

fn cmd_forget(args: &[String]) {
    let exe = match args.get(2) {
        Some(e) if !e.is_empty() => e.as_str(),
        _ => {
            eprintln!("usage: pfsnitch forget <binary>");
            eprintln!("  removes every rule for that binary, and its pinned identity");
            std::process::exit(64);
        }
    };
    // The unscoped rules are not owned by any binary; they are the machine's
    // infrastructure - a resolver, a gateway. There is no sane reading of
    // "forget the empty string", and a plausible misreading deletes the rules
    // keeping the box on the network.
    if exe == "-" {
        eprintln!("pfsnitch: refusing - unscoped rules belong to no binary");
        eprintln!("  remove them individually with `pfsnitch rm`");
        std::process::exit(64);
    }
    match policy::remove_app(Path::new(POLICY_PATH), exe) {
        Ok((0, _)) => {
            println!("no rules for {exe}");
            std::process::exit(1);
        }
        Ok((n, backup)) => {
            println!("removed {n} rule{} for {exe}", if n == 1 { "" } else { "s" });
            println!("  previous policy saved as {backup}");
        }
        Err(e) => {
            eprintln!("pfsnitch: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_clear(args: &[String]) {
    let path = Path::new(POLICY_PATH);
    let rs = policy::rules(path);
    let pol = policy::Policy::load(path);

    // Saying yes to this in a shell should take more than one word.
    if !args.iter().any(|a| a == "--yes") {
        println!("this removes ALL {} rules from {}", rs.len(), path.display());
        if pol.mode(policy::Mode::Visibility).enforcing() {
            // Worth spelling out: the rules about to go include the ones
            // keeping this machine on the network.
            println!();
            println!("  you are in ENFORCEMENT. Clearing includes the infrastructure rules -");
            println!("  your gateway and resolver - so every connection will prompt until you");
            println!("  approve them again, starting with DNS.");
        }
        println!();
        println!("  re-run with --yes to do it (the previous policy is kept as a .bak)");
        std::process::exit(1);
    }
    match policy::clear_rules(path) {
        Ok((0, _)) => println!("no rules to clear"),
        Ok((n, backup)) => {
            println!("cleared {n} rules");
            println!("  previous policy saved as {backup}");
        }
        Err(e) => {
            eprintln!("pfsnitch: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod ask_key_tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// The regression. One name behind several A records must be ONE question:
    /// per-address keys raised a prompt per record, and because the prompts share
    /// a nonce and an answer file, all but the newest became unanswerable and the
    /// click did nothing.
    #[test]
    fn one_name_on_many_addresses_is_one_question() {
        let a = ask_key(Some("example.org"), ip(104, 20, 26, 136));
        let b = ask_key(Some("example.org"), ip(172, 66, 157, 237));
        assert_eq!(a, b);
    }

    /// The approval is written as allow-host-from, which covers the whole name,
    /// so collapsing them does not approve anything the user was not asked about.
    #[test]
    fn different_names_stay_separate() {
        assert_ne!(
            ask_key(Some("example.org"), ip(1, 2, 3, 4)),
            ask_key(Some("example.com"), ip(1, 2, 3, 4))
        );
    }

    /// With no name the address IS the identity of the destination.
    #[test]
    fn without_a_name_the_address_is_the_key() {
        assert_eq!(ask_key(None, ip(1, 2, 3, 4)), "1.2.3.4");
        assert_ne!(ask_key(None, ip(1, 2, 3, 4)), ask_key(None, ip(1, 2, 3, 5)));
    }

    /// The prompt contract uses "-" for "no hostname seen", and the empty string
    /// turns up wherever a name was looked up and missed. Neither is a name, and
    /// treating them as one would collapse every unnamed destination into a
    /// single question.
    #[test]
    fn placeholder_hostnames_are_not_names() {
        assert_eq!(ask_key(Some("-"), ip(1, 2, 3, 4)), "1.2.3.4");
        assert_eq!(ask_key(Some(""), ip(1, 2, 3, 4)), "1.2.3.4");
        assert_ne!(ask_key(Some("-"), ip(1, 2, 3, 4)), ask_key(Some("-"), ip(5, 6, 7, 8)));
    }

    /// DNS is case-insensitive; the rule is written lowercased. If the key were
    /// not, one host would ask twice.
    #[test]
    fn names_are_matched_case_insensitively() {
        assert_eq!(
            ask_key(Some("Example.ORG"), ip(1, 2, 3, 4)),
            ask_key(Some("example.org"), ip(9, 9, 9, 9))
        );
    }

    /// v6 and v4 for one name are still that one name.
    #[test]
    fn address_family_does_not_split_a_name() {
        let v6: IpAddr = "2606:2800:220:1::248".parse().unwrap();
        assert_eq!(ask_key(Some("example.org"), v6), ask_key(Some("example.org"), ip(1, 2, 3, 4)));
    }
}
