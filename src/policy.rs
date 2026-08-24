//! Policy: what to do about a connection.
//!
//! Rules key on the executable PATH (never the process name, which is trivially
//! spoofed) and on the HOSTNAME the application looked up (never just the IP).
//!
//! Hostname rules are the important part. A single site may answer on many
//! addresses - example.com has two A records, a CDN-backed site can have dozens
//! that rotate - so approving an IP would re-prompt endlessly for one site and
//! fill the file with unreviewable addresses. Approving the name covers every
//! address it resolves to, which is how Little Snitch behaves.
//!
//! Plain line-based config rather than TOML/serde: this daemon runs as root in
//! the packet path, and a dozen lines of key/value do not justify a parser
//! dependency tree. `libc` stays the only dependency.
//!
//! Format (/usr/local/etc/pfsnitch/policy.conf):
//!
//!     default ask                        # ask | allow | deny
//!     allow-app  /usr/local/bin/firefox  # this binary, anywhere
//!     deny-app   /usr/local/bin/nosy
//!     allow-host example.com             # every address this name resolves to
//!     allow-host *.googleapis.com        # and any subdomain
//!     allow-dest 8.8.8.8                 # raw address, for unnamed connections
//!
//! HONEST LIMITATIONS, both inherent rather than oversights:
//!   * `allow-dest` opens an address to EVERY process. pf cannot match a
//!     process, so per-application policy is enforced here, not in the kernel.
//!   * `allow-host` trusts the DNS we observed. Anything that resolves an
//!     approved name is allowed, so DNS poisoning would be honoured. Hostname
//!     rules carry this property everywhere, Little Snitch included.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
    Ask,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Approve the destination. If a hostname was seen this becomes a HOST
    /// rule covering every address that name resolves to; only a connection
    /// made to a bare IP falls back to approving the single address.
    AllowConn,
    AllowApp,
    /// Deny THIS destination to this binary only. An application that phones
    /// a metrics endpoint should lose the metrics endpoint, not the network.
    Block,
    /// Deny the binary everything. Deliberately a separate answer: it is a much
    /// bigger hammer and should never be what a plain "Block" click does.
    BlockApp,
    /// No answer in time. Treated as deny for this packet but NOT persisted -
    /// walking away from the screen must not permanently lock something out.
    Timeout,
}

impl Answer {
    pub fn parse(s: &str) -> Option<Answer> {
        match s.trim() {
            "allow-conn" => Some(Answer::AllowConn),
            "allow-app" => Some(Answer::AllowApp),
            "block-conn" | "block" => Some(Answer::Block),
            "block-app" => Some(Answer::BlockApp),
            "timeout" => Some(Answer::Timeout),
            _ => None,
        }
    }
}

#[derive(Debug, Default)]
pub struct Policy {
    default: Option<Verdict>,
    allow_app: HashSet<String>,
    deny_app: HashSet<String>,
    // Host and address rules carry an optional port. None means any port, which
    // is what a bare host means and what every rule written before ports
    // existed still means - so old policy files keep their meaning exactly.
    allow_host: HashSet<Target>,
    deny_host: HashSet<Target>,
    allow_dest: HashSet<(IpAddr, Option<u16>)>,
    /// Addresses denied to every binary. The mirror of allow_dest, and the
    /// reason it exists: without it, "Block" on a connection we could not
    /// attribute had nowhere to write, so `record` silently returned and the
    /// click did nothing at all. Allowing an unattributed connection worked
    /// while blocking one did not, which is the wrong asymmetry for a firewall.
    deny_dest: HashSet<(IpAddr, Option<u16>)>,
    /// Destinations approved for ONE binary. This is what "Allow connection"
    /// writes when we know which binary asked, so approving a host for one
    /// program does not quietly open it for every other program too.
    allow_host_from: HashSet<(String, String, Option<u16>)>,
    allow_dest_from: HashSet<(String, IpAddr, Option<u16>)>,
    deny_host_from: HashSet<(String, String, Option<u16>)>,
    deny_dest_from: HashSet<(String, IpAddr, Option<u16>)>,
    /// Program used to ask the user. Configurable so that no particular
    /// desktop (or any desktop at all) is a requirement - see prompt_bin().
    prompt: Option<String>,
    /// The hash a binary had when its rules were approved. A rule is a
    /// standing permission attached to a path, and a path is not an identity -
    /// this is what notices the file behind it being swapped.
    app_id: HashMap<String, String>,
    /// Operating mode. Lives in the policy file rather than in argv so it can
    /// be changed at runtime: the daemon re-reads the file within a second, so
    /// a switch takes effect without a restart - and therefore without ever
    /// dropping the divert socket and letting traffic past unfiltered.
    mode: Option<Mode>,
}

impl Policy {
    pub fn load(path: &Path) -> Self {
        let mut p = Policy { default: Some(Verdict::Ask), ..Default::default() };
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(_) => return p, // absent config: ask about everything
        };
        for (n, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut it = line.splitn(2, char::is_whitespace);
            let (k, v) = (it.next().unwrap_or(""), it.next().unwrap_or("").trim());
            match k {
                "default" => {
                    p.default = match v {
                        "allow" => Some(Verdict::Allow),
                        "deny" => Some(Verdict::Deny),
                        "ask" => Some(Verdict::Ask),
                        _ => { eprintln!("policy:{}: bad default {v:?}", n + 1); p.default }
                    }
                }
                "allow-app" => { p.allow_app.insert(v.to_string()); }
                "deny-app" => { p.deny_app.insert(v.to_string()); }
                "allow-host" => { let (h, pt) = split_target(v); p.allow_host.insert((h.to_lowercase(), pt)); }
                "deny-host" => { let (h, pt) = split_target(v); p.deny_host.insert((h.to_lowercase(), pt)); }
                "prompt" => { p.prompt = Some(v.to_string()); }
                // app-id <sha256> <path>. Destination-first for the same reason
                // the scoped rules are: a hash has no spaces, a path might.
                "app-id" => match split_scoped(v) {
                    Some((sha, exe)) => { p.app_id.insert(exe, sha.to_lowercase()); }
                    None => eprintln!("policy:{}: want `app-id <sha256> <binary>`", n + 1),
                },
                "mode" => match Mode::parse(v) {
                    Some(m) => p.mode = Some(m),
                    None => eprintln!("policy:{}: bad mode {v:?}", n + 1),
                },
                "allow-host-from" => match split_scoped(v) {
                    Some((h, e)) => { let (hh, pt) = split_target(&h); p.allow_host_from.insert((e, hh.to_lowercase(), pt)); }
                    None => eprintln!("policy:{}: want `allow-host-from <host> <binary>`", n + 1),
                },
                "allow-dest-from" => match split_scoped(v) {
                    Some((a, e)) => { let (aa, pt) = split_target(&a); match aa.parse::<IpAddr>() {
                        Ok(addr) => { p.allow_dest_from.insert((e, addr, pt)); }
                        Err(_) => eprintln!("policy:{}: bad address {a:?}", n + 1),
                    } }
                    None => eprintln!("policy:{}: want `allow-dest-from <addr> <binary>`", n + 1),
                },
                "deny-host-from" => match split_scoped(v) {
                    Some((h, e)) => { let (hh, pt) = split_target(&h); p.deny_host_from.insert((e, hh.to_lowercase(), pt)); }
                    None => eprintln!("policy:{}: want `deny-host-from <host> <binary>`", n + 1),
                },
                "deny-dest-from" => match split_scoped(v) {
                    Some((a, e)) => { let (aa, pt) = split_target(&a); match aa.parse::<IpAddr>() {
                        Ok(addr) => { p.deny_dest_from.insert((e, addr, pt)); }
                        Err(_) => eprintln!("policy:{}: bad address {a:?}", n + 1),
                    } }
                    None => eprintln!("policy:{}: want `deny-dest-from <addr> <binary>`", n + 1),
                },
                "allow-dest" => {
                    let (a, pt) = split_target(v);
                    match a.parse::<IpAddr>() {
                        Ok(addr) => { p.allow_dest.insert((addr, pt)); }
                        Err(_) => eprintln!("policy:{}: bad address {a:?}", n + 1),
                    }
                }
                "deny-dest" => {
                    let (a, pt) = split_target(v);
                    match a.parse::<IpAddr>() {
                        Ok(addr) => { p.deny_dest.insert((addr, pt)); }
                        Err(_) => eprintln!("policy:{}: bad address {a:?}", n + 1),
                    }
                }
                _ => eprintln!("policy:{}: unknown directive {k:?}", n + 1),
            }
        }
        p
    }

    /// `*.example.com` matches any subdomain, and the bare domain too.
    /// Does one rule pattern cover this host? Shared by the global and the
    /// per-application deny sets so a wildcard means the same thing in both.
    fn pattern_matches(rule: &str, host_lower: &str) -> bool {
        if rule == host_lower {
            return true;
        }
        match rule.strip_prefix("*.") {
            Some(suffix) => host_lower == suffix || host_lower.ends_with(&format!(".{suffix}")),
            None => false,
        }
    }

    /// Does a rule's port constraint admit this destination port?
    ///
    /// A rule with no port means any port. That is what a bare host has always
    /// meant, so every rule written before ports existed keeps its meaning.
    fn port_ok(rule: Option<u16>, dport: u16) -> bool {
        match rule {
            None => true,
            Some(p) => p == dport,
        }
    }

    /// Does any (binary, host-pattern, port) rule cover this exe+host+port?
    fn scoped_host_hit(
        set: &HashSet<(String, String, Option<u16>)>,
        exe: &str,
        host_lower: &str,
        dport: u16,
    ) -> bool {
        set.iter().any(|(e, pat, port)| {
            e == exe && Self::port_ok(*port, dport) && Self::pattern_matches(pat, host_lower)
        })
    }

    fn scoped_dest_hit(
        set: &HashSet<(String, IpAddr, Option<u16>)>,
        exe: &str,
        dst: IpAddr,
        dport: u16,
    ) -> bool {
        set.iter()
            .any(|(e, a, port)| e == exe && *a == dst && Self::port_ok(*port, dport))
    }

    fn host_matches(set: &HashSet<Target>, host: &str, dport: u16) -> bool {
        let h = host.to_lowercase();
        set.iter()
            .any(|(pat, port)| Self::port_ok(*port, dport) && Self::pattern_matches(pat, &h))
    }

    fn dest_matches(set: &HashSet<(IpAddr, Option<u16>)>, dst: IpAddr, dport: u16) -> bool {
        set.iter().any(|(a, port)| *a == dst && Self::port_ok(*port, dport))
    }

    pub fn decide(
        &self,
        exe: Option<&str>,
        dst: IpAddr,
        host: Option<&str>,
        dport: u16,
    ) -> Verdict {
        // Most specific first: a destination denied to THIS binary outranks any
        // broader allow, otherwise approving example.com for one app would
        // silently re-open it for an app you had blocked.
        if let Some(e) = exe {
            if Self::scoped_dest_hit(&self.deny_dest_from, e, dst, dport) {
                return Verdict::Deny;
            }
            if let Some(h) = host {
                if Self::scoped_host_hit(&self.deny_host_from, e, &h.to_lowercase(), dport) {
                    return Verdict::Deny;
                }
            }
        }
        if let Some(h) = host {
            if Self::host_matches(&self.deny_host, h, dport) {
                return Verdict::Deny;
            }
        }
        // Sits with deny-host, not with the allow sets: a machine-wide deny by
        // address has to outrank a per-app approval, or blocking an address
        // would do nothing for any app that had already been approved.
        if Self::dest_matches(&self.deny_dest, dst, dport) {
            return Verdict::Deny;
        }
        if let Some(e) = exe {
            if self.deny_app.contains(e) {
                return Verdict::Deny;
            }
            // Approved for THIS binary. Checked before the global allow sets so
            // that a per-app approval is what actually matches, rather than
            // being shadowed by a broad rule that happens to cover it.
            if Self::scoped_dest_hit(&self.allow_dest_from, e, dst, dport) {
                return Verdict::Allow;
            }
            if let Some(h) = host {
                if Self::scoped_host_hit(&self.allow_host_from, e, &h.to_lowercase(), dport) {
                    return Verdict::Allow;
                }
            }
            if self.allow_app.contains(e) {
                return Verdict::Allow;
            }
        }
        if let Some(h) = host {
            if Self::host_matches(&self.allow_host, h, dport) {
                return Verdict::Allow;
            }
        }
        if Self::dest_matches(&self.allow_dest, dst, dport) {
            return Verdict::Allow;
        }
        self.default.unwrap_or(Verdict::Ask)
    }

    /// Persist a decision. Appends, so hand-written comments and ordering
    /// survive. The originating binary is recorded as a comment: reviewing a
    /// bare address months later tells you nothing about why it is there.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &mut self,
        path: &Path,
        ans: Answer,
        exe: Option<&str>,
        dst: IpAddr,
        host: Option<&str>,
        dport: u16,
        origin: Origin,
    ) {
        let who = exe.unwrap_or("unknown");
        // An approval covers the port it was asked about, not every port on that
        // host. Approving a browser's HTTPS access should not also hand it SSH.
        let port = Some(dport);
        let line = match ans {
            Answer::AllowConn => match (exe, host) {
                // Scope to the binary whenever we know it. Approving a host for
                // one program should not quietly open it for every other
                // program on the machine.
                //
                // Prefer the NAME over the address so one rule covers every
                // address the site answers on, instead of one rule per rotating
                // CDN address.
                (Some(e), Some(h)) if !h.is_empty() && h != "-" => {
                    self.allow_host_from.insert((e.to_string(), h.to_lowercase(), port));
                    format!(
                        "allow-host-from {}\t{e}\t# {} for this app",
                        join_target(h, port),
                        origin.adjective()
                    )
                }
                (Some(e), _) => {
                    self.allow_dest_from.insert((e.to_string(), dst, port));
                    format!(
                        "allow-dest-from {}\t{e}\t# no hostname seen; {} for this app",
                        join_target(&dst.to_string(), port),
                        origin.adjective()
                    )
                }
                // No attribution: the process was gone before we could identify
                // it, so a scoped rule would match nothing at all. Fall back to
                // a machine-wide rule and label it, because it is broader than
                // the user asked for and should be easy to spot on review.
                (None, Some(h)) if !h.is_empty() && h != "-" => {
                    self.allow_host.insert((h.to_lowercase(), port));
                    format!(
                        "allow-host {}\t# {}; unattributed connection",
                        join_target(h, port),
                        origin.adjective()
                    )
                }
                (None, _) => {
                    self.allow_dest.insert((dst, port));
                    format!(
                        "allow-dest {}\t# {}; unattributed, no hostname seen",
                        join_target(&dst.to_string(), port),
                        origin.adjective()
                    )
                }
            },
            Answer::AllowApp => match exe {
                Some(e) => {
                    self.allow_app.insert(e.to_string());
                    format!("allow-app {e}")
                }
                // As above: no binary, no app-wide rule. Logged rather than
                // silently dropped.
                None => {
                    eprintln!(
                        "pfsnitch: 'allow app' ignored - this connection could not be attributed to a binary"
                    );
                    return;
                }
            },
            Answer::Block => match exe {
                // Mirror of AllowConn: prefer the NAME when we saw one, so the
                // block follows the site across rotating addresses instead of
                // pinning one IP the app will stop using tomorrow.
                Some(e) => match host {
                    Some(h) if !h.is_empty() && h != "-" => {
                        self.deny_host_from.insert((e.to_string(), h.to_lowercase(), port));
                        format!(
                            "deny-host-from {}\t{e}\t# blocked for this app only",
                            join_target(h, port)
                        )
                    }
                    _ => {
                        self.deny_dest_from.insert((e.to_string(), dst, port));
                        format!(
                            "deny-dest-from {}\t{e}\t# no hostname seen; blocked for this app only",
                            join_target(&dst.to_string(), port)
                        )
                    }
                },
                // Unattributed. Previously this returned and the click did
                // nothing - the user saw a dialog, pressed Block, and no rule
                // was written. A machine-wide deny is broader than they asked
                // for, so it is labelled, but it is what "block this" can mean
                // when there is no binary to attach it to.
                None => match host {
                    Some(h) if !h.is_empty() && h != "-" => {
                        self.deny_host.insert((h.to_lowercase(), port));
                        format!(
                            "deny-host {}\t# unattributed connection; blocked for every application",
                            join_target(h, port)
                        )
                    }
                    _ => {
                        self.deny_dest.insert((dst, port));
                        format!(
                            "deny-dest {}\t# unattributed, no hostname seen; blocked for every application",
                            join_target(&dst.to_string(), port)
                        )
                    }
                },
            },
            Answer::BlockApp => match exe {
                Some(e) => {
                    self.deny_app.insert(e.to_string());
                    format!("deny-app {e}\t# every destination")
                }
                // An app-wide rule needs an app. Nothing can be written, so say
                // so rather than letting the button appear to work.
                None => {
                    eprintln!(
                        "pfsnitch: 'block app' ignored - this connection could not be attributed to a binary"
                    );
                    return;
                }
            },
            Answer::Timeout => return,
        };
        let _ = who;

        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "{line}");
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "default={:?} allow-app={} deny-app={} allow-host={} allow-dest={}",
            self.default.unwrap_or(Verdict::Ask),
            self.allow_app.len(),
            self.deny_app.len(),
            self.allow_host.len(),
            self.allow_dest.len()
        )
    }
}

// ---------------------------------------------------------------------------
// File-level rule management.
//
// These functions work on the policy FILE rather than on a loaded Policy, and
// that is the whole point: the file is the single source of truth and it is
// plain text, so a shell script, a text editor, a TUI or a web UI can all manage
// rules without linking against this crate or speaking a private protocol.
// The daemon picks changes up by itself (it watches the mtime), so a frontend
// never has to find the daemon, hold a socket, or send a signal.
// ---------------------------------------------------------------------------

/// One rule as it appears in the file, with its trailing comment preserved so a
/// rewrite puts everything back the way the user left it.
#[derive(Debug, Clone)]
pub struct Rule {
    pub kind: String,
    pub value: String,
    pub comment: Option<String>,
}

pub const KINDS: &[&str] =
    &[
        "allow-app",
        "deny-app",
        "allow-host",
        "deny-host",
        "allow-dest",
        "deny-dest",
        "allow-host-from",
        "allow-dest-from",
        "deny-host-from",
        "deny-dest-from",
    ];

fn split_comment(raw: &str) -> (&str, Option<String>) {
    match raw.find('#') {
        Some(i) => (&raw[..i], Some(raw[i + 1..].trim().to_string())),
        None => (raw, None),
    }
}

/// Hosts are case-insensitive and addresses have more than one spelling
/// (2606:0:0::1 and 2606::1 are the same host), so compare canonical forms or
/// "remove" will miss rules that "add" would consider duplicates.
fn normalise(kind: &str, value: &str) -> String {
    match kind {
        "allow-host" | "deny-host" => {
            let (h, p) = split_target(value);
            join_target(&h.to_lowercase(), p)
        }
        "allow-host-from" | "deny-host-from" => match split_scoped(value) {
            Some((h, e)) => {
                let (hh, p) = split_target(&h);
                format!("{} {e}", join_target(&hh.to_lowercase(), p))
            }
            None => value.to_string(),
        },
        "allow-dest-from" | "deny-dest-from" => match split_scoped(value) {
            Some((a, e)) => {
                let (aa, p) = split_target(&a);
                match aa.parse::<IpAddr>() {
                    Ok(addr) => format!("{} {e}", join_target(&addr.to_string(), p)),
                    Err(_) => value.to_string(),
                }
            }
            None => value.to_string(),
        },
        "allow-dest" | "deny-dest" => {
            let (a, p) = split_target(value);
            match a.parse::<IpAddr>() {
                Ok(addr) => join_target(&addr.to_string(), p),
                Err(_) => value.to_string(),
            }
        }
        _ => value.to_string(),
    }
}

fn parse_line(raw: &str) -> Option<(String, String, Option<String>)> {
    let (body, comment) = split_comment(raw);
    let body = body.trim();
    if body.is_empty() {
        return None;
    }
    let mut it = body.splitn(2, char::is_whitespace);
    let k = it.next().unwrap_or("").to_string();
    let v = it.next().unwrap_or("").trim().to_string();
    if v.is_empty() {
        return None;
    }
    Some((k, v, comment))
}

/// Every rule in the file, in file order.
pub fn rules(path: &Path) -> Vec<Rule> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    text.lines()
        .filter_map(parse_line)
        .filter(|(k, _, _)| KINDS.contains(&k.as_str()))
        .map(|(kind, value, comment)| Rule { kind, value, comment })
        .collect()
}

/// Append a rule. Returns false if an equivalent rule is already present -
/// adding twice is a no-op rather than a duplicate, because approvals arrive
/// from prompts and frontends alike and neither should have to check first.
pub fn add_rule(path: &Path, kind: &str, value: &str, note: Option<&str>) -> io::Result<bool> {
    if !KINDS.contains(&kind) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown rule type {kind:?} (want one of {})", KINDS.join(", ")),
        ));
    }
    if matches!(kind, "allow-host-from" | "allow-dest-from" | "deny-host-from" | "deny-dest-from") {
        match split_scoped(value) {
            Some((d, _)) if kind.ends_with("dest-from") && split_target(&d).0.parse::<IpAddr>().is_err() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{d:?} is not an IP address - use the -host-from form for names"),
                ));
            }
            Some(_) => {}
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{kind} needs `<destination> <binary>`"),
                ));
            }
        }
    }
    if (kind == "allow-dest" || kind == "deny-dest")
        && split_target(value).0.parse::<IpAddr>().is_err()
    {
        let alt = if kind == "deny-dest" { "deny-host" } else { "allow-host" };
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{value:?} is not an IP address - use {alt} for names"),
        ));
    }
    let norm = normalise(kind, value);
    if rules(path)
        .iter()
        .any(|r| r.kind == kind && normalise(&r.kind, &r.value) == norm)
    {
        return Ok(false);
    }
    let mut f = fs::OpenOptions::new().create(true).append(true).open(path)?;
    match note {
        Some(n) => writeln!(f, "{kind} {norm}\t# {n}")?,
        None => writeln!(f, "{kind} {norm}")?,
    }
    Ok(true)
}

/// Drop every rule matching kind+value. Returns how many lines went.
///
/// Rewrites the file rather than editing in place, keeping comments, blank lines
/// and unrelated rules exactly as they were: this file is meant to stay
/// hand-editable, so the tool must not reformat what it did not change.
pub fn remove_rule(path: &Path, kind: &str, value: &str) -> io::Result<usize> {
    let text = fs::read_to_string(path)?;
    let want = normalise(kind, value);
    let mut kept = String::new();
    let mut removed = 0usize;
    for raw in text.lines() {
        let hit = match parse_line(raw) {
            Some((k, v, _)) => k == kind && normalise(&k, &v) == want,
            None => false,
        };
        if hit {
            removed += 1;
            continue;
        }
        kept.push_str(raw);
        kept.push('\n');
    }
    if removed > 0 {
        write_atomic(path, &kept)?;
    }
    Ok(removed)
}

/// Write via a temp file and rename, so an interrupted write can never leave a
/// truncated policy - which would silently drop every rule the user has.
fn write_atomic(path: &Path, data: &str) -> io::Result<()> {
    let tmp = path.with_extension("conf.tmp");
    fs::write(&tmp, data)?;
    fs::rename(&tmp, path)
}

/// Modification time, used by the daemon to notice edits from any source.
pub fn mtime(path: &Path) -> Option<std::time::SystemTime> {
    fs::metadata(path).ok()?.modified().ok()
}

impl Policy {
    /// Which program to ask the user with.
    ///
    /// Precedence: environment, then a `prompt` directive in the policy file,
    /// then the built-in default. The environment wins so a frontend can launch
    /// the daemon with its own prompt without editing config, and the directive
    /// exists so a headless box can point at a tty prompt permanently.
    pub fn prompt_bin(&self, default: &str) -> String {
        if let Ok(p) = std::env::var("PFSNITCH_PROMPT") {
            if !p.is_empty() {
                return p;
            }
        }
        self.prompt.clone().unwrap_or_else(|| default.to_string())
    }
}

/// What the daemon does with a verdict.
///
/// `Visibility` decides and logs but reinjects every packet, so it is safe to
/// run while you build up a rule set. `Enforcement` actually drops what is not
/// approved. The distinction is deliberately not a boolean anywhere it is
/// stored or printed: "enforce=false" reads like a disabled firewall rather
/// than an observing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Visibility,
    Enforcement,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        match s.trim().to_lowercase().as_str() {
            // The former names stay accepted forever: an rc.conf, a script or a
            // policy file written before the rename must not break on upgrade.
            "visibility" | "listen" | "observe" => Some(Mode::Visibility),
            "enforcement" | "enforce" => Some(Mode::Enforcement),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Visibility => "visibility",
            Mode::Enforcement => "enforcement",
        }
    }

    pub fn enforcing(self) -> bool {
        matches!(self, Mode::Enforcement)
    }
}

impl Policy {
    /// The mode to run in: the policy file wins, falling back to whatever the
    /// daemon was started with.
    pub fn mode(&self, fallback: Mode) -> Mode {
        self.mode.unwrap_or(fallback)
    }
}

/// Write the mode into the policy file, replacing any existing setting.
///
/// Rewrites rather than appends so repeated toggling cannot leave a stack of
/// stale `mode` lines, where the last one silently wins and the file no longer
/// says what it does.
pub fn set_mode(path: &Path, mode: Mode) -> io::Result<()> {
    let text = fs::read_to_string(path).unwrap_or_default();
    let mut out = String::new();
    let mut written = false;
    for raw in text.lines() {
        let is_mode = matches!(parse_line(raw), Some((ref k, _, _)) if k == "mode");
        if is_mode {
            if !written {
                out.push_str(&format!("mode {}\n", mode.as_str()));
                written = true;
            }
            continue;
        }
        out.push_str(raw);
        out.push('\n');
    }
    if !written {
        out.push_str(&format!("mode {}\n", mode.as_str()));
    }
    write_atomic(path, &out)
}

/// Where a recorded rule came from.
///
/// Kept in the file's comment because the distinction matters when reviewing a
/// policy later: "approved" means a human looked at a dialog and chose, while
/// "learned" means visibility mode inferred it from traffic that happened to
/// occur. They deserve different amounts of trust.
#[derive(Debug, Clone, Copy)]
pub enum Origin {
    Approved,
    Learned,
}

impl Origin {
    fn adjective(self) -> &'static str {
        match self {
            Origin::Approved => "approved",
            Origin::Learned => "learned",
        }
    }

    fn verb(self) -> &'static str {
        match self {
            Origin::Approved => "approved for",
            Origin::Learned => "learned from",
        }
    }
}

/// Split a scoped rule value into (destination, binary).
///
/// The destination comes first because it can never contain whitespace, while
/// an executable path can - so splitting on the first space is unambiguous in
/// that order and would not be in the other.
fn split_scoped(v: &str) -> Option<(String, String)> {
    let mut it = v.splitn(2, char::is_whitespace);
    let dest = it.next()?.trim().to_string();
    let exe = it.next()?.trim().to_string();
    if dest.is_empty() || exe.is_empty() {
        return None;
    }
    Some((dest, exe))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_from(name: &str, body: &str) -> (Policy, std::path::PathBuf) {
        let p = std::env::temp_dir().join(format!("pfsnitch-test-{name}.conf"));
        fs::write(&p, body).expect("write test policy");
        (Policy::load(&p), p)
    }

    const APP: &str = "/usr/local/bin/someapp";
    const OTHER: &str = "/usr/local/bin/otherapp";

    #[test]
    fn deny_dest_is_a_listed_kind() {
        // Not cosmetic: `rules`, `status` and `rm` all enumerate KINDS, so a
        // kind missing from it is invisible and unremovable from the CLI.
        assert!(KINDS.contains(&"deny-dest"));
    }

    #[test]
    fn deny_dest_blocks_every_application() {
        let (pol, path) = load_from("deny-dest", "default allow\ndeny-dest 203.0.113.9\n");
        let dst = "203.0.113.9".parse::<IpAddr>().unwrap();
        assert_eq!(pol.decide(Some(APP), dst, None, 443), Verdict::Deny);
        assert_eq!(pol.decide(Some(OTHER), dst, None, 443), Verdict::Deny);
        assert_eq!(pol.decide(None, dst, None, 443), Verdict::Deny);
        let elsewhere = "198.51.100.7".parse::<IpAddr>().unwrap();
        assert_eq!(pol.decide(Some(APP), elsewhere, None, 443), Verdict::Allow);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn deny_dest_outranks_a_per_app_allow() {
        // Same reasoning as deny-host: if an existing approval could shadow it,
        // blocking an address would do nothing for the apps already trusted -
        // which are exactly the ones worth blocking it for.
        let (pol, path) = load_from(
            "deny-dest-prec",
            "default ask\nallow-app /usr/local/bin/someapp\ndeny-dest 203.0.113.9\n",
        );
        let dst = "203.0.113.9".parse::<IpAddr>().unwrap();
        assert_eq!(pol.decide(Some(APP), dst, None, 443), Verdict::Deny);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn deny_dest_honours_its_port_scope() {
        let (pol, path) = load_from("deny-dest-port", "default allow\ndeny-dest 203.0.113.9:443\n");
        let dst = "203.0.113.9".parse::<IpAddr>().unwrap();
        assert_eq!(pol.decide(Some(APP), dst, None, 443), Verdict::Deny);
        assert_eq!(
            pol.decide(Some(APP), dst, None, 80),
            Verdict::Allow,
            "a port-scoped deny must not close other ports"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn blocking_an_unattributed_connection_actually_writes_a_rule() {
        // The regression this fixes: with no binary to scope to, `record`
        // returned early. The dialog appeared, Block was pressed, and nothing
        // was written - while pressing Allow on that same dialog DID write a
        // global rule. Allow-but-never-block is the wrong way for a firewall
        // to be asymmetric.
        let (mut pol, path) = load_from("unattr-block", "default ask\n");
        let dst = "203.0.113.9".parse::<IpAddr>().unwrap();
        pol.record(&path, Answer::Block, None, dst, None, 443, Origin::Approved);

        assert_eq!(pol.decide(None, dst, None, 443), Verdict::Deny);
        assert_eq!(
            pol.decide(Some(APP), dst, None, 443),
            Verdict::Deny,
            "a machine-wide block has to cover attributed traffic too"
        );
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("deny-dest 203.0.113.9:443"), "got: {text}");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn blocking_an_unattributed_connection_prefers_the_hostname() {
        // A name outlives any single address, so the block follows the site
        // rather than pinning one rotating CDN address.
        let (mut pol, path) = load_from("unattr-block-host", "default ask\n");
        let dst = "203.0.113.9".parse::<IpAddr>().unwrap();
        pol.record(&path, Answer::Block, None, dst, Some("metrics.example.com"), 443, Origin::Approved);

        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("deny-host metrics.example.com:443"), "got: {text}");
        let moved = "198.51.100.7".parse::<IpAddr>().unwrap();
        assert_eq!(
            pol.decide(None, moved, Some("metrics.example.com"), 443),
            Verdict::Deny,
            "the block must follow the name to a new address"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn an_app_wide_answer_without_a_binary_writes_nothing() {
        // There is genuinely no app to attach these to. What matters is that
        // they do not quietly widen into something machine-wide instead.
        let (mut pol, path) = load_from("unattr-appwide", "default ask\n");
        let dst = "203.0.113.9".parse::<IpAddr>().unwrap();
        pol.record(&path, Answer::AllowApp, None, dst, None, 443, Origin::Approved);
        pol.record(&path, Answer::BlockApp, None, dst, None, 443, Origin::Approved);

        assert_eq!(fs::read_to_string(&path).unwrap(), "default ask\n");
        assert_eq!(pol.decide(None, dst, None, 443), Verdict::Ask);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn blocking_one_destination_leaves_the_app_otherwise_working() {
        let (pol, path) = load_from(
            "scoped",
            "default allow\ndeny-host-from metrics.example.com /usr/local/bin/someapp\n",
        );
        let dst = "203.0.113.9".parse::<IpAddr>().unwrap();
        assert_eq!(
            pol.decide(Some(APP), dst, Some("metrics.example.com"), 443),
            Verdict::Deny,
            "the blocked endpoint must be denied to this app"
        );
        assert_eq!(
            pol.decide(Some(APP), dst, Some("api.example.com"), 443),
            Verdict::Allow,
            "the app must keep working everywhere else - the whole point"
        );
        assert_eq!(
            pol.decide(Some(OTHER), dst, Some("metrics.example.com"), 443),
            Verdict::Allow,
            "the block is scoped to one binary, not the host globally"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn a_scoped_deny_outranks_a_broader_allow() {
        // Exactly the collision that matters: some other prompt approved the
        // host globally, but this app was told no.
        let (pol, path) = load_from(
            "precedence",
            "default ask\nallow-host metrics.example.com\ndeny-host-from metrics.example.com /usr/local/bin/someapp\n",
        );
        let dst = "203.0.113.9".parse::<IpAddr>().unwrap();
        assert_eq!(
            pol.decide(Some(APP), dst, Some("metrics.example.com"), 443),
            Verdict::Deny,
            "specific beats general, or the block silently evaporates"
        );
        assert_eq!(
            pol.decide(Some(OTHER), dst, Some("metrics.example.com"), 443),
            Verdict::Allow
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn scoped_deny_also_outranks_allow_app_for_that_destination() {
        let (pol, path) = load_from(
            "vsallowapp",
            "default ask\nallow-app /usr/local/bin/someapp\ndeny-host-from metrics.example.com /usr/local/bin/someapp\n",
        );
        let dst = "203.0.113.9".parse::<IpAddr>().unwrap();
        assert_eq!(
            pol.decide(Some(APP), dst, Some("metrics.example.com"), 443),
            Verdict::Deny,
            "approving an app wholesale must not resurrect a destination you blocked"
        );
        assert_eq!(pol.decide(Some(APP), dst, Some("cdn.example.com"), 443), Verdict::Allow);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn scoped_deny_by_bare_address_when_no_hostname_was_seen() {
        let (pol, path) = load_from(
            "byaddr",
            "default allow\ndeny-dest-from 203.0.113.9 /usr/local/bin/someapp\n",
        );
        let blocked = "203.0.113.9".parse::<IpAddr>().unwrap();
        let other = "203.0.113.10".parse::<IpAddr>().unwrap();
        assert_eq!(pol.decide(Some(APP), blocked, None, 443), Verdict::Deny);
        assert_eq!(pol.decide(Some(APP), other, None, 443), Verdict::Allow);
        assert_eq!(pol.decide(Some(OTHER), blocked, None, 443), Verdict::Allow);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn wildcards_work_in_scoped_rules_too() {
        let (pol, path) = load_from(
            "wildcard",
            "default allow\ndeny-host-from *.telemetry.example.com /usr/local/bin/someapp\n",
        );
        let dst = "203.0.113.9".parse::<IpAddr>().unwrap();
        assert_eq!(pol.decide(Some(APP), dst, Some("eu.telemetry.example.com"), 443), Verdict::Deny);
        assert_eq!(pol.decide(Some(APP), dst, Some("telemetry.example.com"), 443), Verdict::Deny);
        assert_eq!(pol.decide(Some(APP), dst, Some("example.com"), 443), Verdict::Allow);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn an_executable_path_containing_spaces_still_parses() {
        // The destination is first precisely so this works: it can never
        // contain whitespace, and the rest of the line is the path.
        let (pol, path) = load_from(
            "spacey",
            "default allow\ndeny-host-from metrics.example.com /opt/My App/bin/app\n",
        );
        let dst = "203.0.113.9".parse::<IpAddr>().unwrap();
        assert_eq!(
            pol.decide(Some("/opt/My App/bin/app"), dst, Some("metrics.example.com"), 443),
            Verdict::Deny
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn a_port_scoped_rule_does_not_open_other_ports() {
        // The gap this whole feature exists to close: approving HTTPS to a host
        // must not also hand the app SSH to it.
        let (pol, path) = load_from(
            "portscope",
            "default ask\nallow-host-from example.com:443 /usr/local/bin/someapp\n",
        );
        let dst = "203.0.113.9".parse::<IpAddr>().unwrap();
        assert_eq!(pol.decide(Some(APP), dst, Some("example.com"), 443), Verdict::Allow);
        assert_eq!(
            pol.decide(Some(APP), dst, Some("example.com"), 22),
            Verdict::Ask,
            "a different port on the same host is a different decision"
        );
        assert_eq!(pol.decide(Some(APP), dst, Some("example.com"), 80), Verdict::Ask);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn a_rule_without_a_port_still_means_any_port() {
        // Every rule written before ports existed must keep its meaning.
        let (pol, path) = load_from(
            "portless",
            "default ask\nallow-host-from example.com /usr/local/bin/someapp\n",
        );
        let dst = "203.0.113.9".parse::<IpAddr>().unwrap();
        for p in [22u16, 80, 443, 8080] {
            assert_eq!(
                pol.decide(Some(APP), dst, Some("example.com"), p),
                Verdict::Allow,
                "bare host rule should still cover port {p}"
            );
        }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn a_port_scoped_deny_only_blocks_that_port() {
        let (pol, path) = load_from(
            "denyport",
            "default allow\ndeny-host-from example.com:443 /usr/local/bin/someapp\n",
        );
        let dst = "203.0.113.9".parse::<IpAddr>().unwrap();
        assert_eq!(pol.decide(Some(APP), dst, Some("example.com"), 443), Verdict::Deny);
        assert_eq!(pol.decide(Some(APP), dst, Some("example.com"), 80), Verdict::Allow);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn ipv6_literal_with_a_port_is_parsed_and_matched() {
        let (pol, path) = load_from(
            "v6port",
            "default ask\nallow-dest-from [2606:4700:4700::1111]:853 /usr/local/bin/someapp\n",
        );
        let v6 = "2606:4700:4700::1111".parse::<IpAddr>().unwrap();
        assert_eq!(pol.decide(Some(APP), v6, None, 853), Verdict::Allow);
        assert_eq!(pol.decide(Some(APP), v6, None, 443), Verdict::Ask);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn approving_a_host_for_one_app_does_not_open_it_for_others() {
        // The reason scoped allows exist at all.
        let (pol, path) = load_from(
            "scopedallow",
            "default ask\nallow-host-from api.example.com /usr/local/bin/someapp\n",
        );
        let dst = "203.0.113.9".parse::<IpAddr>().unwrap();
        assert_eq!(pol.decide(Some(APP), dst, Some("api.example.com"), 443), Verdict::Allow);
        assert_eq!(
            pol.decide(Some(OTHER), dst, Some("api.example.com"), 443),
            Verdict::Ask,
            "a different binary must still be asked about the same host"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn a_scoped_deny_still_beats_a_scoped_allow_for_another_app() {
        let (pol, path) = load_from(
            "mixedscope",
            "default ask\nallow-host-from api.example.com /usr/local/bin/someapp\ndeny-host-from api.example.com /usr/local/bin/otherapp\n",
        );
        let dst = "203.0.113.9".parse::<IpAddr>().unwrap();
        assert_eq!(pol.decide(Some(APP), dst, Some("api.example.com"), 443), Verdict::Allow);
        assert_eq!(pol.decide(Some(OTHER), dst, Some("api.example.com"), 443), Verdict::Deny);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn a_scoped_deny_beats_a_scoped_allow_for_the_same_app() {
        // Contradictory rules should resolve the safe way round.
        let (pol, path) = load_from(
            "contradiction",
            "default ask\nallow-host-from api.example.com /usr/local/bin/someapp\ndeny-host-from api.example.com /usr/local/bin/someapp\n",
        );
        let dst = "203.0.113.9".parse::<IpAddr>().unwrap();
        assert_eq!(
            pol.decide(Some(APP), dst, Some("api.example.com"), 443),
            Verdict::Deny,
            "deny must win when both are present, never allow"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn a_global_allow_host_still_covers_every_binary() {
        // Infrastructure rules (DNS, a gateway) are deliberately machine-wide.
        let (pol, path) = load_from(
            "globalallow",
            "default ask\nallow-host dns.example.com\n",
        );
        let dst = "203.0.113.9".parse::<IpAddr>().unwrap();
        assert_eq!(pol.decide(Some(APP), dst, Some("dns.example.com"), 443), Verdict::Allow);
        assert_eq!(pol.decide(Some(OTHER), dst, Some("dns.example.com"), 443), Verdict::Allow);
        assert_eq!(pol.decide(None, dst, Some("dns.example.com"), 443), Verdict::Allow);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn a_scoped_allow_cannot_match_an_unattributed_connection() {
        // Documents the real cost of scoping: with no binary to match against,
        // a per-app rule cannot apply, so we fall through rather than guess.
        let (pol, path) = load_from(
            "unattributed",
            "default ask\nallow-host-from api.example.com /usr/local/bin/someapp\n",
        );
        let dst = "203.0.113.9".parse::<IpAddr>().unwrap();
        assert_eq!(
            pol.decide(None, dst, Some("api.example.com"), 443),
            Verdict::Ask,
            "fail closed: an unidentified process gets no benefit from another app rule"
        );
        let _ = fs::remove_file(path);
    }
}

/// A destination as written in a rule: a name or address, and an optional port.
///
/// `None` for the port means "any port", which is what a bare host means and
/// what every rule written before ports existed still means.
pub type Target = (String, Option<u16>);

/// Split "host", "host:port", or "[v6addr]:port" into its parts.
///
/// IPv6 is why this is not a one-line split: an address is full of colons, so a
/// bare `2606:4700::1111` must not be read as host `2606` port nothing-sensible.
/// The rule is the same one URLs use - brackets when you want a port with a v6
/// literal - and anything that parses as a bare address is taken whole.
pub fn split_target(s: &str) -> Target {
    let s = s.trim();

    // [2606:4700::1111]:443  or  [2606:4700::1111]
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(close) = rest.find(']') {
            let host = &rest[..close];
            let after = &rest[close + 1..];
            let port = after.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
            return (host.to_string(), port);
        }
    }

    // A bare IPv6 literal has more than one colon and no brackets: take it whole.
    if s.parse::<std::net::Ipv6Addr>().is_ok() {
        return (s.to_string(), None);
    }

    // host:port, but only if what follows the LAST colon is really a port.
    if let Some(i) = s.rfind(':') {
        if let Ok(p) = s[i + 1..].parse::<u16>() {
            // Guard against a v6 address we failed to parse above.
            if s[..i].matches(':').count() == 0 {
                return (s[..i].to_string(), Some(p));
            }
        }
    }

    (s.to_string(), None)
}

/// Render a target back the way a rule file spells it.
pub fn join_target(host: &str, port: Option<u16>) -> String {
    match port {
        None => host.to_string(),
        Some(p) if host.parse::<std::net::Ipv6Addr>().is_ok() => format!("[{host}]:{p}"),
        Some(p) => format!("{host}:{p}"),
    }
}

#[cfg(test)]
mod target_tests {
    use super::*;

    #[test]
    fn plain_hostname_means_any_port() {
        assert_eq!(split_target("example.com"), ("example.com".into(), None));
    }

    #[test]
    fn hostname_with_port() {
        assert_eq!(split_target("example.com:443"), ("example.com".into(), Some(443)));
    }

    #[test]
    fn bare_ipv6_is_not_mistaken_for_a_port() {
        // The whole reason this needs care: 1111 is not a port here.
        assert_eq!(
            split_target("2606:4700:4700::1111"),
            ("2606:4700:4700::1111".into(), None)
        );
    }

    #[test]
    fn bracketed_ipv6_with_port() {
        assert_eq!(
            split_target("[2606:4700:4700::1111]:853"),
            ("2606:4700:4700::1111".into(), Some(853))
        );
    }

    #[test]
    fn bracketed_ipv6_without_port() {
        assert_eq!(
            split_target("[2606:4700:4700::1111]"),
            ("2606:4700:4700::1111".into(), None)
        );
    }

    #[test]
    fn ipv4_with_and_without_port() {
        assert_eq!(split_target("1.1.1.1"), ("1.1.1.1".into(), None));
        assert_eq!(split_target("1.1.1.1:53"), ("1.1.1.1".into(), Some(53)));
    }

    #[test]
    fn a_port_that_is_not_a_number_stays_part_of_the_name() {
        // "example.com:https" is not something we accept as a port, and quietly
        // dropping the suffix would silently widen the rule.
        assert_eq!(split_target("example.com:https"), ("example.com:https".into(), None));
    }

    #[test]
    fn round_trips() {
        for s in ["example.com", "example.com:443", "1.1.1.1:53", "[2606:4700::1111]:853"] {
            let (h, p) = split_target(s);
            assert_eq!(join_target(&h, p), s, "round trip failed for {s}");
        }
    }
}

impl Policy {
    /// The hash this binary had when its rules were approved, if we recorded one.
    pub fn expected_id(&self, exe: &str) -> Option<&str> {
        self.app_id.get(exe).map(|s| s.as_str())
    }

    /// Remember what a binary looked like at the moment it was approved.
    ///
    /// Only ever recorded on an explicit approval, never on a learned rule:
    /// visibility mode records what happened, and pinning an identity to
    /// traffic nobody looked at would give the pin a weight it has not earned.
    pub fn record_id(&mut self, path: &Path, exe: &str, sha: &str) {
        if self.app_id.contains_key(exe) {
            return;
        }
        self.app_id.insert(exe.to_string(), sha.to_lowercase());
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "app-id {sha}\t{exe}\t# identity when approved");
        }
    }

    /// Forget a binary's recorded identity, so the next approval re-pins it.
    pub fn forget_id(&mut self, exe: &str) {
        self.app_id.remove(exe);
    }
}

/// Remove every rule belonging to one binary, and its pinned identity.
///
/// Returns how many lines went. Takes a backup first: this is the one operation
/// that can destroy a lot of decisions at once, and a rule set is not something
/// a user can reconstruct from memory.
pub fn remove_app(path: &Path, exe: &str) -> io::Result<(usize, String)> {
    let text = fs::read_to_string(path)?;

    let backup = format!("{}.bak", path.display());
    fs::write(&backup, &text)?;

    let mut kept = String::new();
    let mut removed = 0usize;
    for raw in text.lines() {
        let hit = match parse_line(raw) {
            Some((k, v, _)) => match k.as_str() {
                // The whole value is the binary.
                "allow-app" | "deny-app" => v == exe,
                // "<hash> <binary>" and "<destination> <binary>".
                "app-id"
                | "allow-host-from"
                | "deny-host-from"
                | "allow-dest-from"
                | "deny-dest-from" => split_scoped(&v).map(|(_, e)| e == exe).unwrap_or(false),
                _ => false,
            },
            None => false,
        };
        if hit {
            removed += 1;
            continue;
        }
        kept.push_str(raw);
        kept.push('\n');
    }
    if removed > 0 {
        write_atomic(path, &kept)?;
    }
    Ok((removed, backup))
}

/// Remove every rule, keeping the settings that are not rules.
///
/// `default`, `mode` and `prompt` survive: they describe how pfsnitch behaves,
/// not what it permits, and silently resetting the mode while clearing a rule
/// set would be a nasty surprise. Comments survive too, so a hand-annotated
/// policy keeps its annotations.
///
/// Takes a backup. This is the single most destructive thing the tool can do.
pub fn clear_rules(path: &Path) -> io::Result<(usize, String)> {
    let text = fs::read_to_string(path)?;
    let backup = format!("{}.bak", path.display());
    fs::write(&backup, &text)?;

    let mut kept = String::new();
    let mut removed = 0usize;
    for raw in text.lines() {
        let is_rule = match parse_line(raw) {
            Some((k, _, _)) => KINDS.contains(&k.as_str()) || k == "app-id",
            None => false,
        };
        if is_rule {
            removed += 1;
            continue;
        }
        kept.push_str(raw);
        kept.push('\n');
    }
    if removed > 0 {
        write_atomic(path, &kept)?;
    }
    Ok((removed, backup))
}
