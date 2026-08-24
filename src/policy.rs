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

use std::collections::HashSet;
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
    allow_host: HashSet<String>,
    deny_host: HashSet<String>,
    allow_dest: HashSet<IpAddr>,
    /// Destinations denied to ONE binary, leaving it otherwise working.
    /// This is what "Block" produces: blocking a metrics endpoint should not
    /// take the whole application off the network.
    /// Destinations approved for ONE binary. This is what "Allow connection"
    /// writes when we know which binary asked, so approving a host for one
    /// program does not quietly open it for every other program too.
    allow_host_from: HashSet<(String, String)>,
    allow_dest_from: HashSet<(String, IpAddr)>,
    deny_host_from: HashSet<(String, String)>,
    deny_dest_from: HashSet<(String, IpAddr)>,
    /// Program used to ask the user. Configurable so that no particular
    /// desktop (or any desktop at all) is a requirement - see prompt_bin().
    prompt: Option<String>,
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
                "allow-host" => { p.allow_host.insert(v.to_lowercase()); }
                "deny-host" => { p.deny_host.insert(v.to_lowercase()); }
                "prompt" => { p.prompt = Some(v.to_string()); }
                "mode" => match Mode::parse(v) {
                    Some(m) => p.mode = Some(m),
                    None => eprintln!("policy:{}: bad mode {v:?}", n + 1),
                },
                "allow-host-from" => match split_scoped(v) {
                    Some((h, e)) => { p.allow_host_from.insert((e, h.to_lowercase())); }
                    None => eprintln!("policy:{}: want `allow-host-from <host> <binary>`", n + 1),
                },
                "allow-dest-from" => match split_scoped(v) {
                    Some((a, e)) => match a.parse::<IpAddr>() {
                        Ok(addr) => { p.allow_dest_from.insert((e, addr)); }
                        Err(_) => eprintln!("policy:{}: bad address {a:?}", n + 1),
                    },
                    None => eprintln!("policy:{}: want `allow-dest-from <addr> <binary>`", n + 1),
                },
                "deny-host-from" => match split_scoped(v) {
                    Some((h, e)) => { p.deny_host_from.insert((e, h.to_lowercase())); }
                    None => eprintln!("policy:{}: want `deny-host-from <host> <binary>`", n + 1),
                },
                "deny-dest-from" => match split_scoped(v) {
                    Some((a, e)) => match a.parse::<IpAddr>() {
                        Ok(addr) => { p.deny_dest_from.insert((e, addr)); }
                        Err(_) => eprintln!("policy:{}: bad address {a:?}", n + 1),
                    },
                    None => eprintln!("policy:{}: want `deny-dest-from <addr> <binary>`", n + 1),
                },
                "allow-dest" => match v.parse::<IpAddr>() {
                    Ok(a) => { p.allow_dest.insert(a); }
                    Err(_) => eprintln!("policy:{}: bad address {v:?}", n + 1),
                },
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

    /// Does any (binary, host-pattern) pair in this set cover exe+host?
    fn scoped_host_hit(set: &HashSet<(String, String)>, exe: &str, host_lower: &str) -> bool {
        set.iter().any(|(e, pat)| e == exe && Self::pattern_matches(pat, host_lower))
    }

    fn host_matches(set: &HashSet<String>, host: &str) -> bool {
        let h = host.to_lowercase();
        set.contains(&h) || set.iter().any(|rule| Self::pattern_matches(rule, &h))
    }

    /// Decide. Denials win over approvals: an explicitly blocked binary is not
    /// rescued by some other application having opened up the destination.
    pub fn decide(&self, exe: Option<&str>, dst: IpAddr, host: Option<&str>) -> Verdict {
        // Most specific first: a destination denied to THIS binary outranks any
        // broader allow, otherwise approving example.com for one app would
        // silently re-open it for an app you had blocked.
        if let Some(e) = exe {
            if self.deny_dest_from.contains(&(e.to_string(), dst)) {
                return Verdict::Deny;
            }
            if let Some(h) = host {
                if Self::scoped_host_hit(&self.deny_host_from, e, &h.to_lowercase()) {
                    return Verdict::Deny;
                }
            }
        }
        if let Some(h) = host {
            if Self::host_matches(&self.deny_host, h) {
                return Verdict::Deny;
            }
        }
        if let Some(e) = exe {
            if self.deny_app.contains(e) {
                return Verdict::Deny;
            }
            // Approved for THIS binary. Checked before the global allow sets so
            // that a per-app approval is what actually matches, rather than
            // being shadowed by a broad rule that happens to cover it.
            if self.allow_dest_from.contains(&(e.to_string(), dst)) {
                return Verdict::Allow;
            }
            if let Some(h) = host {
                if Self::scoped_host_hit(&self.allow_host_from, e, &h.to_lowercase()) {
                    return Verdict::Allow;
                }
            }
            if self.allow_app.contains(e) {
                return Verdict::Allow;
            }
        }
        if let Some(h) = host {
            if Self::host_matches(&self.allow_host, h) {
                return Verdict::Allow;
            }
        }
        if self.allow_dest.contains(&dst) {
            return Verdict::Allow;
        }
        self.default.unwrap_or(Verdict::Ask)
    }

    /// Persist a decision. Appends, so hand-written comments and ordering
    /// survive. The originating binary is recorded as a comment: reviewing a
    /// bare address months later tells you nothing about why it is there.
    pub fn record(
        &mut self,
        path: &Path,
        ans: Answer,
        exe: Option<&str>,
        dst: IpAddr,
        host: Option<&str>,
        origin: Origin,
    ) {
        let who = exe.unwrap_or("unknown");
        let line = match ans {
            Answer::AllowConn => match (exe, host) {
                // Scope to the binary whenever we know it. Approving a host for
                // one program should not quietly open it for every other
                // program on the machine - that is the whole difference between
                // "this app may talk to it" and "this machine may talk to it".
                //
                // Prefer the NAME over the address so one rule covers every
                // address the site answers on, instead of one rule per rotating
                // CDN address.
                (Some(e), Some(h)) if !h.is_empty() && h != "-" => {
                    self.allow_host_from.insert((e.to_string(), h.to_lowercase()));
                    format!("allow-host-from {h}\t{e}\t# {} for this app", origin.adjective())
                }
                (Some(e), _) => {
                    self.allow_dest_from.insert((e.to_string(), dst));
                    format!(
                        "allow-dest-from {dst}\t{e}\t# no hostname seen; {} for this app",
                        origin.adjective()
                    )
                }
                // No attribution: the process was gone before we could identify
                // it, so a scoped rule would match nothing at all. Fall back to
                // a machine-wide rule and label it, because it is broader than
                // the user asked for and should be easy to spot on review.
                (None, Some(h)) if !h.is_empty() && h != "-" => {
                    self.allow_host.insert(h.to_lowercase());
                    format!("allow-host {h}\t# {}; unattributed connection", origin.adjective())
                }
                (None, _) => {
                    self.allow_dest.insert(dst);
                    format!(
                        "allow-dest {dst}\t# {}; unattributed, no hostname seen",
                        origin.adjective()
                    )
                }
            },
            Answer::AllowApp => match exe {
                Some(e) => {
                    self.allow_app.insert(e.to_string());
                    format!("allow-app {e}")
                }
                None => return,
            },
            Answer::Block => match exe {
                // Mirror of AllowConn: prefer the NAME when we saw one, so the
                // block follows the site across rotating addresses instead of
                // pinning one IP the app will stop using tomorrow.
                Some(e) => match host {
                    Some(h) if !h.is_empty() && h != "-" => {
                        self.deny_host_from.insert((e.to_string(), h.to_lowercase()));
                        format!("deny-host-from {h}\t{e}\t# blocked for this app only")
                    }
                    _ => {
                        self.deny_dest_from.insert((e.to_string(), dst));
                        format!("deny-dest-from {dst}\t{e}\t# no hostname seen; blocked for this app only")
                    }
                },
                None => return,
            },
            Answer::BlockApp => match exe {
                Some(e) => {
                    self.deny_app.insert(e.to_string());
                    format!("deny-app {e}\t# every destination")
                }
                None => return,
            },
            Answer::Timeout => return,
        };

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
        "allow-host" | "deny-host" => value.to_lowercase(),
        "allow-host-from" | "deny-host-from" => match split_scoped(value) {
            Some((h, e)) => format!("{} {e}", h.to_lowercase()),
            None => value.to_string(),
        },
        "allow-dest-from" | "deny-dest-from" => match split_scoped(value) {
            Some((a, e)) => match a.parse::<IpAddr>() {
                Ok(addr) => format!("{addr} {e}"),
                Err(_) => value.to_string(),
            },
            None => value.to_string(),
        },
        "allow-dest" => value
            .parse::<IpAddr>()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| value.to_string()),
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
            Some((d, _)) if kind.ends_with("dest-from") && d.parse::<IpAddr>().is_err() => {
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
    if kind == "allow-dest" && value.parse::<IpAddr>().is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{value:?} is not an IP address - use allow-host for names"),
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
    fn blocking_one_destination_leaves_the_app_otherwise_working() {
        let (pol, path) = load_from(
            "scoped",
            "default allow\ndeny-host-from metrics.example.com /usr/local/bin/someapp\n",
        );
        let dst = "203.0.113.9".parse::<IpAddr>().unwrap();
        assert_eq!(
            pol.decide(Some(APP), dst, Some("metrics.example.com")),
            Verdict::Deny,
            "the blocked endpoint must be denied to this app"
        );
        assert_eq!(
            pol.decide(Some(APP), dst, Some("api.example.com")),
            Verdict::Allow,
            "the app must keep working everywhere else - the whole point"
        );
        assert_eq!(
            pol.decide(Some(OTHER), dst, Some("metrics.example.com")),
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
            pol.decide(Some(APP), dst, Some("metrics.example.com")),
            Verdict::Deny,
            "specific beats general, or the block silently evaporates"
        );
        assert_eq!(
            pol.decide(Some(OTHER), dst, Some("metrics.example.com")),
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
            pol.decide(Some(APP), dst, Some("metrics.example.com")),
            Verdict::Deny,
            "approving an app wholesale must not resurrect a destination you blocked"
        );
        assert_eq!(pol.decide(Some(APP), dst, Some("cdn.example.com")), Verdict::Allow);
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
        assert_eq!(pol.decide(Some(APP), blocked, None), Verdict::Deny);
        assert_eq!(pol.decide(Some(APP), other, None), Verdict::Allow);
        assert_eq!(pol.decide(Some(OTHER), blocked, None), Verdict::Allow);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn wildcards_work_in_scoped_rules_too() {
        let (pol, path) = load_from(
            "wildcard",
            "default allow\ndeny-host-from *.telemetry.example.com /usr/local/bin/someapp\n",
        );
        let dst = "203.0.113.9".parse::<IpAddr>().unwrap();
        assert_eq!(pol.decide(Some(APP), dst, Some("eu.telemetry.example.com")), Verdict::Deny);
        assert_eq!(pol.decide(Some(APP), dst, Some("telemetry.example.com")), Verdict::Deny);
        assert_eq!(pol.decide(Some(APP), dst, Some("example.com")), Verdict::Allow);
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
            pol.decide(Some("/opt/My App/bin/app"), dst, Some("metrics.example.com")),
            Verdict::Deny
        );
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
        assert_eq!(pol.decide(Some(APP), dst, Some("api.example.com")), Verdict::Allow);
        assert_eq!(
            pol.decide(Some(OTHER), dst, Some("api.example.com")),
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
        assert_eq!(pol.decide(Some(APP), dst, Some("api.example.com")), Verdict::Allow);
        assert_eq!(pol.decide(Some(OTHER), dst, Some("api.example.com")), Verdict::Deny);
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
            pol.decide(Some(APP), dst, Some("api.example.com")),
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
        assert_eq!(pol.decide(Some(APP), dst, Some("dns.example.com")), Verdict::Allow);
        assert_eq!(pol.decide(Some(OTHER), dst, Some("dns.example.com")), Verdict::Allow);
        assert_eq!(pol.decide(None, dst, Some("dns.example.com")), Verdict::Allow);
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
            pol.decide(None, dst, Some("api.example.com")),
            Verdict::Ask,
            "fail closed: an unidentified process gets no benefit from another app rule"
        );
        let _ = fs::remove_file(path);
    }
}
