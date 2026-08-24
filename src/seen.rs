//! When did this binary last talk to this destination?
//!
//! Deliberately not traffic accounting. We only ever see the first packet of a
//! TCP connection - the rest matches pf state and never reaches userspace - so
//! byte counts would be UDP-only and quietly misleading. A timestamp is
//! something we can actually observe for every protocol, and it answers the
//! question people actually ask of a rule list: is this still in use, or is it
//! left over from something I did months ago?
//!
//! Kept in memory and flushed to a small file, because the CLI is a separate
//! process and the whole design avoids having an IPC protocol to speak.

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub const PATH: &str = "/var/run/pfsnitch/lastseen";

#[derive(Default)]
pub struct Seen {
    /// (binary, destination as a rule would spell it) -> unix seconds
    map: HashMap<(String, String), u64>,
    dirty: bool,
    last_flush: Option<Instant>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Seen {
    /// Seeded from the table on disk.
    ///
    /// Without this a restart silently resets every timestamp to "never" - the
    /// daemon would write its empty map straight over the history, which is
    /// worse than not recording anything, because it looks like real data.
    pub fn new() -> Self {
        Seen {
            map: load(),
            dirty: false,
            last_flush: None,
        }
    }

    /// Note that `exe` just contacted `dest`.
    ///
    /// `dest` should be spelled the way a rule spells it - the hostname when we
    /// saw one, the address otherwise - so the CLI can join these against rules
    /// without a second matching scheme that could disagree with the first.
    pub fn touch(&mut self, exe: &str, dest: &str) {
        if exe.is_empty() || dest.is_empty() || dest == "-" {
            return;
        }
        // A machine talks to a bounded set of places, but a long-lived daemon
        // with an unbounded map is a leak waiting for something unusual.
        if self.map.len() > 4096 {
            self.map.clear();
        }
        self.map.insert((exe.to_string(), dest.to_lowercase()), now());
        self.dirty = true;
    }

    /// Write the table out if it has changed and enough time has passed.
    ///
    /// Rate-limited because this is on the packet path: a busy UDP flow would
    /// otherwise rewrite the file thousands of times a second for information
    /// nobody is reading that fast.
    pub fn flush(&mut self, every: std::time::Duration) {
        if !self.dirty {
            return;
        }
        if let Some(t) = self.last_flush {
            if t.elapsed() < every {
                return;
            }
        }
        self.last_flush = Some(Instant::now());
        self.dirty = false;

        let path = Path::new(PATH);
        let tmp = path.with_extension("tmp");
        let mut buf = String::with_capacity(self.map.len() * 48);
        for ((exe, dest), ts) in &self.map {
            // Destination first: it can never contain a tab or a space, an
            // executable path might. Same reasoning as the scoped rule format.
            buf.push_str(&format!("{ts}\t{dest}\t{exe}\n"));
        }
        // Rename into place so a reader never sees a half-written table.
        if let Ok(mut f) = std::fs::File::create(&tmp) {
            if f.write_all(buf.as_bytes()).is_ok() {
                let _ = std::fs::rename(&tmp, path);
            }
        }
    }
}

/// Read the table back: (binary, destination) -> unix seconds.
pub fn load() -> HashMap<(String, String), u64> {
    let mut out = HashMap::new();
    let text = match std::fs::read_to_string(PATH) {
        Ok(t) => t,
        Err(_) => return out,
    };
    for line in text.lines() {
        let mut it = line.splitn(3, '\t');
        let (ts, dest, exe) = match (it.next(), it.next(), it.next()) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => continue,
        };
        if let Ok(t) = ts.parse::<u64>() {
            out.insert((exe.to_string(), dest.to_lowercase()), t);
        }
    }
    out
}

/// "4m ago", "3d ago", or "never" - short enough for a table column.
pub fn ago(ts: Option<u64>) -> String {
    let ts = match ts {
        Some(t) if t > 0 => t,
        _ => return "never".to_string(),
    };
    let n = now();
    if n < ts {
        // Clock went backwards; claiming a negative age would be worse than
        // admitting we do not know.
        return "just now".to_string();
    }
    let d = n - ts;
    match d {
        0..=59 => format!("{d}s ago"),
        60..=3599 => format!("{}m ago", d / 60),
        3600..=86399 => format!("{}h ago", d / 3600),
        _ => format!("{}d ago", d / 86400),
    }
}
