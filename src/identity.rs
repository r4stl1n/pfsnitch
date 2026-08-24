//! Is the binary behind a rule still the binary that was approved?
//!
//! Policy keys on the executable path, which is the only stable handle pf and
//! libprocstat give us. But a path is not an identity: replace the file and the
//! replacement inherits every rule the original earned. Little Snitch solves
//! this with code signatures; FreeBSD binaries generally are not signed, so we
//! use a content hash instead.
//!
//! The hash is computed by shelling out to sha256(1) from base rather than
//! carrying a crypto implementation. That is only affordable because of the
//! cache below: a binary is hashed once, and again only if its mtime or size
//! changes. Hashing on every packet would be absurd.

use std::collections::HashMap;
use std::process::Command;
use std::time::UNIX_EPOCH;

#[derive(Default)]
pub struct Identity {
    /// path -> (mtime, size, hash). Keyed on the cheap facts so we can tell
    /// whether the expensive one still applies.
    cache: HashMap<String, (u64, u64, String)>,
}

impl Identity {
    pub fn new() -> Self {
        Self::default()
    }

    /// Current hash of a binary, or None if it cannot be read.
    ///
    /// None is deliberately distinct from "changed": a binary we cannot hash is
    /// not evidence of tampering, and treating it as such would break every
    /// rule the moment a file became unreadable.
    pub fn hash(&mut self, path: &str) -> Option<String> {
        let md = std::fs::metadata(path).ok()?;
        let size = md.len();
        let mtime = md
            .modified()
            .ok()?
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_secs();

        if let Some((m, s, h)) = self.cache.get(path) {
            if *m == mtime && *s == size {
                return Some(h.clone());
            }
        }

        let out = Command::new("/sbin/sha256").arg("-q").arg(path).output().ok()?;
        if !out.status.success() {
            return None;
        }
        let h = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if h.is_empty() {
            return None;
        }
        // Bound the cache. A machine does not run enough distinct binaries for
        // this to matter, but an unbounded map in a long-lived daemon is a leak
        // waiting for something unusual to happen.
        if self.cache.len() > 2048 {
            self.cache.clear();
        }
        self.cache.insert(path.to_string(), (mtime, size, h.clone()));
        Some(h)
    }
}
