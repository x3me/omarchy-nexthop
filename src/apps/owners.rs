use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;
use std::fs;
use std::os::unix::ffi::OsStrExt;

use crate::util::monotonic;

pub type Clock = Box<dyn Fn() -> f64 + Send + Sync>;

// INFO: fc 17oct26 cached owners go stale when a socket is passed or inherited, Python re-read them with ss -p every 3 s
pub const FULL_SCAN_EVERY_S: f64 = 30.0;

#[derive(Clone, Debug, PartialEq)]
pub struct Owner {
    pub pid: i32,
    pub name: String,
}

pub struct Owners {
    root: String,
    clock: Clock,
    by_inode: HashMap<u32, Option<Owner>>,
    last_full_scan: Option<f64>,
    #[cfg(test)]
    pub scans: u64,
}

impl Default for Owners {
    fn default() -> Self {
        Self::new()
    }
}

pub fn socket_inode(link: &[u8]) -> Option<u32> {
    let digits = link.strip_prefix(b"socket:[")?.strip_suffix(b"]")?;
    std::str::from_utf8(digits).ok()?.parse().ok()
}

pub fn comm_name(comm: &[u8]) -> String {
    let comm = comm.strip_suffix(b"\n").unwrap_or(comm);
    let end = comm.iter().position(|&c| c == b')').unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

impl Owners {
    pub fn new() -> Self {
        Self::with_root("/proc", Box::new(monotonic))
    }

    pub fn with_root(root: &str, clock: Clock) -> Self {
        Self {
            root: root.trim_end_matches('/').to_string(),
            clock,
            by_inode: HashMap::new(),
            last_full_scan: None,
            #[cfg(test)]
            scans: 0,
        }
    }

    pub fn get(&self, inode: u32) -> Option<&Owner> {
        self.by_inode.get(&inode)?.as_ref()
    }

    pub fn resolve(&mut self, inodes: impl IntoIterator<Item = u32>, deadline: f64) -> bool {
        let live: HashSet<u32> = inodes.into_iter().filter(|&i| i != 0).collect();
        self.by_inode.retain(|ino, _| live.contains(ino));
        if live.is_empty() {
            return true;
        }
        self.refresh_names(deadline);
        if self.last_full_scan.is_none_or(|t| (self.clock)() - t > FULL_SCAN_EVERY_S) {
            return self.scan(&live, deadline);
        }
        let mut unknown: HashSet<u32> = live.iter().copied().filter(|i| !self.by_inode.contains_key(i)).collect();
        if unknown.is_empty() {
            return true;
        }
        let known_owners: BTreeSet<i32> = self.by_inode.values().flatten().map(|o| o.pid).collect();
        let mut path = String::new();
        for pid in known_owners {
            let (found, complete) = self.sockets_of(pid, &unknown, &mut path, deadline);
            for (ino, owner) in found {
                unknown.remove(&ino);
                self.by_inode.insert(ino, Some(owner));
            }
            if !complete {
                return false;
            }
        }
        if unknown.is_empty() {
            return true;
        }
        self.scan(&live, deadline)
    }

    fn expired(&self, deadline: f64) -> bool {
        (self.clock)() > deadline
    }

    fn numeric_entries(&self, dir: &str, deadline: f64) -> Option<Vec<i32>> {
        let Ok(entries) = fs::read_dir(dir) else {
            return Some(Vec::new());
        };
        let mut out = Vec::new();
        for entry in entries {
            if self.expired(deadline) {
                return None;
            }
            if let Some(n) = entry.ok().and_then(|e| e.file_name().to_str()?.parse().ok()) {
                out.push(n);
            }
        }
        out.sort_unstable();
        Some(out)
    }

    fn sockets_of(
        &self,
        pid: i32,
        wanted: &HashSet<u32>,
        path: &mut String,
        deadline: f64,
    ) -> (Vec<(u32, Owner)>, bool) {
        path.clear();
        let _ = write!(path, "{}/{pid}/fd/", self.root);
        let base = path.len();
        let mut name: Option<String> = None;
        let mut found = Vec::new();
        let Some(fds) = self.numeric_entries(&path[..base - 1], deadline) else {
            return (found, false);
        };
        for fd in fds {
            if self.expired(deadline) {
                return (found, false);
            }
            path.truncate(base);
            let _ = write!(path, "{fd}");
            let Ok(link) = fs::read_link(&*path) else {
                continue;
            };
            let Some(ino) = socket_inode(link.as_os_str().as_bytes()) else {
                continue;
            };
            if !wanted.contains(&ino) {
                continue;
            }
            let name = name.get_or_insert_with(|| self.read_comm(pid).unwrap_or_default());
            found.push((ino, Owner { pid, name: name.clone() }));
        }
        (found, true)
    }

    fn read_comm(&self, pid: i32) -> Option<String> {
        fs::read(format!("{}/{pid}/comm", self.root)).ok().map(|raw| comm_name(&raw))
    }

    fn refresh_names(&mut self, deadline: f64) {
        let mut names: HashMap<i32, Option<String>> = HashMap::new();
        for owner in self.by_inode.values().flatten() {
            if names.contains_key(&owner.pid) {
                continue;
            }
            if self.expired(deadline) {
                break;
            }
            names.insert(owner.pid, self.read_comm(owner.pid));
        }
        self.by_inode.retain(|_, slot| match slot {
            None => true,
            Some(owner) => match names.get(&owner.pid) {
                None => true,
                Some(Some(name)) => {
                    owner.name.clone_from(name);
                    true
                }
                Some(None) => false,
            },
        });
    }

    fn scan(&mut self, live: &HashSet<u32>, deadline: f64) -> bool {
        #[cfg(test)]
        {
            self.scans += 1;
        }
        let started = (self.clock)();
        let mut found: HashMap<u32, Owner> = HashMap::new();
        let mut complete = true;
        let mut path = String::new();
        let pids = self.numeric_entries(&self.root, deadline);
        for &pid in pids.as_deref().unwrap_or_default() {
            let (owned, done) = self.sockets_of(pid, live, &mut path, deadline);
            found.extend(owned);
            if !done {
                complete = false;
                break;
            }
        }
        complete &= pids.is_some();
        if complete {
            for &ino in live {
                self.by_inode.insert(ino, found.remove(&ino));
            }
            self.last_full_scan = Some(started);
        } else {
            for (ino, owner) in found {
                self.by_inode.insert(ino, Some(owner));
            }
        }
        complete
    }
}
