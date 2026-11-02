//! Saved searches and the little state that outlives a window.
//!
//! Section 6.2: "Saved searches can be named and stored in the workspace."
//! This is that workspace, kept deliberately small - saved searches, the last
//! directory browsed, and the captures opened recently. Full session and
//! workspace persistence is phase 8; what is here is what phase 5 needs, in a
//! file that a later phase can grow rather than replace.
//!
//! # Why it is hand-written text
//!
//! No serde in this crate: the file is a handful of lines and a dependency for
//! it would be a dependency in the way. The format is one record per line,
//! `key\tvalue`, which cannot be broken by a label containing a comma and can
//! be read by anything.
//!
//! A workspace that fails to load is not an error worth stopping for - a
//! missing or corrupt one means "no saved searches", and the window opens.

use std::path::PathBuf;

/// A named query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Saved {
    pub name: String,
    pub query: String,
}

#[derive(Debug, Default, Clone)]
pub struct Workspace {
    pub searches: Vec<Saved>,
    pub last_dir: Option<PathBuf>,
    /// Most recent first, capped - a recent list that grows forever is a list
    /// nobody reads.
    pub recent: Vec<PathBuf>,
}

const RECENT_MAX: usize = 8;

impl Workspace {
    /// Where the file lives: beside the user's other application data.
    pub fn path() -> Option<PathBuf> {
        let base = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from))
            .or_else(|| std::env::var_os("HOME")
                .map(|h| PathBuf::from(h).join(".config")))?;
        Some(base.join("sniffer").join("workspace.tsv"))
    }

    pub fn load() -> Workspace {
        let Some(path) = Self::path() else { return Workspace::default() };
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Workspace::default();
        };
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Workspace {
        let mut w = Workspace::default();
        for line in text.lines() {
            let line = line.trim_end_matches(['\r', '\n']);
            let Some((key, value)) = line.split_once('\t') else { continue };
            match key {
                "search" => {
                    // The name is up to the next tab; the query is the rest,
                    // so a query containing spaces needs no quoting.
                    if let Some((name, q)) = value.split_once('\t') {
                        w.searches.push(Saved {
                            name: name.to_string(),
                            query: q.to_string(),
                        });
                    }
                }
                "dir" => w.last_dir = Some(PathBuf::from(value)),
                "recent" => w.recent.push(PathBuf::from(value)),
                _ => {}
            }
        }
        w.recent.truncate(RECENT_MAX);
        w
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        for s in &self.searches {
            // A tab in a name would break the format, so it cannot be in one.
            let name = s.name.replace('\t', " ");
            let query = s.query.replace('\t', " ");
            out.push_str(&format!("search\t{name}\t{query}\n"));
        }
        if let Some(dir) = &self.last_dir {
            out.push_str(&format!("dir\t{}\n", dir.display()));
        }
        for path in self.recent.iter().take(RECENT_MAX) {
            out.push_str(&format!("recent\t{}\n", path.display()));
        }
        out
    }

    /// Write it, quietly. A workspace that cannot be saved must not stop the
    /// window from closing.
    pub fn save(&self) {
        let Some(path) = Self::path() else { return };
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(path, self.render());
    }

    /// Save a query under a name, replacing one of the same name.
    ///
    /// Returns false when there was nothing to save. Silence would be worse:
    /// the window used to report success for a query nobody had typed.
    pub fn remember(&mut self, name: &str, query: &str) -> bool {
        let name = name.trim();
        if name.is_empty() || query.trim().is_empty() {
            return false;
        }
        match self.searches.iter_mut().find(|s| s.name == name) {
            Some(existing) => existing.query = query.to_string(),
            None => self.searches.push(Saved {
                name: name.to_string(),
                query: query.to_string(),
            }),
        }
        true
    }

    pub fn forget(&mut self, name: &str) {
        self.searches.retain(|s| s.name != name);
    }

    /// Note a capture as recently opened, most recent first and no duplicates.
    pub fn opened(&mut self, path: &std::path::Path) {
        self.recent.retain(|p| p != path);
        self.recent.insert(0, path.to_path_buf());
        self.recent.truncate(RECENT_MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_workspace_round_trips_through_its_file_format() {
        let mut w = Workspace::default();
        w.remember("nacks", "error:nack");
        w.remember("that one device", "addr:0x52 type:READ");
        w.last_dir = Some(PathBuf::from("E:/captures"));
        w.opened(std::path::Path::new("E:/captures/a.cap"));

        let back = Workspace::parse(&w.render());
        assert_eq!(back.searches, w.searches);
        assert_eq!(back.last_dir, w.last_dir);
        assert_eq!(back.recent, w.recent);
    }

    /// A query with spaces in it is the normal case, not the exception.
    #[test]
    fn a_saved_query_keeps_its_spaces() {
        let mut w = Workspace::default();
        w.remember("two terms", "addr:0x52 error:any");
        let back = Workspace::parse(&w.render());
        assert_eq!(back.searches[0].query, "addr:0x52 error:any");
    }

    #[test]
    fn saving_the_same_name_twice_replaces_rather_than_duplicates() {
        let mut w = Workspace::default();
        w.remember("mine", "addr:0x52");
        w.remember("mine", "addr:0x53");
        assert_eq!(w.searches.len(), 1);
        assert_eq!(w.searches[0].query, "addr:0x53");
    }

    #[test]
    fn an_empty_name_or_query_is_not_saved_and_says_so() {
        let mut w = Workspace::default();
        assert!(!w.remember("", "addr:0x52"));
        assert!(!w.remember("named", "   "));
        assert!(w.searches.is_empty());
        assert!(w.remember("named", "addr:0x52"));
    }

    #[test]
    fn recent_captures_are_most_recent_first_without_duplicates() {
        let mut w = Workspace::default();
        for name in ["a", "b", "a"] {
            w.opened(std::path::Path::new(name));
        }
        assert_eq!(w.recent, vec![PathBuf::from("a"), PathBuf::from("b")]);
    }

    /// Rubbish in the file means "no saved searches", not a window that will
    /// not open.
    #[test]
    fn a_corrupt_workspace_loads_as_an_empty_one() {
        let w = Workspace::parse("this is not a workspace\n\0\nsearch\tonly a name\n");
        assert!(w.searches.is_empty());
        assert!(w.recent.is_empty());
        assert!(w.last_dir.is_none());
    }
}
