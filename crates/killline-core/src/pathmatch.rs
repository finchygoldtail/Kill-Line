//! Path normalisation and matching.
//!
//! Patterns are either plain paths, which match the path itself and anything
//! beneath it (`/workspace` matches `/workspace/a/b`), or globs:
//! `*` matches within one path segment, `**` matches any number of segments.
//! A leading `~/` is expanded to both `/root/` and `/home/*/`.

/// Lexically normalise an absolute path: collapse `//`, `.` and `..`.
/// This does not touch the filesystem (and so does not resolve symlinks;
/// KillLine gets kernel-resolved paths from a separate hook for that).
pub fn normalize(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    let mut out = String::with_capacity(path.len());
    for p in &parts {
        out.push('/');
        out.push_str(p);
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

/// Join a possibly-relative path onto a base directory and normalise it.
pub fn resolve(base: &str, path: &str) -> String {
    if path.starts_with('/') {
        normalize(path)
    } else {
        normalize(&format!("{}/{}", base, path))
    }
}

/// Expand `~/x` into `/root/x` and `/home/*/x`.
pub fn expand_home(pattern: &str) -> Vec<String> {
    if let Some(rest) = pattern.strip_prefix("~/") {
        vec![format!("/root/{}", rest), format!("/home/*/{}", rest)]
    } else if pattern == "~" {
        vec!["/root".to_string(), "/home/*".to_string()]
    } else {
        vec![pattern.to_string()]
    }
}

fn is_glob(p: &str) -> bool {
    p.contains('*') || p.contains('?')
}

/// Does `pattern` match `path`? `path` must already be normalised.
pub fn matches(pattern: &str, path: &str) -> bool {
    if is_glob(pattern) {
        let pat: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        // A glob pattern also covers everything beneath a matching directory.
        glob_segments(&pat, &segs, true)
    } else {
        let pat = normalize(pattern);
        if pat == "/" {
            return true;
        }
        path == pat || (path.starts_with(&pat) && path.as_bytes().get(pat.len()) == Some(&b'/'))
    }
}

fn glob_segments(pat: &[&str], segs: &[&str], prefix_ok: bool) -> bool {
    match pat.first() {
        None => segs.is_empty() || prefix_ok,
        Some(&"**") => {
            for i in 0..=segs.len() {
                if glob_segments(&pat[1..], &segs[i..], prefix_ok) {
                    return true;
                }
            }
            false
        }
        Some(p) => match segs.first() {
            Some(s) if segment_match(p.as_bytes(), s.as_bytes()) => {
                glob_segments(&pat[1..], &segs[1..], prefix_ok)
            }
            _ => false,
        },
    }
}

fn segment_match(p: &[u8], s: &[u8]) -> bool {
    match (p.first(), s.first()) {
        (None, None) => true,
        (Some(b'*'), _) => {
            segment_match(&p[1..], s) || (!s.is_empty() && segment_match(p, &s[1..]))
        }
        (Some(b'?'), Some(_)) => segment_match(&p[1..], &s[1..]),
        (Some(a), Some(b)) if a == b => segment_match(&p[1..], &s[1..]),
        _ => false,
    }
}

/// First pattern in `patterns` that matches `path`.
pub fn first_match<'a>(patterns: &'a [String], path: &str) -> Option<&'a str> {
    patterns
        .iter()
        .find(|p| matches(p, path))
        .map(|s| s.as_str())
}

/// A pre-compiled list of patterns. Matching allocates nothing; plain
/// prefixes are checked before globs.
#[derive(Debug, Clone, Default)]
pub struct PatternSet {
    raw: Vec<String>,
    /// (normalised prefix, index into raw)
    prefixes: Vec<(String, usize)>,
    /// (segments, index into raw)
    globs: Vec<(Vec<String>, usize)>,
}

impl PatternSet {
    pub fn new<I: IntoIterator<Item = S>, S: AsRef<str>>(patterns: I) -> PatternSet {
        let mut set = PatternSet::default();
        for p in patterns {
            let p = p.as_ref();
            let i = set.raw.len();
            set.raw.push(p.to_string());
            if is_glob(p) {
                set.globs.push((
                    p.split('/')
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect(),
                    i,
                ));
            } else {
                set.prefixes.push((normalize(p), i));
            }
        }
        set
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    pub fn patterns(&self) -> &[String] {
        &self.raw
    }

    /// The first (in declaration order) pattern matching `path`, which must
    /// be normalised.
    pub fn first_match(&self, path: &str) -> Option<&str> {
        let mut best: Option<usize> = None;
        for (pre, i) in &self.prefixes {
            let hit = pre == "/"
                || path == pre
                || (path.starts_with(pre.as_str())
                    && path.as_bytes().get(pre.len()) == Some(&b'/'));
            if hit {
                best = Some(best.map_or(*i, |b| b.min(*i)));
                break;
            }
        }
        if !self.globs.is_empty() {
            let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            for (g, i) in &self.globs {
                if best.is_some_and(|b| b < *i) {
                    break;
                }
                let pat: Vec<&str> = g.iter().map(|s| s.as_str()).collect();
                if glob_segments(&pat, &segs, true) {
                    best = Some(best.map_or(*i, |b| b.min(*i)));
                    break;
                }
            }
        }
        best.map(|i| self.raw[i].as_str())
    }

    pub fn matches(&self, path: &str) -> bool {
        self.first_match(path).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises() {
        assert_eq!(normalize("/workspace/../etc//shadow"), "/etc/shadow");
        assert_eq!(normalize("/a/./b/"), "/a/b");
        assert_eq!(normalize("/../.."), "/");
        assert_eq!(resolve("/workspace", "../root/.ssh"), "/root/.ssh");
    }

    #[test]
    fn prefix_matching_respects_segments() {
        assert!(matches("/workspace", "/workspace"));
        assert!(matches("/workspace", "/workspace/output/x"));
        assert!(!matches("/workspace", "/workspace2/x"));
        assert!(matches("/", "/anything"));
    }

    #[test]
    fn globs() {
        assert!(matches("/home/*/.ssh", "/home/alice/.ssh/id_rsa"));
        assert!(matches("**/.env", "/srv/app/.env"));
        assert!(!matches("**/.env", "/srv/app/.envrc"));
        assert!(matches("**/.env.*", "/srv/app/.env.local"));
        assert!(matches("**/id_rsa*", "/x/y/id_rsa.pub"));
        assert!(matches("/proc/*/environ", "/proc/42/environ"));
        assert!(!matches("/proc/*/environ", "/proc/42/status"));
    }

    #[test]
    fn pattern_set_matches_like_matches() {
        let pats = ["/workspace", "**/.env", "/proc/*/environ", "/"];
        let set = PatternSet::new(pats.iter());
        for path in ["/workspace/a", "/x/.env", "/proc/3/environ", "/etc/passwd"] {
            let expect = pats.iter().find(|p| matches(p, path)).copied();
            assert_eq!(set.first_match(path), expect, "{}", path);
        }
        let set = PatternSet::new(["/a", "/b"].iter());
        assert_eq!(set.first_match("/c"), None);
    }

    #[test]
    fn home_expansion() {
        let v = expand_home("~/.aws");
        assert!(v.iter().any(|p| matches(p, "/root/.aws/credentials")));
        assert!(v.iter().any(|p| matches(p, "/home/bob/.aws/config")));
    }
}
