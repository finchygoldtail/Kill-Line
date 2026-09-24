//! Path normalisation and matching.
//!
//! Patterns are either plain paths, which match the path itself and anything
//! beneath it (`/workspace` matches `/workspace/a/b`), or globs:
//! `*` matches within one path segment, `**` matches any number of segments.
//! A leading `~/` is expanded to both `/root/` and `/home/*/`.

/// Lexically normalise an absolute path: collapse `//`, `.` and `..`.
/// This does not touch the filesystem (and so does not resolve symlinks;
/// Kill Line gets kernel-resolved paths from a separate hook for that).
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

/// Canonical form of a Windows path, so the same matcher serves both
/// platforms: lowercase (NTFS lookups are case-insensitive), forward
/// slashes, a leading slash before the drive, device and pipe namespaces
/// shortened.
///
/// `C:\Users\Bob\.ssh\id_rsa`      → `/c:/users/bob/.ssh/id_rsa`
/// `\??\C:\Temp\x`                → `/c:/temp/x`
/// `\Device\NamedPipe\docker_engine` → `/pipe/docker_engine`
/// `\\.\PhysicalDrive0`            → `/physicaldrive0`
pub fn canonical_windows(path: &str) -> String {
    let mut p = path.replace('\\', "/").to_lowercase();
    for prefix in ["//?/", "/??/", "//./"] {
        if let Some(rest) = p.strip_prefix(prefix) {
            p = rest.to_string();
            break;
        }
    }
    if let Some(rest) = p.strip_prefix("/device/namedpipe/") {
        p = format!("/pipe/{}", rest);
    } else if let Some(rest) = p.strip_prefix("pipe/") {
        p = format!("/pipe/{}", rest);
    }
    let b = p.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        p = format!("/{}", p);
    }
    normalize(&p)
}

/// Is this pattern an absolute Windows path (`C:\…`, `C:/…`) or UNC path?
pub fn is_windows_absolute(p: &str) -> bool {
    let b = p.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/'))
        || p.starts_with("\\\\")
        || (b.len() >= 3
            && (b[0] == b'*' || b[0] == b'?')
            && b[1] == b':'
            && (b[2] == b'\\' || b[2] == b'/'))
}

/// Home expansion for Windows: `~/x` → `/*:/users/*/x` (any drive, any user).
pub fn expand_home_windows(pattern: &str) -> Vec<String> {
    let p = pattern.replace('\\', "/");
    if let Some(rest) = p.strip_prefix("~/") {
        vec![canonical_windows_pattern(&format!("*:/users/*/{}", rest))]
    } else if p == "~" {
        vec!["/*:/users/*".to_string()]
    } else {
        vec![canonical_windows_pattern(&p)]
    }
}

/// Like `canonical_windows`, for patterns (keeps `**/` prefixes and globs).
pub fn canonical_windows_pattern(p: &str) -> String {
    let p = p.replace('\\', "/").to_lowercase();
    if p.starts_with("**/") || p.starts_with('/') {
        return p;
    }
    canonical_windows(&p)
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

    /// Is `path` a proper ancestor of one of the plain (non-glob) patterns?
    pub fn is_ancestor(&self, path: &str) -> bool {
        let with_slash = if path.ends_with('/') {
            path.to_string()
        } else {
            format!("{}/", path)
        };
        self.prefixes
            .iter()
            .any(|(pre, _)| pre.len() > path.len() && pre.starts_with(&with_slash))
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
    fn windows_paths() {
        assert_eq!(
            canonical_windows(r"C:\Users\Bob\.ssh\id_rsa"),
            "/c:/users/bob/.ssh/id_rsa"
        );
        assert_eq!(canonical_windows(r"\??\C:\Temp\..\x"), "/c:/x");
        assert_eq!(
            canonical_windows(r"\Device\NamedPipe\docker_engine"),
            "/pipe/docker_engine"
        );
        assert_eq!(
            canonical_windows(r"\\.\pipe\docker_engine"),
            "/pipe/docker_engine"
        );
        assert_eq!(canonical_windows(r"\\.\PhysicalDrive0"), "/physicaldrive0");
        assert!(is_windows_absolute(r"C:\Work"));
        assert!(!is_windows_absolute("relative"));
        let pats = expand_home_windows("~/.aws");
        assert!(matches(
            &pats[0],
            &canonical_windows(r"D:\Users\Alice\.aws\credentials")
        ));
        assert_eq!(
            canonical_windows_pattern(r"C:\Work\Project"),
            "/c:/work/project"
        );
    }

    #[test]
    fn home_expansion() {
        let v = expand_home("~/.aws");
        assert!(v.iter().any(|p| matches(p, "/root/.aws/credentials")));
        assert!(v.iter().any(|p| matches(p, "/home/bob/.aws/config")));
    }
}
