//! Redaction of secrets from command lines and other free text.
//!
//! KillLine never reads file contents, but command-line arguments and
//! environment-style assignments frequently carry tokens. Everything that
//! looks secret is replaced before it reaches the timeline.

pub const REDACTED: &str = "[REDACTED]";

const SECRET_KEYS: &[&str] = &[
    "pass", "pwd", "secret", "token", "apikey", "api_key", "api-key", "auth", "credential",
    "private", "session", "cookie", "bearer", "access_key", "access-key", "signature",
];

const SECRET_PREFIXES: &[&str] = &[
    "sk-", "sk_live_", "sk_test_", "ghp_", "gho_", "ghs_", "ghu_", "github_pat_", "glpat-",
    "xoxb-", "xoxp-", "xoxa-", "AKIA", "ASIA", "AIza", "ya29.", "eyJ", "npm_", "pypi-",
    "hf_", "-----BEGIN",
];

fn key_is_secret(key: &str) -> bool {
    let k = key.trim_start_matches('-').to_ascii_lowercase();
    SECRET_KEYS.iter().any(|s| k.contains(s))
}

fn looks_like_secret_value(v: &str) -> bool {
    if SECRET_PREFIXES.iter().any(|p| v.starts_with(p)) && v.len() >= 12 {
        return true;
    }
    // Long, high-variety tokens (base64 / hex keys).
    if v.len() >= 32 && !v.contains('/') && !v.contains(' ') {
        let alnum = v.chars().filter(|c| c.is_ascii_alphanumeric()).count();
        let digits = v.chars().filter(|c| c.is_ascii_digit()).count();
        let upper = v.chars().filter(|c| c.is_ascii_uppercase()).count();
        let lower = v.chars().filter(|c| c.is_ascii_lowercase()).count();
        if alnum * 10 >= v.len() * 9 && digits > 0 && (upper > 0 || lower > 0) {
            return true;
        }
    }
    // URLs with embedded credentials: scheme://user:pass@host
    if let Some(rest) = v.split("://").nth(1) {
        if let Some(at) = rest.find('@') {
            if rest[..at].contains(':') {
                return true;
            }
        }
    }
    false
}

/// Redact a single free-text value.
pub fn redact_value(v: &str) -> String {
    if let Some((k, _)) = v.split_once('=') {
        if key_is_secret(k) {
            return format!("{}={}", k, REDACTED);
        }
    }
    if looks_like_secret_value(v) {
        return REDACTED.to_string();
    }
    if let Some(i) = v.find("://") {
        let rest = &v[i + 3..];
        if let Some(at) = rest.find('@') {
            if rest[..at].contains(':') {
                return format!("{}://{}@{}", &v[..i], REDACTED, &rest[at + 1..]);
            }
        }
    }
    v.to_string()
}

/// Redact an argument vector. Handles `--token=x`, `--token x`, `-p x`,
/// `KEY=value`, bearer headers and token-shaped values.
pub fn redact_argv(argv: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut redact_next = false;
    for a in argv {
        if redact_next {
            out.push(REDACTED.to_string());
            redact_next = false;
            continue;
        }
        let lower = a.to_ascii_lowercase();
        if lower.starts_with("authorization:") || lower.starts_with("x-api-key:") {
            let name = a.split(':').next().unwrap_or("");
            out.push(format!("{}: {}", name, REDACTED));
            continue;
        }
        if a.starts_with('-') && !a.contains('=') && (key_is_secret(a) || a == "-p" || a == "-u") {
            out.push(a.clone());
            redact_next = true;
            continue;
        }
        out.push(redact_value(a));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn redacts_flags_and_assignments() {
        let r = redact_argv(&v(&["curl", "--token", "abc", "--api-key=xyz", "AWS_SECRET_ACCESS_KEY=q"]));
        assert_eq!(r, v(&["curl", "--token", REDACTED, "--api-key=[REDACTED]", "AWS_SECRET_ACCESS_KEY=[REDACTED]"]));
    }

    #[test]
    fn redacts_token_shapes_and_urls() {
        let r = redact_argv(&v(&["x", "ghp_aaaaaaaaaaaaaaaaaaaa", "https://bob:hunter2@example.com/repo"]));
        assert_eq!(r[1], REDACTED);
        assert_eq!(r[2], REDACTED);
        let h = redact_argv(&v(&["-H", "Authorization: Bearer abc"]));
        assert_eq!(h[1], "Authorization: [REDACTED]");
    }

    #[test]
    fn leaves_ordinary_arguments() {
        let a = v(&["python3", "/workspace/worker.py", "--output", "/workspace/output/r.txt", "-v"]);
        assert_eq!(redact_argv(&a), a);
    }
}
