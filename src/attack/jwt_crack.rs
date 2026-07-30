//! JWT in-process brute-force cracker.
//!
//! Supports HS256 (HMAC-SHA256) secret cracking. No subprocess spawn, no
//! external hashcat dependency. Designed for v4.6.0 to kill Sumopod-style
//! "weak JWT secret" findings without spawning external tools.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::Instant;

type HmacSha256 = Hmac<Sha256>;

/// Result of a single JWT crack attempt.
#[derive(Debug, Clone)]
pub struct CrackResult {
    pub jwt: String,
    pub secret: Option<String>,
    pub attempts: usize,
    pub duration_ms: u64,
    pub hit: bool,
}

/// Parse a JWT into its 3 base64url segments (header, payload, signature).
pub fn parse_segments(jwt: &str) -> Result<(&str, &str, &str), String> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(format!("malformed JWT: {} segments", parts.len()));
    }
    Ok((parts[0], parts[1], parts[2]))
}

/// Decode base64url (RFC 7515 §2) without external dep.
/// Adds padding so std can handle it.
fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| format!("base64url decode: {e}"))
}

/// Check whether a candidate secret produces the JWT's signature (HS256).
///
/// Returns true on match. Constant-time via `subtle` not yet used — for v4.6.0
/// we accept timing variance (the secrets are tried via runtime bruteforce and
/// timing leak is a minor concern in this context).
pub fn check_secret(jwt: &str, secret: &str) -> bool {
    let (header_b64, payload_b64, sig_b64) = match parse_segments(jwt) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig_bytes = match b64url_decode(sig_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if sig_bytes.len() != 32 {
        return false;
    }
    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(signing_input.as_bytes());
    mac.verify_slice(&sig_bytes).is_ok()
}

/// Crack a JWT by iterating a wordlist. Stops on first match.
///
/// `wordlist` is any iterator of `&str` secrets (line-by-line file, built-in
/// common list, custom array).
pub fn crack<I, S>(jwt: &str, wordlist: I) -> CrackResult
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let start = Instant::now();
    if parse_segments(jwt).is_err() {
        return CrackResult {
            jwt: jwt.to_string(),
            secret: None,
            attempts: 0,
            duration_ms: start.elapsed().as_millis() as u64,
            hit: false,
        };
    }
    let mut attempts = 0usize;
    for candidate in wordlist {
        attempts += 1;
        let s = candidate.as_ref();
        if check_secret(jwt, s) {
            return CrackResult {
                jwt: jwt.to_string(),
                secret: Some(s.to_string()),
                attempts,
                duration_ms: start.elapsed().as_millis() as u64,
                hit: true,
            };
        }
    }
    CrackResult {
        jwt: jwt.to_string(),
        secret: None,
        attempts,
        duration_ms: start.elapsed().as_millis() as u64,
        hit: false,
    }
}

/// Built-in common JWT secrets — first 100 entries from public leaks/Crackstation.
pub fn builtin_wordlist() -> Vec<&'static str> {
    vec![
        "secret", "password", "123456", "admin", "qwerty", "jwt", "key",
        "your-256-bit-secret", "your-secret", "my-secret", "top-secret",
        "keyboard cat", "shhhhh", "default", "changeme", "letmein",
        "iloveyou", "1234567890", "abc123", "test", "root", "toor",
        "supersecret", "jwt_secret", "hmac-secret", "signing-key",
        "private_key", "shared_secret", "SECRET", "SECRET_KEY", "MY_SECRET",
        "JWT_SECRET", "JWT_KEY", "TOKEN_SECRET", "HMAC_KEY", "SIGN_KEY",
        "AAA", "BBB", "aaa", "bbb", "pass", "passwd", "pwd",
        "12345", "1234", "123456789", "0000", "1111", "00000",
        "1q2w3e4r", "qwerty123", "abc", "xyz", "asdf", "zxcv",
        "test123", "secret123", "admin123", "root123", "user", "guest",
        "demo", "sample", "example", "default123", "production",
        "staging", "development", "internal", "external", "public",
        "private", "server", "client", "api", "backend", "frontend",
        "mobile", "web", "service", "worker", "queue", "database",
        "redis", "mongo", "postgres", "mysql", "sqlite", "oracle",
        "auth-secret", "session-secret", "cookie-secret", "csrf-secret",
        "jwt-key", "hmac-secret-key", "token-key", "auth-key",
        "notsecret", "nope", "nothing", "placeholder", "TODO",
        "FIXME", "CHANGEME", "TBD", "REPLACE_ME",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an HS256 JWT for testing.
    fn mint_jwt(secret: &str, header: &str, payload: &str) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let h = URL_SAFE_NO_PAD.encode(header);
        let p = URL_SAFE_NO_PAD.encode(payload);
        let signing_input = format!("{h}.{p}");
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(signing_input.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{h}.{p}.{sig}")
    }

    #[test]
    fn parse_segments_correct_format() {
        let jwt = "abc.def.ghi";
        assert_eq!(parse_segments(jwt).unwrap(), ("abc", "def", "ghi"));
    }

    #[test]
    fn parse_segments_rejects_malformed() {
        assert!(parse_segments("only.two").is_err());
        assert!(parse_segments("a.b.c.d").is_err());
    }

    #[test]
    fn check_secret_correct_matches() {
        let jwt = mint_jwt("mySecret", r#"{"alg":"HS256"}"#, r#"{"sub":"1"}"#);
        assert!(check_secret(&jwt, "mySecret"));
    }

    #[test]
    fn check_secret_wrong_rejects() {
        let jwt = mint_jwt("mySecret", r#"{"alg":"HS256"}"#, r#"{"sub":"1"}"#);
        assert!(!check_secret(&jwt, "wrong"));
        assert!(!check_secret(&jwt, ""));
    }

    #[test]
    fn crack_finds_secret_in_wordlist() {
        let jwt = mint_jwt("supersecret", r#"{"alg":"HS256"}"#, r#"{"sub":"1"}"#);
        let words: Vec<&str> = vec!["admin", "test", "supersecret", "wrong"];
        let res = crack(&jwt, words);
        assert!(res.hit);
        assert_eq!(res.secret.as_deref(), Some("supersecret"));
        // Cracks at attempt 3.
        assert_eq!(res.attempts, 3);
    }

    #[test]
    fn crack_returns_no_hit_when_absent() {
        let jwt = mint_jwt("real-secret-xxx", r#"{"alg":"HS256"}"#, r#"{}"#);
        let words: Vec<&str> = vec!["admin", "test", "wrong"];
        let res = crack(&jwt, words);
        assert!(!res.hit);
        assert_eq!(res.attempts, 3);
        assert!(res.secret.is_none());
    }

    #[test]
    fn crack_handles_empty_wordlist() {
        let jwt = mint_jwt("s", r#"{"alg":"HS256"}"#, r#"{}"#);
        let words: Vec<&str> = vec![];
        let res = crack(&jwt, words);
        assert!(!res.hit);
        assert_eq!(res.attempts, 0);
    }

    #[test]
    fn crack_handles_malformed_jwt() {
        let words: Vec<&str> = vec!["x"];
        let res = crack("not-a-jwt", words);
        assert!(!res.hit);
        assert_eq!(res.attempts, 0);
    }

    #[test]
    fn builtin_wordlist_nonempty() {
        let words = builtin_wordlist();
        assert!(words.len() > 50);
        assert!(words.contains(&"secret"));
        assert!(words.contains(&"password"));
    }

    #[test]
    fn builtin_wordlist_cracks_known_jwt() {
        // Mint a JWT with a known common secret from the builtin list.
        let jwt = mint_jwt("changeme", r#"{"alg":"HS256"}"#, r#"{"sub":"1"}"#);
        let words = builtin_wordlist();
        let res = crack(&jwt, words);
        assert!(res.hit);
        assert_eq!(res.secret.as_deref(), Some("changeme"));
    }
}
