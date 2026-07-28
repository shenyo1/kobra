use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;

/// NoSQL injection (MongoDB-style). Uses differential: param[$ne]=<valid> differs
/// from param[$ne]=<impossible>, proving operator injection. Crazy adds $where/$regex.
pub async fn scan(http: &HttpClient, target: &str, params: &[String], mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let base = if target.contains('?') { target.to_string() } else { format!("{}/?q=test", target.trim_end_matches('/')) };

    for p in params {
        // baseline: normal value
        let b_url = inject(&base, p, "realvalue123");
        let base_body = match http.get(&b_url).await { Ok((_,_,b,_)) => b, Err(_) => continue };
        let base_len = base_body.len();

        let probes: Vec<&str> = if mode == Mode::Crazy {
            vec!["admin", "admin[$ne]=x", "x[$where]=1", "x[$regex]=.*"]
        } else {
            vec!["admin", "admin[$ne]=x"]
        };

        for pl in probes {
            let u = inject(&base, p, pl);
            let body = match http.get(&u).await { Ok((_,_,b,_)) => b, Err(_) => continue };
            let lb = body.to_lowercase();
            // positive signal: real Mongo error
            if lb.contains("mongoerror") || lb.contains("mongoserver") || lb.contains("cannot use $") {
                out.push(Finding::new(Severity::High, "NOSQL", "NoSQL injection (error-based)", target)
                    .with_param(p).with_payload(pl)
                    .with_evidence("MongoDB error reflected")
                    .with_confidence(90));
                continue;
            }
            // blind differential: $ne=impossible makes body differ from baseline
            if pl.contains("$ne") && body.len() != base_len {
                out.push(Finding::new(Severity::Medium, "NOSQL", "Possible NoSQL blind injection ($ne differential)", target)
                    .with_param(p).with_payload(pl)
                    .with_evidence(&format!("body len {} vs baseline {}", body.len(), base_len))
                    .with_confidence(55));
            }
        }
    }
    Ok(out)
}

fn inject(base: &str, key: &str, val: &str) -> String {
    if let Ok(mut u) = url::Url::parse(base) {
        u.query_pairs_mut().append_pair(key, val);
        u.to_string()
    } else {
        format!("{}?{}={}", base, key, val)
    }
}
