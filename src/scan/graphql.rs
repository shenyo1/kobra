use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;
use std::collections::HashMap;

/// GraphQL scanner: introspection exposure + bypass techniques + batch IDOR hint.
pub async fn scan(http: &HttpClient, target: &str, _mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let roots = vec![
        format!("{}/graphql", target.trim_end_matches('/')),
        format!("{}/api/graphql", target.trim_end_matches('/')),
        format!("{}/v1/graphql", target.trim_end_matches('/')),
        format!("{}/api/v2/graphql", target.trim_end_matches('/')),
    ];

    // (label, query body, optional header)
    let probes: Vec<(&str, &str, Option<(&str, &str)>)> = vec![
        ("introspection __schema", r#"{"query":"{__schema{types{name}}}"}"#, None),
        ("introspection __type", r#"{"query":"{__type(name:\"User\"){fields{name}}}"}"#, None),
        ("introspection X-Introspection header", r#"{"query":"{__schema{types{name}}}"}"#, Some(("X-Introspection", "enabled"))),
        ("introspection GET method", "{__schema{types{name}}}", None),
    ];

    for url in roots {
        for (label, qbody, hdr) in &probes {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            if let Some((k, v)) = hdr {
                headers.insert(k.to_string(), v.to_string());
            }
            // POST
            if let Ok((st, _h, resp, _f)) = http.fetch(&url, reqwest::Method::POST, Some(qbody), Some(headers.clone())).await {
                check_graphql(&mut out, &url, label, st, &resp);
            }
            // GET (for the GET-method probe)
            if label.contains("GET method") {
                let get_url = format!("{}?query={}", url, urlencoding(qbody));
                if let Ok((st, _h, resp, _f)) = http.get(&get_url).await {
                    check_graphql(&mut out, &url, label, st, &resp);
                }
            }
        }
    }
    Ok(out)
}

fn check_graphql(out: &mut Vec<Finding>, url: &str, label: &str, st: u16, resp: &str) {
    let rl = resp.to_lowercase();
    if st == 200 && (rl.contains("\"types\"") || rl.contains("\"name\"") && rl.contains("querytype") || rl.contains("\"kind\"")) {
        out.push(Finding::new(Severity::Medium, "GRAPHQL", "GraphQL introspection exposed (schema leak)", url)
            .with_payload(label)
            .with_evidence("introspection returned schema")
            .with_confidence(88));
    } else if st == 200 && rl.contains("errors") {
        out.push(Finding::new(Severity::Low, "GRAPHQL", "GraphQL endpoint responds (error info leak)", url)
            .with_evidence("error message returned")
            .with_confidence(50));
    }
}

fn urlencoding(s: &str) -> String {
    s.chars().map(|c| match c {
        '{' => "%7B".to_string(),
        '}' => "%7D".to_string(),
        '"' => "%22".to_string(),
        ' ' => "%20".to_string(),
        ':' => "%3A".to_string(),
        ',' => "%2C".to_string(),
        _ => c.to_string(),
    }).collect()
}
