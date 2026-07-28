use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;
use std::collections::HashMap;

/// Insecure deserialization probes (error-based, non-destructive).
/// Sends crafted serialized blobs; flags language by error signatures returned.
pub async fn scan(http: &HttpClient, target: &str, _mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let url = target.trim_end_matches('/').to_string();

    // (label, content-type, raw bytes, error signatures)
    let probes: Vec<(&str, &str, Vec<u8>, &[&str])> = vec![
        ("Java", "application/x-java-serialized-object",
         vec![0xac, 0xed, 0x00, 0x05], &["java.io", "NotSerializableException", "ObjectInputStream", "InvalidClassException"]),
        ("PHP", "application/x-www-form-urlencoded",
         b"O:4:\"test\":0:{}".to_vec(), &["unserialize", "Incomplete Class", "Illegal offset"]),
        ("Python pickle", "application/octet-stream",
         b"c__builtin__\nexec\n(S'x'\ntR.".to_vec(), &["pickle", "UnpicklingError", "could not find MARK"]),
        (".NET", "application/octet-stream",
         vec![0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00],
         &["BinaryFormatter", "SerializationException", "EndOfStreamException"]),
    ];

    for (label, ct, body, sigs) in probes {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".into(), ct.into());
        let body_str = String::from_utf8_lossy(&body);
        if let Ok((_st, _h, resp, _f)) = http.fetch(&url, reqwest::Method::POST, Some(&body_str), Some(headers)).await {
            let lb = resp.to_lowercase();
            if sigs.iter().any(|s| lb.contains(&s.to_lowercase())) {
                out.push(Finding::new(Severity::Medium, "DESER", "Insecure deserialization (error-based)", target)
                    .with_payload(label)
                    .with_evidence("deserialization error leaked framework/language")
                    .with_confidence(70));
            }
        }
    }
    Ok(out)
}
