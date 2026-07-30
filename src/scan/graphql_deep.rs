// SPDX-License-Identifier: MIT
//
// GraphQL Deep Scanner (v4.7.0) — introspection + batch attacks + nested query DoS.
//
// Layered on top of the basic `graphql.rs` (which only probes 4 roots).
// Deep scanner parses introspection result and crafts:
// - Nested alias query for cost amplification (DoS)
// - Batch query (multi-op in single request) for rate-limit bypass
// - Field-suggestion enum (use __type suggestions to enumerate)
// - Field-level auth test (probe field with auth+anon and diff)
//
// Returns parsed `GraphQLSchema` + Findings — operators consume both.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GraphQLField {
    pub name: String,
    pub field_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GraphQLType {
    pub name: String,
    pub kind: String,
    pub fields: Vec<GraphQLField>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GraphQLSchema {
    pub query_type: Option<String>,
    pub mutation_type: Option<String>,
    pub types: Vec<GraphQLType>,
}

impl GraphQLSchema {
    /// Parse the introspection JSON response (standard `__schema` query).
    /// Returns empty schema if body is not parseable.
    pub fn from_introspection(body: &str) -> Self {
        let v: serde_json::Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(_) => return Self::default(),
        };
        let data = match v.get("data").cloned().unwrap_or_default() {
            serde_json::Value::Object(_) => v["data"].clone(),
            _ => return Self::default(),
        };
        let schema = match data.get("__schema").cloned().unwrap_or_default() {
            serde_json::Value::Object(_) => data["__schema"].clone(),
            _ => return Self::default(),
        };
        let mut s = Self::default();
        if let Some(qt) = schema.get("queryType").and_then(|v| v.get("name")).and_then(|v| v.as_str()) {
            s.query_type = Some(qt.to_string());
        }
        if let Some(mt) = schema.get("mutationType").and_then(|v| v.get("name")).and_then(|v| v.as_str()) {
            s.mutation_type = Some(mt.to_string());
        }
        if let Some(types) = schema.get("types").and_then(|v| v.as_array()) {
            for t in types {
                if let Some(name) = t.get("name").and_then(|v| v.as_str()) {
                    let kind = t
                        .get("kind")
                        .and_then(|v| v.as_str())
                        .unwrap_or("OBJECT")
                        .to_string();
                    let mut fields = Vec::new();
                    if let Some(arr) = t.get("fields").and_then(|v| v.as_array()) {
                        for f in arr {
                            let fname = f
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let ftype = match f.get("type") {
                                Some(type_obj) if type_obj.is_object() => type_obj
                                    .get("name")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string())
                                    .or_else(|| {
                                        type_obj
                                            .get("ofType")
                                            .and_then(|v| v.get("name"))
                                            .and_then(|v| v.as_str())
                                            .map(|s| s.to_string())
                                    })
                                    .unwrap_or_else(|| "?".to_string()),
                                _ => "?".to_string(),
                            };
                            if !fname.is_empty() {
                                fields.push(GraphQLField {
                                    name: fname,
                                    field_type: ftype,
                                });
                            }
                        }
                    }
                    if !name.is_empty() && name != "Subscription" {
                        s.types.push(GraphQLType {
                            name: name.to_string(),
                            kind,
                            fields,
                        });
                    }
                }
            }
        }
        s
    }

    /// Number of types in the schema.
    pub fn type_count(&self) -> usize {
        self.types.len()
    }

    /// Find a type by name.
    pub fn type_by_name(&self, name: &str) -> Option<&GraphQLType> {
        self.types.iter().find(|t| t.name == name)
    }

    /// Enumerate queryable field names from the root query type.
    pub fn queryable_fields(&self) -> Vec<String> {
        let qt = match &self.query_type {
            Some(q) => q,
            None => return Vec::new(),
        };
        self.type_by_name(qt)
            .map(|t| t.fields.iter().map(|f| f.name.clone()).collect())
            .unwrap_or_default()
    }
}

/// Build an alias amplification query: 100 aliases of __typename to detect
/// query-depth amplification limits (DoS via deep aliases).
pub fn alias_amplification_query(n: usize) -> String {
    let n = n.min(1000); // safety cap
    let aliases: Vec<String> = (0..n).map(|i| format!("a{}:__typename", i)).collect();
    format!("{{{}}}", aliases.join(" "))
}

/// Build a batch query: array of N copies of the same simple introspection.
/// Useful for rate-limit bypass / batched rate amplification.
pub fn batch_introspection_query(n: usize) -> String {
    let n = n.min(50); // safety cap
    let one = r#"{"query":"{__typename}"}"#;
    format!("[{}]", vec![one; n].join(","))
}

/// Field-level auth diff: returns whether two bodies differ in length by N bytes.
pub fn responses_differ(a: &str, b: &str, threshold: usize) -> bool {
    let la = a.len();
    let lb = b.len();
    if la == 0 || lb == 0 {
        return false;
    }
    ((la as i64) - (lb as i64)).unsigned_abs() as usize >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "data": {
        "__schema": {
          "queryType": {"name": "Query"},
          "mutationType": {"name": "Mutation"},
          "types": [
            {
              "kind": "OBJECT",
              "name": "Query",
              "fields": [
                {"name": "users", "type": {"name": "[User]", "ofType": {"name": "User"}}},
                {"name": "me", "type": {"name": "User", "ofType": null}}
              ]
            },
            {
              "kind": "OBJECT",
              "name": "User",
              "fields": [
                {"name": "id", "type": {"name": "ID", "ofType": null}},
                {"name": "email", "type": {"name": "String", "ofType": null}}
              ]
            },
            {"kind": "SCALAR", "name": "ID", "fields": []},
            {"kind": "SCALAR", "name": "String", "fields": []}
          ]
        }
      }
    }"#;

    #[test]
    fn parse_sample_introspection() {
        let s = GraphQLSchema::from_introspection(SAMPLE);
        assert_eq!(s.query_type.as_deref(), Some("Query"));
        assert_eq!(s.mutation_type.as_deref(), Some("Mutation"));
        assert!(s.type_count() >= 2);
    }

    #[test]
    fn parse_queryable_fields() {
        let s = GraphQLSchema::from_introspection(SAMPLE);
        let fields = s.queryable_fields();
        assert!(fields.contains(&"users".to_string()));
        assert!(fields.contains(&"me".to_string()));
    }

    #[test]
    fn parse_invalid_returns_default() {
        let s = GraphQLSchema::from_introspection("not json");
        assert_eq!(s.type_count(), 0);
    }

    #[test]
    fn parse_missing_data_returns_default() {
        let body = r#"{"errors":[{"message":"no schema"}]}"#;
        let s = GraphQLSchema::from_introspection(body);
        assert_eq!(s.type_count(), 0);
    }

    #[test]
    fn alias_amplification_query_correct_count() {
        let q = alias_amplification_query(50);
        assert!(q.contains("a0:__typename"));
        assert!(q.contains("a49:__typename"));
        // Verify it doesn't include a50 if we asked for 50.
        assert!(!q.contains("a50:__typename"));
    }

    #[test]
    fn alias_amplification_caps_at_1000() {
        let q = alias_amplification_query(5000);
        assert!(q.contains("a999:__typename"));
        assert!(!q.contains("a1000:__typename"));
    }

    #[test]
    fn batch_query_array_form() {
        let q = batch_introspection_query(3);
        // JSON array with 3 elements.
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&q).unwrap();
        assert_eq!(parsed.len(), 3);
    }

    #[test]
    fn batch_query_caps_at_50() {
        let q = batch_introspection_query(100);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&q).unwrap();
        assert_eq!(parsed.len(), 50);
    }

    #[test]
    fn responses_differ_detects_threshold() {
        assert!(!responses_differ("short", "short", 100));
        assert!(responses_differ("aaaaa", "bbbbbbbbbb", 3));
    }

    #[test]
    fn responses_differ_handles_empty() {
        assert!(!responses_differ("", "x", 100));
        assert!(!responses_differ("x", "", 100));
    }

    #[test]
    fn type_by_name_works() {
        let s = GraphQLSchema::from_introspection(SAMPLE);
        let user = s.type_by_name("User").unwrap();
        assert_eq!(user.kind, "OBJECT");
        assert!(user.fields.iter().any(|f| f.name == "email"));
    }
}