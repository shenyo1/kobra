//! API Schema Fuzzing — auto-discover OpenAPI/Swagger specs and generate
//! test cases from the schema. Tests every endpoint + param + type.

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use serde_json::Value;

/// Discovered API schema
#[derive(Debug, Default)]
pub struct ApiSchema {
    pub spec_url: String,
    pub title: String,
    pub version: String,
    pub endpoints: Vec<ApiEndpoint>,
}

#[derive(Debug, Clone)]
pub struct ApiEndpoint {
    pub method: String,
    pub path: String,
    pub params: Vec<ApiParam>,
    pub has_auth: bool,
}

#[derive(Debug, Clone)]
pub struct ApiParam {
    pub name: String,
    pub location: String, // query, path, header, body
    pub param_type: String, // string, integer, boolean, array, object
    pub required: bool,
}

/// Common OpenAPI/Swagger spec locations
const SPEC_PATHS: &[&str] = &[
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/api-docs",
    "/api/docs",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/v3/openapi.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/docs/openapi.json",
    "/.well-known/openapi.json",
    "/apidocs/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
];

/// Main scan: discover spec → parse → generate tests → execute
pub async fn scan(http: &HttpClient, target: &str, mode: Mode) -> Vec<Finding> {
    let mut findings = Vec::new();
    let base = target.trim_end_matches('/');

    // Phase 1: Discover OpenAPI spec
    let schema = match discover_spec(http, base).await {
        Some(s) => s,
        None => return findings,
    };

    findings.push(
        Finding::new(Severity::Medium, "API-SCHEMA", &format!("OpenAPI spec found: {} ({})", schema.title, schema.version), target)
            .with_evidence(&schema.spec_url)
            .with_note(&format!("{} endpoints discovered", schema.endpoints.len()))
            .with_confidence(90),
    );

    // Phase 2: Test each endpoint
    let limit = match mode {
        Mode::Stealth => 5,
        Mode::Normal => 15,
        Mode::Crazy => schema.endpoints.len(),
    };

    for ep in schema.endpoints.iter().take(limit) {
        let ep_findings = test_endpoint(http, base, ep).await;
        findings.extend(ep_findings);
    }

    findings
}

/// Discover OpenAPI/Swagger spec
async fn discover_spec(http: &HttpClient, base: &str) -> Option<ApiSchema> {
    for path in SPEC_PATHS {
        let url = format!("{}{}", base, path);
        if let Ok((st, _h, body, _f)) = http.get(&url).await {
            if st == 200 && body.len() > 50 {
                // Try JSON parse
                if let Ok(json) = serde_json::from_str::<Value>(&body) {
                    if json.get("openapi").is_some() || json.get("swagger").is_some() {
                        return Some(parse_openapi(&json, &url));
                    }
                }
                // Try YAML (basic check)
                if body.contains("openapi:") || body.contains("swagger:") {
                    return Some(ApiSchema {
                        spec_url: url,
                        title: "YAML spec (unparsed)".to_string(),
                        version: "unknown".to_string(),
                        endpoints: vec![],
                    });
                }
            }
        }
    }
    None
}

/// Parse OpenAPI 3.x / Swagger 2.x JSON into ApiSchema
fn parse_openapi(json: &Value, spec_url: &str) -> ApiSchema {
    let mut schema = ApiSchema {
        spec_url: spec_url.to_string(),
        title: json["info"]["title"].as_str().unwrap_or("Unknown API").to_string(),
        version: json["info"]["version"].as_str().unwrap_or("0.0").to_string(),
        endpoints: Vec::new(),
    };

    // OpenAPI 3.x: paths object
    if let Some(paths) = json["paths"].as_object() {
        for (path, methods) in paths {
            if let Some(methods_obj) = methods.as_object() {
                for (method, details) in methods_obj {
                    let method_upper = method.to_uppercase();
                    if !["GET", "POST", "PUT", "DELETE", "PATCH"].contains(&method_upper.as_str()) {
                        continue;
                    }

                    let mut params = Vec::new();

                    // Path/query/header parameters
                    if let Some(param_arr) = details["parameters"].as_array() {
                        for p in param_arr {
                            params.push(ApiParam {
                                name: p["name"].as_str().unwrap_or("").to_string(),
                                location: p["in"].as_str().unwrap_or("query").to_string(),
                                param_type: p["schema"]["type"].as_str().unwrap_or("string").to_string(),
                                required: p["required"].as_bool().unwrap_or(false),
                            });
                        }
                    }

                    // Request body (OpenAPI 3.x)
                    if let Some(body_schema) = details["requestBody"]["content"]["application/json"]["schema"].as_object() {
                        if let Some(props) = body_schema["properties"].as_object() {
                            let required_fields: Vec<String> = body_schema["required"]
                                .as_array()
                                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                                .unwrap_or_default();

                            for (name, prop) in props {
                                params.push(ApiParam {
                                    name: name.clone(),
                                    location: "body".to_string(),
                                    param_type: prop["type"].as_str().unwrap_or("string").to_string(),
                                    required: required_fields.contains(name),
                                });
                            }
                        }
                    }

                    // Check if auth required
                    let has_auth = details["security"].as_array().map(|a| !a.is_empty()).unwrap_or(false)
                        || json["components"]["securitySchemes"].as_object().map(|s| !s.is_empty()).unwrap_or(false);

                    schema.endpoints.push(ApiEndpoint {
                        method: method_upper,
                        path: path.clone(),
                        params,
                        has_auth,
                    });
                }
            }
        }
    }

    schema
}

/// Test a single endpoint for common issues
async fn test_endpoint(http: &HttpClient, base: &str, ep: &ApiEndpoint) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Build URL with path params replaced
    let mut url_path = ep.path.clone();
    for p in &ep.params {
        if p.location == "path" {
            url_path = url_path.replace(&format!("{{{}}}", p.name), "1");
        }
    }
    let url = format!("{}{}", base, url_path);

    // Test 1: Unauthenticated access
    if ep.has_auth {
        if let Ok((st, _h, body, _f)) = http.get(&url).await {
            if st == 200 && body.len() > 10 && !body.contains("error") && !body.contains("unauthorized") {
                findings.push(
                    Finding::new(Severity::High, "API-SCHEMA", &format!("Unauthenticated access: {} {}", ep.method, ep.path), &url)
                        .with_evidence(&format!("HTTP 200 without auth on protected endpoint ({} bytes)", body.len()))
                        .with_note("Endpoint marked as requiring auth but returns 200 without credentials")
                        .with_confidence(70),
                );
            }
        }
    }

    // Test 2: Method not allowed → try other methods
    if ep.method == "GET" {
        for alt_method in &["POST", "PUT", "DELETE"] {
            if let Ok((st, _h, _b, _f)) = http.fetch(&url, alt_method.parse().unwrap_or(reqwest::Method::POST), None, None).await {
                if st == 200 {
                    findings.push(
                        Finding::new(Severity::Low, "API-SCHEMA", &format!("{} {} also accepts {}", ep.method, ep.path, alt_method), &url)
                            .with_evidence(&format!("HTTP 200 on {} (documented as GET only)", alt_method))
                            .with_confidence(50),
                    );
                }
            }
        }
    }

    // Test 3: Type confusion on params
    for p in ep.params.iter().filter(|p| p.location == "query") {
        let test_val = match p.param_type.as_str() {
            "integer" => "string_not_int",
            "boolean" => "not_a_bool",
            "array" => "single_value",
            _ => continue,
        };
        let test_url = format!("{}?{}={}", url, p.name, test_val);
        if let Ok((st, _h, body, _f)) = http.get(&test_url).await {
            if st == 500 {
                findings.push(
                    Finding::new(Severity::Medium, "API-SCHEMA", &format!("Type confusion crash: {} param {}", ep.path, p.name), &test_url)
                        .with_evidence(&format!("HTTP 500 when sending {} to {} param (expected {})", test_val, p.name, p.param_type))
                        .with_note("Server crashes on invalid type — missing input validation")
                        .with_confidence(75),
                );
            } else if st == 200 && body.contains("error") {
                findings.push(
                    Finding::new(Severity::Low, "API-SCHEMA", &format!("Verbose error: {} param {}", ep.path, p.name), &test_url)
                        .with_evidence(&format!("Error message leaked on type mismatch"))
                        .with_confidence(55),
                );
            }
        }
    }

    // Test 4: SQLi on string params
    for p in ep.params.iter().filter(|p| p.location == "query" && p.param_type == "string") {
        let sqli_url = format!("{}?{}=' OR '1'='1", url, p.name);
        if let Ok((st, _h, body, _f)) = http.get(&sqli_url).await {
            let body_lower = body.to_lowercase();
            if body_lower.contains("sql") || body_lower.contains("syntax") || body_lower.contains("mysql") || body_lower.contains("postgres") {
                findings.push(
                    Finding::new(Severity::Critical, "API-SCHEMA", &format!("SQLi via schema param: {} → {}", ep.path, p.name), &sqli_url)
                        .with_evidence("SQL error in response to quote injection")
                        .with_confidence(80),
                );
            }
            let _ = st;
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_openapi_basic() {
        let json: Value = serde_json::json!({
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0"},
            "paths": {
                "/users": {
                    "get": {
                        "parameters": [
                            {"name": "limit", "in": "query", "schema": {"type": "integer"}, "required": false}
                        ],
                        "security": [{"bearerAuth": []}]
                    },
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": {"type": "string"},
                                            "email": {"type": "string"}
                                        },
                                        "required": ["name"]
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "securitySchemes": {
                    "bearerAuth": {"type": "http", "scheme": "bearer"}
                }
            }
        });

        let schema = parse_openapi(&json, "https://a.com/openapi.json");
        assert_eq!(schema.title, "Test API");
        assert_eq!(schema.endpoints.len(), 2);

        let get_ep = &schema.endpoints[0];
        assert_eq!(get_ep.method, "GET");
        assert_eq!(get_ep.path, "/users");
        assert!(get_ep.has_auth);
        assert_eq!(get_ep.params.len(), 1);
        assert_eq!(get_ep.params[0].name, "limit");

        let post_ep = &schema.endpoints[1];
        assert_eq!(post_ep.method, "POST");
        assert_eq!(post_ep.params.len(), 2);
        assert!(post_ep.params.iter().any(|p| p.name == "name" && p.required));
    }

    #[test]
    fn parse_empty_spec() {
        let json: Value = serde_json::json!({"openapi": "3.0.0", "info": {"title": "Empty", "version": "0.1"}});
        let schema = parse_openapi(&json, "https://a.com/openapi.json");
        assert_eq!(schema.endpoints.len(), 0);
    }

    #[test]
    fn spec_paths_non_empty() {
        assert!(SPEC_PATHS.len() >= 10);
    }

    #[test]
    fn parse_swagger2() {
        let json: Value = serde_json::json!({
            "swagger": "2.0",
            "info": {"title": "Swagger 2", "version": "2.0"},
            "paths": {
                "/pets": {
                    "get": {
                        "parameters": [
                            {"name": "status", "in": "query", "type": "string"}
                        ]
                    }
                }
            }
        });
        let schema = parse_openapi(&json, "https://a.com/swagger.json");
        assert_eq!(schema.endpoints.len(), 1);
    }
}
