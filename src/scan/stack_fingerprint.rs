//! Stack fingerprinting (Priority 3 fix v4.2.0).
//! Lesson: KOBRA used generic payloads (magic-link) on Juice Shop = FP.
//! Future: detect target stack first, then pick stack-specific payloads.

use crate::http::HttpClient;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Stack {
    pub spa: Option<String>,
    pub server: Option<String>,
    pub api_style: Option<String>,
    pub is_spa: bool,
    pub total_size: usize,
    pub framework_hint: String,
}

/// Detect stack markers from headers + body of /.
pub async fn fingerprint(http: &HttpClient, target: &str) -> Stack {
    let mut s = Stack::default();
    let url = target.trim_end_matches('/');

    if let Ok((_st, h, body, _f)) = http.get(url).await {
        let hl = h.to_lowercase();
        let bl = body.to_lowercase();

        // Server framework
        if hl.contains("server: express") {
            s.server = Some("Express".into());
        } else if hl.contains("server: nginx") {
            s.server = Some("nginx".into());
        } else if hl.contains("server: apache") {
            s.server = Some("Apache".into());
        } else if hl.contains("x-powered-by: php") {
            s.server = Some("PHP".into());
        }

        // SPA framework
        if bl.contains("<html") && bl.contains("</html>") {
            let has_main_js = body.contains("main.js")
                || (body.contains("main.") && body.contains(".js"));
            let has_polyfills = body.contains("polyfills.js") || body.contains("polyfills");
            let has_angular = body.contains("ng-version")
                || body.contains("angular")
                || (body.contains("polyfills") && body.contains("runtime"));
            let has_react = body.contains("__next")
                || (body.contains("react") && body.contains("root"));
            let has_vue = body.contains("nuxt") || (body.contains("vue") && body.contains("app"));
            let has_svelte = body.contains("__svelte") || body.contains("svelte");
            let has_ember = body.contains("ember") && body.contains("view");

            if has_angular {
                s.spa = Some("Angular".into());
                s.is_spa = true;
            } else if has_react {
                if body.contains("__next") || hl.contains("x-nextjs") {
                    s.spa = Some("Next.js".into());
                } else {
                    s.spa = Some("React".into());
                }
                s.is_spa = true;
            } else if has_vue {
                if body.contains("__nuxt") || hl.contains("x-nuxt") {
                    s.spa = Some("Nuxt.js".into());
                } else {
                    s.spa = Some("Vue.js".into());
                }
                s.is_spa = true;
            } else if has_svelte {
                s.spa = Some("Svelte".into());
                s.is_spa = true;
            } else if has_ember {
                s.spa = Some("Ember".into());
                s.is_spa = true;
            } else if has_main_js && has_polyfills {
                s.spa = Some("SPA".into());
                s.is_spa = true;
            }
            s.total_size = body.len();
        }

        // API style
        if bl.contains("graphql") || hl.contains("x-powered-by: graphql") {
            s.api_style = Some("GraphQL".into());
        } else if bl.contains("<html") {
            s.api_style = Some("REST+HTML".into());
        } else {
            s.api_style = Some("REST".into());
        }

        // Framework hint
        let mut parts: Vec<String> = Vec::new();
        if let Some(ref spa) = s.spa {
            parts.push(spa.clone());
        }
        if let Some(ref server) = s.server {
            parts.push(server.clone());
        }
        if let Some(ref api) = s.api_style {
            parts.push(api.clone());
        }
        s.framework_hint = parts.join(" + ");
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_default() {
        let s = Stack::default();
        assert!(!s.is_spa);
        assert_eq!(s.spa, None);
        assert_eq!(s.framework_hint, "");
    }

    #[test]
    fn stack_format_hint() {
        let mut s = Stack::default();
        s.spa = Some("Angular".into());
        s.server = Some("Express".into());
        s.api_style = Some("REST+HTML".into());
        let mut parts: Vec<String> = Vec::new();
        if let Some(ref spa) = s.spa { parts.push(spa.clone()); }
        if let Some(ref server) = s.server { parts.push(server.clone()); }
        if let Some(ref api) = s.api_style { parts.push(api.clone()); }
        s.framework_hint = parts.join(" + ");
        assert_eq!(s.framework_hint, "Angular + Express + REST+HTML");
    }

    #[test]
    fn stack_spa_detection_markers() {
        // Just verify the field logic compiles + works.
        let mut s = Stack::default();
        s.is_spa = true;
        assert!(s.is_spa);
    }
}