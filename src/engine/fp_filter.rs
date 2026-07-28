//! Centralized False-Positive filter. Single source of truth for WAF/catch-all detection.
//! Modules call into here instead of duplicating CF/Kong/CloudFront checks.

/// Identified edge/frontend vendor from response headers + body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frontend {
    Cloudflare,
    Cloudfront,
    Fastly,
    Akamai,
    Imperva,
    Vercel,
    Netlify,
    Nginx,
    Apache,
    Kong,
    Unknown,
}

impl Frontend {
    pub fn as_str(&self) -> &'static str {
        match self {
            Frontend::Cloudflare => "cloudflare",
            Frontend::Cloudfront => "cloudfront",
            Frontend::Fastly => "fastly",
            Frontend::Akamai => "akamai",
            Frontend::Imperva => "imperva",
            Frontend::Vercel => "vercel",
            Frontend::Netlify => "netlify",
            Frontend::Nginx => "nginx",
            Frontend::Apache => "apache",
            Frontend::Kong => "kong",
            Frontend::Unknown => "unknown",
        }
    }
}

/// Detect frontend from headers (case-insensitive substring match).
pub fn detect_frontend(headers: &str) -> Frontend {
    let lower = headers.to_lowercase();
    if lower.contains("cf-ray") || lower.contains("server: cloudflare") {
        return Frontend::Cloudflare;
    }
    if lower.contains("x-amz-cf-id") || lower.contains("via: cloudfront") {
        return Frontend::Cloudfront;
    }
    if lower.contains("x-served-by: cache-") || lower.contains("fastly") {
        return Frontend::Fastly;
    }
    if lower.contains("x-akamai") || lower.contains("akamai") {
        return Frontend::Akamai;
    }
    if lower.contains("x-iinfo") || lower.contains("incapsula") {
        return Frontend::Imperva;
    }
    if lower.contains("x-vercel-id") || lower.contains("server: vercel") {
        return Frontend::Vercel;
    }
    if lower.contains("server: netlify") || lower.contains("x-nf-request-id") {
        return Frontend::Netlify;
    }
    if lower.contains("x-kong-") {
        return Frontend::Kong;
    }
    if lower.contains("server: nginx") {
        return Frontend::Nginx;
    }
    if lower.contains("server: apache") {
        return Frontend::Apache;
    }
    Frontend::Unknown
}

/// Detect a Cloudflare-style catch-all error page (returns 200/404 for any path).
/// True positive signals: cf-ray present in body + body contains "Just a moment"
/// or "ray id" or generic error wording.
pub fn is_cf_catchall(body: &str, headers: &str) -> bool {
    let lower_b = body.to_lowercase();
    let lower_h = headers.to_lowercase();
    let has_cf = lower_h.contains("cf-ray") || lower_h.contains("server: cloudflare");
    let cf_marker = lower_b.contains("just a moment")
        || lower_b.contains("ray id")
        || lower_b.contains("checking your browser")
        || lower_b.contains("attention required");
    has_cf && cf_marker
}

/// True if the response body is a Kong "no Route matched" stub.
pub fn is_kong_noroute(body: &str) -> bool {
    let lower = body.to_lowercase();
    lower.contains("no route matched")
        || (lower.contains("\"message\"") && lower.contains("not found"))
}

/// True if the response is a generic 404 with no real content (skip in reports).
pub fn is_generic_404(status: u16, body: &str) -> bool {
    status == 404 && body.len() < 200
}

/// True if the response is an obvious static / asset (skip XSS tests on .js/.css).
pub fn is_static_asset(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.ends_with(".js")
        || lower.ends_with(".css")
        || lower.ends_with(".png")
        || lower.ends_with(".jpg")
        || lower.ends_with(".jpeg")
        || lower.ends_with(".gif")
        || lower.ends_with(".svg")
        || lower.ends_with(".ico")
        || lower.ends_with(".woff")
        || lower.ends_with(".woff2")
        || lower.ends_with(".ttf")
        || lower.ends_with(".map")
}

/// Drop this finding if (status, body, headers) match a known FP pattern.
pub fn is_false_positive(status: u16, body: &str, headers: &str, path: &str) -> bool {
    if is_cf_catchall(body, headers) {
        return true;
    }
    if is_kong_noroute(body) {
        return true;
    }
    if is_generic_404(status, body) {
        return true;
    }
    if is_static_asset(path) && !body.contains("INJECTED") {
        // Plain asset responses with no injection marker are noise
        let lower = body.to_lowercase();
        if !lower.contains("error")
            && !lower.contains("warning")
            && !lower.contains("traceback")
            && !lower.contains("exception")
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detect_cf() {
        let h = "Server: cloudflare\nCF-RAY: 12345";
        assert_eq!(detect_frontend(h), Frontend::Cloudflare);
    }
    #[test]
    fn detect_kong_header() {
        let h = "X-Kong-Upstream-Latency: 5";
        assert_eq!(detect_frontend(h), Frontend::Kong);
    }
    #[test]
    fn detect_unknown() {
        assert_eq!(detect_frontend("Server: gunicorn/19.9.0"), Frontend::Unknown);
    }
    #[test]
    fn cf_catchall_positive() {
        let h = "cf-ray: 12345\nserver: cloudflare";
        let b = "Just a moment... ray id: 12345";
        assert!(is_cf_catchall(b, h));
    }
    #[test]
    fn cf_catchall_negative() {
        let h = "Server: nginx";
        let b = "real page";
        assert!(!is_cf_catchall(b, h));
    }
    #[test]
    fn kong_noroute_positive() {
        assert!(is_kong_noroute("{\"message\":\"no Route matched\"}"));
    }
    #[test]
    fn static_asset() {
        assert!(is_static_asset("/static/js/main.js"));
        assert!(is_static_asset("/a/b/image.PNG"));
        assert!(!is_static_asset("/api/users"));
    }
    #[test]
    fn fp_suppress_cf() {
        let h = "Server: cloudflare\nCF-RAY: x";
        let b = "Just a moment...";
        assert!(is_false_positive(403, b, h, "/admin"));
    }
    #[test]
    fn fp_keep_real_error() {
        let h = "Server: nginx";
        let b = "Traceback (most recent call last): File \"x.py\"";
        assert!(!is_false_positive(500, b, h, "/api/v1/users"));
    }
}
