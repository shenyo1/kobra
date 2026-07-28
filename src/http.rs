use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use reqwest::Client;
use tokio::sync::Semaphore;

/// Shared HTTP client wrapper with cookie jar + configurable behavior.
pub struct HttpClient {
    pub client: Client,
    pub sem: Arc<Semaphore>,
    pub timeout: Duration,
    pub user_agent: String,
    pub extra_headers: Vec<(String, String)>,  // custom headers (auth tokens, etc.)
    pub cookie: Option<String>,                // custom cookie string
}

impl HttpClient {
    pub fn new(concurrency: usize, timeout_secs: u64) -> Result<Self> {
        let client = Client::builder()
            .cookie_store(true)
            .timeout(Duration::from_secs(timeout_secs))
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()?;
        Ok(HttpClient {
            client,
            sem: Arc::new(Semaphore::new(concurrency.max(1))),
            timeout: Duration::from_secs(timeout_secs),
            user_agent: "kobra/0.1 (all-in-one bb tool)".to_string(),
            extra_headers: Vec::new(),
            cookie: None,
        })
    }

    /// Apply auth headers (Authorization, Cookie, custom headers).
    pub fn apply_auth(&mut self, headers: Vec<(String, String)>, cookie: Option<String>) {
        self.extra_headers = headers;
        self.cookie = cookie;
    }

    /// Fetch a URL, return (status, headers, body, final_url).
    pub async fn fetch(
        &self,
        url: &str,
        method: reqwest::Method,
        body: Option<&str>,
        headers: Option<std::collections::HashMap<String, String>>,
    ) -> Result<(u16, String, String, String)> {
        let _permit = self.sem.acquire().await?;
        let mut req = self.client.request(method.clone(), url).header("User-Agent", &self.user_agent);

        // Apply custom auth headers
        for (k, v) in &self.extra_headers {
            req = req.header(k, v);
        }
        // Apply cookie
        if let Some(c) = &self.cookie {
            req = req.header("Cookie", c);
        }

        // Apply per-request headers
        if let Some(h) = headers {
            for (k, v) in h {
                req = req.header(&k, &v);
            }
        }
        if let Some(b) = body {
            req = req.header("Content-Type", "application/x-www-form-urlencoded").body(b.to_string());
        }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let final_url = resp.url().to_string();
        let mut header_str = String::new();
        for (k, v) in resp.headers().iter() {
            header_str.push_str(&format!("{}: {}\n", k.as_str(), v.to_str().unwrap_or("")));
        }
        let text = resp.text().await.unwrap_or_default();
        Ok((status, header_str, text, final_url))
    }

    pub async fn get(&self, url: &str) -> Result<(u16, String, String, String)> {
        self.fetch(url, reqwest::Method::GET, None, None).await
    }

    /// GET returning also a raw response string (headers + body) for report proof.
    pub async fn get_full(&self, url: &str) -> Result<(u16, String, String, String, String)> {
        let _permit = self.sem.acquire().await?;
        let mut req = self.client.get(url).header("User-Agent", &self.user_agent);
        for (k, v) in &self.extra_headers {
            req = req.header(k, v);
        }
        if let Some(c) = &self.cookie {
            req = req.header("Cookie", c);
        }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let final_url = resp.url().to_string();
        let mut header_str = String::new();
        for (k, v) in resp.headers().iter() {
            header_str.push_str(&format!("{}: {}\n", k.as_str(), v.to_str().unwrap_or("")));
        }
        let reason = resp.status().canonical_reason().unwrap_or("").to_string();
        let text = resp.text().await.unwrap_or_default();
        let raw = format!("HTTP/1.1 {} {}\n{}{}\n", status, reason, header_str, text);
        Ok((status, header_str, text, final_url, raw))
    }

    /// GET with a custom Origin header (for CORS testing).
    pub async fn get_with_origin(
        &self,
        url: &str,
        origin: &str,
    ) -> Result<(u16, String, String, String)> {
        let mut h = std::collections::HashMap::new();
        h.insert("Origin".to_string(), origin.to_string());
        self.fetch(url, reqwest::Method::GET, None, Some(h)).await
    }
}
