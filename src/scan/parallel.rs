//! Multi-target parallel scanning with shared rate-limit budget.
//! Pools targets, dispatches to N concurrent workers.

use crate::types::Finding;
use crate::engine::rate_limit::{new_limiter, wait_ms};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

pub struct ParallelConfig {
    pub max_concurrent: usize,
    pub delay_between: Duration,
    pub rotate_ua: bool,
}

impl Default for ParallelConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 5,
            delay_between: Duration::from_millis(200),
            rotate_ua: true,
        }
    }
}

pub async fn scan_targets<F, Fut>(
    targets: Vec<String>,
    config: ParallelConfig,
    on_target: F,
) -> Vec<Finding>
where
    F: Fn(String) -> Fut + Send + Sync + Clone + 'static,
    Fut: std::future::Future<Output = Vec<Finding>> + Send + 'static,
{
    let mut all = Vec::new();
    let limiter = new_limiter();
    let sem = Arc::new(tokio::sync::Semaphore::new(config.max_concurrent));
    let on_target = Arc::new(on_target);

    let mut tasks = Vec::new();
    for t in targets {
        let sem = sem.clone();
        let limiter = limiter.clone();
        let on_target = on_target.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let d = wait_ms(&limiter, &t);
            if d > 0 {
                sleep(Duration::from_millis(d)).await;
            }
            Some(on_target(t).await)
        }));
    }
    for t in tasks {
        if let Ok(Some(f)) = t.await {
            all.extend(f);
        }
    }
    all
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_config_sane() {
        let c = ParallelConfig::default();
        assert!(c.max_concurrent > 0);
        assert!(c.delay_between.as_millis() < 5000);
    }
    #[test]
    fn wait_ms_returns_zero_for_unknown_host() {
        let rl = new_limiter();
        assert_eq!(wait_ms(&rl, "https://new.com/"), 0);
    }
}
