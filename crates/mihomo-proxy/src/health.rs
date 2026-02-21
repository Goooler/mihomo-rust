use mihomo_common::{DelayHistory, ProxyAdapter, ProxyState};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};
use tracing::{debug, warn};

pub struct ProxyHealth {
    alive: AtomicBool,
    history: RwLock<Vec<DelayHistory>>,
    max_history: usize,
}

impl ProxyHealth {
    pub fn new() -> Self {
        Self {
            alive: AtomicBool::new(true),
            history: RwLock::new(Vec::new()),
            max_history: 10,
        }
    }

    pub fn alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    pub fn set_alive(&self, alive: bool) {
        self.alive.store(alive, Ordering::Relaxed);
    }

    pub fn last_delay(&self) -> u16 {
        self.history.read().last().map(|h| h.delay).unwrap_or(0)
    }

    pub fn delay_history(&self) -> Vec<DelayHistory> {
        self.history.read().clone()
    }

    pub fn record_delay(&self, delay: u16) {
        let mut history = self.history.write();
        history.push(DelayHistory {
            time: SystemTime::now(),
            delay,
        });
        if history.len() > self.max_history {
            history.remove(0);
        }
        self.alive.store(delay > 0, Ordering::Relaxed);
    }

    pub fn state(&self) -> ProxyState {
        ProxyState {
            alive: self.alive(),
            history: self.delay_history(),
        }
    }
}

impl Default for ProxyHealth {
    fn default() -> Self {
        Self::new()
    }
}

/// Test a proxy by making an HTTP GET request and measuring round-trip time
pub async fn url_test(adapter: &dyn ProxyAdapter, url: &str, timeout: Duration) -> u16 {
    let start = Instant::now();
    let metadata = mihomo_common::Metadata {
        network: mihomo_common::Network::Tcp,
        host: extract_host(url),
        dst_port: extract_port(url),
        ..Default::default()
    };

    let result = tokio::time::timeout(timeout, async {
        let _conn = adapter.dial_tcp(&metadata).await?;
        // For a simple URL test, just establishing the connection is enough
        // A full implementation would send an HTTP request
        Ok::<_, mihomo_common::MihomoError>(())
    })
    .await;

    match result {
        Ok(Ok(())) => {
            let delay = start.elapsed().as_millis() as u16;
            debug!("{} URL test: {}ms", adapter.name(), delay);
            delay
        }
        _ => {
            warn!("{} URL test failed", adapter.name());
            0
        }
    }
}

fn extract_host(url: &str) -> String {
    let url = url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let host = url.split('/').next().unwrap_or(url);
    let host = host.split(':').next().unwrap_or(host);
    host.to_string()
}

fn extract_port(url: &str) -> u16 {
    if url.starts_with("https://") {
        443
    } else {
        80
    }
}
