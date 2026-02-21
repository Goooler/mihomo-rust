pub mod dns_parser;
pub mod proxy_parser;
pub mod raw;
pub mod rule_parser;

use mihomo_common::{Proxy, Rule, TunnelMode};
use mihomo_dns::Resolver;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn};

pub struct Config {
    pub general: GeneralConfig,
    pub dns: DnsConfig,
    pub proxies: HashMap<String, Arc<dyn Proxy>>,
    pub rules: Vec<Box<dyn Rule>>,
    pub listeners: ListenerConfig,
    pub api: ApiConfig,
}

pub struct GeneralConfig {
    pub mode: TunnelMode,
    pub log_level: String,
    pub ipv6: bool,
    pub allow_lan: bool,
    pub bind_address: String,
}

pub struct DnsConfig {
    pub resolver: Arc<Resolver>,
    pub listen_addr: Option<SocketAddr>,
}

pub struct ListenerConfig {
    pub mixed_port: Option<u16>,
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    pub bind_address: String,
}

pub struct ApiConfig {
    pub external_controller: Option<SocketAddr>,
    pub secret: Option<String>,
}

pub fn load_config(path: &str) -> Result<Config, anyhow::Error> {
    let content = std::fs::read_to_string(path)?;
    load_config_from_str(&content)
}

pub fn load_config_from_str(content: &str) -> Result<Config, anyhow::Error> {
    let raw: raw::RawConfig = serde_yaml::from_str(content)?;
    build_config(raw)
}

fn build_config(raw: raw::RawConfig) -> Result<Config, anyhow::Error> {
    // General config
    let mode = raw
        .mode
        .as_deref()
        .unwrap_or("rule")
        .parse::<TunnelMode>()
        .unwrap_or(TunnelMode::Rule);
    let log_level = raw.log_level.clone().unwrap_or_else(|| "info".to_string());
    let bind_address = raw
        .bind_address
        .clone()
        .unwrap_or_else(|| "127.0.0.1".to_string());

    let general = GeneralConfig {
        mode,
        log_level,
        ipv6: raw.ipv6.unwrap_or(false),
        allow_lan: raw.allow_lan.unwrap_or(false),
        bind_address,
    };

    // DNS
    let dns_config = dns_parser::parse_dns(&raw)?;

    // Proxies
    let mut proxies: HashMap<String, Arc<dyn Proxy>> = HashMap::new();
    // Add built-in proxies
    let direct = Arc::new(proxy_parser::WrappedProxy::new(Box::new(
        mihomo_proxy::DirectAdapter::new(),
    )));
    let reject = Arc::new(proxy_parser::WrappedProxy::new(Box::new(
        mihomo_proxy::RejectAdapter::new(false),
    )));
    let reject_drop = Arc::new(proxy_parser::WrappedProxy::new(Box::new(
        mihomo_proxy::RejectAdapter::new(true),
    )));
    proxies.insert("DIRECT".to_string(), direct);
    proxies.insert("REJECT".to_string(), reject);
    proxies.insert("REJECT-DROP".to_string(), reject_drop);

    // Parse user proxies
    for raw_proxy in raw.proxies.unwrap_or_default() {
        match proxy_parser::parse_proxy(&raw_proxy) {
            Ok(proxy) => {
                let name = proxy.name().to_string();
                proxies.insert(name, proxy);
            }
            Err(e) => warn!("Failed to parse proxy: {}", e),
        }
    }

    // Parse proxy groups (after individual proxies are registered)
    for raw_group in raw.proxy_groups.unwrap_or_default() {
        match proxy_parser::parse_proxy_group(&raw_group, &proxies) {
            Ok(group) => {
                let name = group.name().to_string();
                proxies.insert(name, group);
            }
            Err(e) => warn!("Failed to parse proxy group: {}", e),
        }
    }

    // Rules
    let rules = rule_parser::parse_rules(&raw.rules.unwrap_or_default());

    // Listener config
    let bind_addr = if general.allow_lan {
        general.bind_address.clone()
    } else {
        "127.0.0.1".to_string()
    };
    let listeners = ListenerConfig {
        mixed_port: raw.mixed_port,
        socks_port: raw.socks_port,
        http_port: raw.port,
        bind_address: bind_addr,
    };

    // API config
    let api = ApiConfig {
        external_controller: raw
            .external_controller
            .as_deref()
            .and_then(|s| s.parse().ok()),
        secret: raw.secret,
    };

    info!(
        "Config loaded: mode={}, proxies={}, rules={}",
        mode,
        proxies.len(),
        rules.len()
    );

    Ok(Config {
        general,
        dns: dns_config,
        proxies,
        rules,
        listeners,
        api,
    })
}
