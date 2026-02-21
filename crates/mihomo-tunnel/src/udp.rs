use crate::tunnel::TunnelInner;
use dashmap::DashMap;
use mihomo_common::{DnsMode, Metadata, ProxyPacketConn};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// NAT table entry for UDP sessions
pub struct UdpSession {
    pub conn: Box<dyn ProxyPacketConn>,
    pub proxy_name: String,
}

pub type NatTable = Arc<DashMap<String, Arc<UdpSession>>>;

pub fn new_nat_table() -> NatTable {
    Arc::new(DashMap::new())
}

/// Handle a UDP packet: look up or create a NAT session
pub async fn handle_udp(
    tunnel: &TunnelInner,
    data: &[u8],
    src: SocketAddr,
    mut metadata: Metadata,
) {
    // Fix metadata for FakeIP
    if let Some(dst_ip) = metadata.dst_ip {
        if tunnel.resolver.is_fake_ip(dst_ip) {
            if let Some(host) = tunnel.resolver.fake_ip_reverse(dst_ip) {
                metadata.host = host;
                metadata.dns_mode = DnsMode::FakeIp;
            }
        }
    }

    let key = format!("{}:{}", src, metadata.remote_address());

    // Check if we have an existing session
    if let Some(session) = tunnel.nat_table.get(&key) {
        let dst_addr = metadata.remote_address();
        if let Ok(addr) = dst_addr.parse::<SocketAddr>() {
            if let Err(e) = session.conn.write_packet(data, &addr).await {
                debug!("UDP write error for {}: {}", key, e);
                tunnel.nat_table.remove(&key);
            }
        }
        return;
    }

    // New session: match rules and create proxy connection
    let (proxy, rule_name, rule_payload) = match tunnel.resolve_proxy(&metadata) {
        Some(v) => v,
        None => {
            warn!("no matching rule for UDP {}", metadata.remote_address());
            return;
        }
    };

    info!(
        "UDP {} --> {} match {}({}) using {}",
        metadata.source_address(),
        metadata.remote_address(),
        rule_name,
        rule_payload,
        proxy.name()
    );

    match proxy.dial_udp(&metadata).await {
        Ok(conn) => {
            let dst_addr = metadata.remote_address();
            if let Ok(addr) = dst_addr.parse::<SocketAddr>() {
                if let Err(e) = conn.write_packet(data, &addr).await {
                    warn!("UDP initial write error: {}", e);
                    return;
                }
            }
            let session = Arc::new(UdpSession {
                conn,
                proxy_name: proxy.name().to_string(),
            });
            tunnel.nat_table.insert(key, session);
        }
        Err(e) => {
            warn!("UDP dial error for {}: {}", metadata.remote_address(), e);
        }
    }
}
