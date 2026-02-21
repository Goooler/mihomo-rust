use crate::tun_conn::TunTcpConn;
use futures::{SinkExt, StreamExt};
use mihomo_common::{ConnType, Metadata, Network};
use mihomo_dns::{DnsServer, Resolver};
use mihomo_tunnel::Tunnel;
use netstack_smoltcp::StackBuilder;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tracing::{debug, error, info};

/// Configuration for the TUN listener, passed from the config layer.
pub struct TunListenerConfig {
    pub device: Option<String>,
    pub mtu: u16,
    pub inet4_address: String,
    pub dns_hijack: Vec<SocketAddr>,
}

/// TUN listener that creates a virtual network interface and processes
/// captured IP traffic through the tunnel's proxy routing engine.
///
/// Uses `netstack-smoltcp` for user-space TCP/IP reassembly to avoid
/// TCP-over-TCP performance issues.
pub struct TunListener {
    tunnel: Tunnel,
    config: TunListenerConfig,
    resolver: Arc<Resolver>,
}

impl TunListener {
    pub fn new(tunnel: Tunnel, config: TunListenerConfig, resolver: Arc<Resolver>) -> Self {
        Self {
            tunnel,
            config,
            resolver,
        }
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Parse the inet4 address from CIDR notation (e.g., "198.18.0.1/16")
        let (ip_str, prefix) = parse_cidr(&self.config.inet4_address)?;
        let ip: Ipv4Addr = ip_str.parse()?;

        // Build the TUN device
        let mut builder = tun_rs::DeviceBuilder::new()
            .mtu(self.config.mtu)
            .ipv4(ip, prefix, None);

        if let Some(ref name) = self.config.device {
            builder = builder.name(name.as_str());
        }

        let device = Arc::new(builder.build_async()?);
        info!(
            "TUN device created: addr={}/{}, mtu={}",
            ip, prefix, self.config.mtu
        );

        // Build the netstack-smoltcp stack
        let (stack, tcp_runner, udp_socket, tcp_listener) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .build()?;

        let tcp_runner = tcp_runner.ok_or("TCP runner not created")?;
        let udp_socket = udp_socket.ok_or("UDP socket not created")?;
        let tcp_listener = tcp_listener.ok_or("TCP listener not created")?;

        // Spawn the TCP runner (drives the smoltcp TCP interface/socket state machine)
        tokio::spawn(async move {
            if let Err(e) = tcp_runner.await {
                error!("TCP runner error: {}", e);
            }
        });

        // Bidirectional packet relay: TUN device ↔ netstack
        let device_relay = device.clone();
        tokio::spawn(async move {
            relay_packets(device_relay, stack).await;
        });

        // TCP acceptor: receive reassembled TCP streams from netstack
        let tunnel_tcp = self.tunnel.clone();
        let mut tcp_listener = tcp_listener;
        tokio::spawn(async move {
            while let Some((stream, _local_addr, remote_addr)) = tcp_listener.next().await {
                let src_addr = *stream.local_addr();

                let metadata = Metadata {
                    network: Network::Tcp,
                    conn_type: ConnType::Tun,
                    src_ip: Some(src_addr.ip()),
                    dst_ip: Some(remote_addr.ip()),
                    src_port: src_addr.port(),
                    dst_port: remote_addr.port(),
                    ..Default::default()
                };

                let conn = Box::new(TunTcpConn::new(stream, remote_addr));
                let tunnel = tunnel_tcp.clone();
                tokio::spawn(async move {
                    mihomo_tunnel::tcp::handle_tcp(tunnel.inner(), conn, metadata).await;
                });
            }
        });

        // UDP handler with DNS hijack support
        let tunnel_udp = self.tunnel.clone();
        let dns_hijack_addrs = self.config.dns_hijack.clone();
        let resolver = self.resolver.clone();
        let (mut udp_read, mut udp_write) = udp_socket.split();

        tokio::spawn(async move {
            while let Some((payload, src_addr, dst_addr)) = udp_read.next().await {
                // Check if this packet targets a DNS hijack address
                if dns_hijack_addrs.contains(&dst_addr) {
                    match DnsServer::handle_query(&payload, &resolver).await {
                        Ok(response) => {
                            // Send DNS response back via netstack (swap src/dst)
                            let reply: netstack_smoltcp::udp::UdpMsg =
                                (response, dst_addr, src_addr);
                            if let Err(e) = udp_write.send(reply).await {
                                debug!("DNS hijack reply error: {}", e);
                            }
                        }
                        Err(e) => {
                            debug!("DNS hijack query error: {}", e);
                        }
                    }
                    continue;
                }

                // Regular UDP traffic: forward through tunnel
                let metadata = Metadata {
                    network: Network::Udp,
                    conn_type: ConnType::Tun,
                    src_ip: Some(src_addr.ip()),
                    dst_ip: Some(dst_addr.ip()),
                    src_port: src_addr.port(),
                    dst_port: dst_addr.port(),
                    ..Default::default()
                };

                let tunnel = tunnel_udp.clone();
                tokio::spawn(async move {
                    mihomo_tunnel::udp::handle_udp(tunnel.inner(), &payload, src_addr, metadata)
                        .await;
                });
            }
        });

        info!("TUN listener running");

        // Keep alive — caller manages shutdown
        std::future::pending::<()>().await;
        Ok(())
    }
}

/// Bidirectional packet relay between TUN device and netstack-smoltcp stack.
///
/// The `Stack` is both a `Sink` (accepts raw IP packets from TUN) and a
/// `Stream` (yields outgoing IP packets to write back to TUN). We use
/// `tokio::select!` to multiplex both directions in a single task.
async fn relay_packets(device: Arc<tun_rs::AsyncDevice>, mut stack: netstack_smoltcp::Stack) {
    let mut tun_buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            // TUN → stack: read raw IP packet from device, feed to netstack
            result = device.recv(&mut tun_buf) => {
                match result {
                    Ok(n) if n > 0 => {
                        let pkt = tun_buf[..n].to_vec();
                        if let Err(e) = stack.send(pkt).await {
                            debug!("TUN->stack error: {}", e);
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        error!("TUN recv error: {}", e);
                        break;
                    }
                }
            }
            // stack → TUN: read outgoing packet from netstack, write to TUN device
            Some(result) = stack.next() => {
                match result {
                    Ok(pkt) => {
                        if let Err(e) = device.send(&pkt).await {
                            debug!("stack->TUN error: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("stack stream error: {}", e);
                        break;
                    }
                }
            }
        }
    }
}

/// Parse a CIDR string like "198.18.0.1/16" into (ip_str, prefix_len).
fn parse_cidr(cidr: &str) -> Result<(&str, u8), Box<dyn std::error::Error + Send + Sync>> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("invalid CIDR: {}", cidr).into());
    }
    let prefix: u8 = parts[1].parse()?;
    Ok((parts[0], prefix))
}
