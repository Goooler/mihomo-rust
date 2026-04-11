//! In-process loopback servers for transport layer tests.
// Each test binary (tls_test, ws_test, …) includes this module but only uses
// a subset of the functions.  Dead-code warnings on the unused half are
// expected and suppressed here.
#![allow(dead_code)]
//!
//! Contains server-side code (`TcpListener`, `TlsAcceptor`, etc.) that is
//! intentionally placed here (not in `src/`) to satisfy acceptance criterion
//! F2: "no `accept`/`bind`/`listen`/`TcpListener` in `src/**/*.rs`".
//!
//! # Design
//!
//! [`spawn_tls_server`] starts a single-connection TLS server in a background
//! tokio task.  After accepting and completing the TLS handshake it captures
//! connection metadata (SNI, negotiated ALPN, peer certificates) and sends
//! them through a oneshot channel.  The server then echoes any data it
//! receives so callers can test round-trips.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

// ─── Cert generation ─────────────────────────────────────────────────────────

/// Generate a self-signed certificate for the given Subject Alternative Names.
///
/// Returns `(cert_der, key_der)` — DER bytes for server config — plus
/// `cert_pem` for tests that need the raw PEM bytes.
pub fn gen_cert(
    sans: &[&str],
) -> (
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
    String, // cert PEM
    String, // key PEM
) {
    let ck =
        rcgen::generate_simple_self_signed(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .expect("rcgen cert generation failed");

    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    let cert_pem = ck.cert.pem();
    let key_pem = ck.key_pair.serialize_pem();
    (cert_der, key_der, cert_pem, key_pem)
}

/// Install the ring crypto provider once per process (idempotent).
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

// ─── Captured connection info ─────────────────────────────────────────────────

/// Metadata captured from the server side of a TLS handshake.
#[derive(Debug, Default)]
pub struct ConnInfo {
    /// The SNI name the client sent (None if client sent no SNI extension).
    pub server_name: Option<String>,
    /// The ALPN protocol negotiated (None if no ALPN was agreed).
    pub alpn: Option<Vec<u8>>,
    /// DER-encoded certificates from the client (empty if no client cert).
    pub peer_certs: Vec<Vec<u8>>,
}

// ─── Server builder ───────────────────────────────────────────────────────────

/// Configuration for [`spawn_tls_server`].
pub struct ServerOptions {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
    /// ALPN protocols the server advertises (empty = no ALPN).
    pub server_alpn: Vec<Vec<u8>>,
    /// If `Some`, the server requires a client certificate and verifies it
    /// against the given CA cert (DER-encoded).
    pub require_client_cert_ca: Option<CertificateDer<'static>>,
}

/// Spawn a single-accept TLS loopback server.
///
/// Returns `(addr, conn_info_rx)`.  The server accepts one connection,
/// performs the TLS handshake, sends [`ConnInfo`] through the channel,
/// then echoes all received bytes until EOF.
///
/// The server runs in a background tokio task and is cleaned up when the
/// `conn_info_rx` channel is dropped or the task exits naturally.
pub async fn spawn_tls_server(
    opts: ServerOptions,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<ConnInfo>,
) {
    let (tx, rx) = tokio::sync::oneshot::channel();

    let server_config_builder = rustls::ServerConfig::builder();

    // Client certificate verification
    let server_config = if let Some(ca_der) = opts.require_client_cert_ca {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(ca_der).expect("valid CA cert DER");
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .expect("WebPkiClientVerifier build");
        let mut cfg = server_config_builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![opts.cert_der], opts.key_der)
            .expect("server TLS config with client cert verifier");
        cfg.alpn_protocols = opts.server_alpn;
        cfg
    } else {
        let mut cfg = server_config_builder
            .with_no_client_auth()
            .with_single_cert(vec![opts.cert_der], opts.key_der)
            .expect("server TLS config");
        cfg.alpn_protocols = opts.server_alpn;
        cfg
    };

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        let (tcp, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => return,
        };

        let tls_stream = match acceptor.accept(tcp).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("loopback TLS accept error: {}", e);
                return;
            }
        };

        // Capture handshake metadata before moving the stream.
        let (_, server_conn) = tls_stream.get_ref();
        let info = ConnInfo {
            server_name: server_conn.server_name().map(|s| s.to_owned()),
            alpn: server_conn.alpn_protocol().map(|p| p.to_vec()),
            peer_certs: server_conn
                .peer_certificates()
                .unwrap_or(&[])
                .iter()
                .map(|c| c.to_vec())
                .collect(),
        };

        let _ = tx.send(info);

        // Drain the connection so the client side doesn't get a broken pipe on
        // its write.  No echo needed for TLS unit tests — they only assert
        // handshake properties, not round-trip data.
        let mut tls_stream = tls_stream;
        let mut drain = [0u8; 256];
        loop {
            match tokio::io::AsyncReadExt::read(&mut tls_stream, &mut drain).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });

    (addr, rx)
}

// ─── WebSocket loopback server ────────────────────────────────────────────────

/// Metadata captured from the WebSocket upgrade request.
#[derive(Debug, Default)]
pub struct WsConnInfo {
    /// Value of the `Host` header sent by the client.
    pub host: Option<String>,
    /// Value of the `Sec-WebSocket-Protocol` header (used for early data).
    pub sec_ws_protocol: Option<String>,
    /// All headers from the upgrade request (lower-cased names).
    pub headers: std::collections::HashMap<String, String>,
}

/// Spawn a single-accept plain-TCP WebSocket loopback server.
///
/// Returns `(addr, ws_info_rx)`.  The server:
/// 1. Accepts one TCP connection.
/// 2. Performs the WebSocket handshake, capturing upgrade-request headers.
/// 3. Sends [`WsConnInfo`] through the oneshot channel.
/// 4. Drains the connection until EOF.
pub async fn spawn_ws_server() -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<WsConnInfo>,
) {
    let (tx, rx) = tokio::sync::oneshot::channel::<WsConnInfo>();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ws loopback bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        let (tcp, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => return,
        };

        // Use accept_hdr_async to capture the upgrade-request headers.
        use tokio_tungstenite::tungstenite::handshake::server::{Callback, Request, Response};

        struct CaptureCallback(tokio::sync::oneshot::Sender<WsConnInfo>);

        impl Callback for CaptureCallback {
            fn on_request(
                self,
                request: &Request,
                mut response: Response,
            ) -> std::result::Result<
                Response,
                tokio_tungstenite::tungstenite::http::Response<Option<String>>,
            > {
                let mut headers = std::collections::HashMap::new();
                let mut host = None;
                let mut sec_ws_protocol = None;

                for (k, v) in request.headers() {
                    let key = k.as_str().to_ascii_lowercase();
                    let val = v.to_str().unwrap_or("").to_string();
                    if key == "host" {
                        host = Some(val.clone());
                    }
                    if key == "sec-websocket-protocol" {
                        sec_ws_protocol = Some(val.clone());
                    }
                    headers.insert(key, val);
                }

                // RFC 6455: if the client sends Sec-WebSocket-Protocol, the server
                // MUST respond with one of the listed protocols (tungstenite enforces
                // this on the client side).  Echo it back verbatim so the handshake
                // succeeds — the test only cares about the header value, not the
                // subprotocol semantics.
                if let Some(proto) = request.headers().get("sec-websocket-protocol") {
                    response.headers_mut().insert(
                        tokio_tungstenite::tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL,
                        proto.clone(),
                    );
                }

                let info = WsConnInfo {
                    host,
                    sec_ws_protocol,
                    headers,
                };
                let _ = self.0.send(info);
                Ok(response)
            }
        }

        let ws = match tokio_tungstenite::accept_hdr_async(tcp, CaptureCallback(tx)).await {
            Ok(ws) => ws,
            Err(e) => {
                eprintln!("ws loopback accept error: {}", e);
                return;
            }
        };

        // Drain the connection.
        let mut ws = ws;
        use futures_util::StreamExt;
        while ws.next().await.is_some() {}
    });

    (addr, rx)
}
