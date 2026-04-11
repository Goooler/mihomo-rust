//! TLS client transport layer (`features = ["tls"]`).
//!
//! [`TlsLayer`] wraps any inner [`Stream`] with a rustls TLS handshake and
//! returns the upgraded stream ready for the next layer (WebSocket, gRPC, …)
//! or for the proxy protocol codec (Trojan, VMess, …).
//!
//! # SNI resolution contract
//!
//! `mihomo-config` resolves the effective SNI **before** constructing
//! [`TlsConfig`]; the transport layer never sees the dial address.
//! Resolution rules (applied in `mihomo-config`):
//!
//! | YAML `servername` | `server` field   | `TlsConfig.sni`       |
//! |-------------------|------------------|-----------------------|
//! | set               | any              | `Some(servername)`    |
//! | unset             | hostname         | `Some(hostname)`      |
//! | unset             | IP literal       | `Some("1.2.3.4")`*   |
//!
//! *`rustls::pki_types::ServerName::try_from("1.2.3.4")` creates an
//! `IpAddress` variant, which rustls uses for certificate verification
//! but does **not** include in the TLS SNI extension (RFC 6066 §3
//! prohibits IP literals in SNI).  Test case A9 asserts this behaviour.
//!
//! `sni = None` is never produced for a valid TLS connection; [`TlsLayer::new`]
//! returns [`TransportError::Config`] if it receives `None`.
//!
//! # Fingerprint stub
//!
//! `client-fingerprint` is accepted, stored, and warned about exactly once
//! per distinct value.  No actual uTLS fingerprint spoofing is performed.
//! See issue #32 for the tracking issue.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};

use async_trait::async_trait;
use tracing::warn;

use crate::{Result, Stream, Transport, TransportError};

// ─── Fingerprint dedup ────────────────────────────────────────────────────────

/// Process-global set of `client-fingerprint` values that have already
/// produced a `warn!`.  Guarantees each distinct value warns exactly once
/// even when the proxy list has hundreds of entries sharing the same value.
static FINGERPRINT_WARNED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

fn fingerprint_warned_set() -> &'static Mutex<HashSet<String>> {
    FINGERPRINT_WARNED.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Emit the fingerprint stub warning at most once per distinct value.
///
/// Called from [`TlsLayer::new`].  Uses `insert()` on the global `HashSet`
/// — truthy means "first time we've seen this value", which is when we warn.
pub(crate) fn warn_fingerprint_once(fingerprint: &str) {
    let mut set = fingerprint_warned_set()
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if set.insert(fingerprint.to_string()) {
        warn!(
            "client-fingerprint=\"{}\" set on proxy: \
             uTLS fingerprint spoofing is not implemented; \
             TLS handshake will use rustls defaults. \
             See https://github.com/mihomo-rust/mihomo-rust/issues/32 \
             for real uTLS support.",
            fingerprint
        );
    }
}

// ─── Config structs ───────────────────────────────────────────────────────────

/// TLS layer configuration, built by `mihomo-config` from YAML and passed
/// into [`TlsLayer::new`].  This struct never sees YAML directly.
///
/// Corresponds to the `tls:`, `skip-cert-verify:`, `alpn:`, and
/// `client-fingerprint:` keys in a proxy entry.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Whether TLS is enabled.  If `false`, no [`TlsLayer`] should be
    /// constructed; this field is a convenience for config-side logic.
    pub enabled: bool,

    /// Effective SNI, resolved by config before construction (see module doc).
    /// Must be `Some` when `enabled = true`.
    pub sni: Option<String>,

    /// ALPN protocol IDs offered in the ClientHello.
    /// Empty slice → no ALPN extension.
    pub alpn: Vec<String>,

    /// Disable server certificate verification.  Emits a `warn!` once.
    pub skip_cert_verify: bool,

    /// Optional mutual-TLS client certificate (PEM-encoded).
    pub client_cert: Option<ClientCert>,

    /// `client-fingerprint` YAML value: stored, warned about, not acted on.
    pub fingerprint: Option<String>,

    /// Extra CA certificates (DER-encoded) added to the root store in
    /// addition to `webpki-roots`.  Used in tests with self-signed certs;
    /// production deployments leave this empty.
    pub additional_roots: Vec<Vec<u8>>,
}

impl TlsConfig {
    /// Convenience constructor: TLS enabled, SNI set, all other fields default.
    pub fn new(sni: impl Into<String>) -> Self {
        Self {
            enabled: true,
            sni: Some(sni.into()),
            alpn: Vec::new(),
            skip_cert_verify: false,
            client_cert: None,
            fingerprint: None,
            additional_roots: Vec::new(),
        }
    }
}

/// Optional mutual-TLS client certificate (PEM-encoded key and certificate).
#[derive(Debug, Clone)]
pub struct ClientCert {
    /// PEM-encoded X.509 certificate chain.
    pub cert_pem: Vec<u8>,
    /// PEM-encoded private key (PKCS#8 or RSA).
    pub key_pem: Vec<u8>,
}

// ─── Insecure certificate verifier ───────────────────────────────────────────

/// Certificate verifier that accepts any certificate without validation.
/// Used when `skip_cert_verify = true`.
///
/// Previously duplicated in `trojan.rs` and `v2ray_plugin.rs`; now lives
/// here as the single authoritative copy.
#[derive(Debug)]
struct InsecureCertVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ─── TlsLayer ─────────────────────────────────────────────────────────────────

/// TLS client transport layer.
///
/// Build once at startup from a [`TlsConfig`]; call [`Transport::connect`] for
/// each new connection.  Cheap to clone — the inner `TlsConnector` wraps an
/// `Arc<rustls::ClientConfig>`.
pub struct TlsLayer {
    connector: tokio_rustls::TlsConnector,
    /// Pre-parsed server name, resolved at construction time.
    server_name: rustls::pki_types::ServerName<'static>,
}

impl TlsLayer {
    /// Construct a `TlsLayer` from the given configuration.
    ///
    /// Emits the fingerprint stub `warn!` if `config.fingerprint` is set
    /// (deduped globally by value — see [`warn_fingerprint_once`]).
    ///
    /// Emits a `warn!` if `skip_cert_verify = true` (footgun telemetry).
    ///
    /// # Errors
    ///
    /// * [`TransportError::Config`] — `sni` is `None`, or the SNI string is
    ///   not a valid DNS name or IP address.
    /// * [`TransportError::Config`] — a DER in `additional_roots` is malformed.
    /// * [`TransportError::Config`] — `client_cert` PEM is unparseable.
    /// * [`TransportError::Tls`] — client cert + key don't match.
    pub fn new(config: &TlsConfig) -> Result<Self> {
        // Fingerprint stub warning (deduped globally by value).
        if let Some(fp) = &config.fingerprint {
            warn_fingerprint_once(fp);
        }

        // Skip-cert-verify telemetry — one warn per TlsLayer instance (not deduped
        // globally; the proxy table typically has few skip-verify entries).
        if config.skip_cert_verify {
            warn!(
                "skip-cert-verify=true: TLS certificate verification is disabled; \
                 the connection is NOT authenticated against a trusted CA"
            );
        }

        // Resolve SNI.
        let sni_str = config.sni.as_deref().ok_or_else(|| {
            TransportError::Config(
                "TlsLayer requires sni to be Some; None is reserved for non-TLS paths. \
                 mihomo-config must resolve the effective SNI before constructing TlsLayer."
                    .into(),
            )
        })?;

        let server_name = rustls::pki_types::ServerName::try_from(sni_str)
            .map_err(|e| TransportError::Config(format!("invalid SNI '{}': {}", sni_str, e)))?
            .to_owned();

        let rustls_config = Self::build_rustls_config(config)?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(rustls_config));

        Ok(Self {
            connector,
            server_name,
        })
    }

    fn build_rustls_config(config: &TlsConfig) -> Result<rustls::ClientConfig> {
        // --- Verifier half of the builder ---
        let builder = if config.skip_cert_verify {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier))
        } else {
            let mut root_store = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            for ca_der in &config.additional_roots {
                root_store
                    .add(rustls::pki_types::CertificateDer::from(ca_der.clone()))
                    .map_err(|e| {
                        TransportError::Config(format!("additional_roots: invalid CA cert: {}", e))
                    })?;
            }
            rustls::ClientConfig::builder().with_root_certificates(root_store)
        };

        // --- Client-auth half of the builder ---
        let mut tls_config = match &config.client_cert {
            Some(cc) => {
                let cert_chain = rustls_pemfile::certs(&mut cc.cert_pem.as_slice())
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|e| {
                        TransportError::Config(format!(
                            "client_cert.cert_pem: PEM parse error: {}",
                            e
                        ))
                    })?;
                let private_key = rustls_pemfile::private_key(&mut cc.key_pem.as_slice())
                    .map_err(|e| {
                        TransportError::Config(format!(
                            "client_cert.key_pem: PEM parse error: {}",
                            e
                        ))
                    })?
                    .ok_or_else(|| {
                        TransportError::Config("client_cert.key_pem: no private key found".into())
                    })?;
                builder
                    .with_client_auth_cert(cert_chain, private_key)
                    .map_err(|e| TransportError::Tls(format!("client cert setup: {}", e)))?
            }
            None => builder.with_no_client_auth(),
        };

        // --- ALPN ---
        if !config.alpn.is_empty() {
            tls_config.alpn_protocols = config.alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
        }

        Ok(tls_config)
    }
}

#[async_trait]
impl Transport for TlsLayer {
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        let tls_stream = self
            .connector
            .connect(self.server_name.clone(), inner)
            .await
            .map_err(|e| TransportError::Tls(e.to_string()))?;
        Ok(Box::new(tls_stream))
    }
}
