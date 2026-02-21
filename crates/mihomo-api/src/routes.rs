use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use mihomo_common::TunnelMode;
use mihomo_tunnel::Tunnel;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::info;

pub struct AppState {
    pub tunnel: Tunnel,
    #[allow(dead_code)]
    pub secret: Option<String>,
}

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(hello))
        .route("/version", get(version))
        .route("/proxies", get(get_proxies))
        .route("/proxies/{name}", get(get_proxy).put(update_proxy))
        .route("/rules", get(get_rules))
        .route("/connections", get(get_connections))
        .route("/connections/{id}", delete(close_connection))
        .route("/configs", get(get_configs).patch(update_configs))
        .route("/traffic", get(get_traffic))
        .route("/dns/query", post(dns_query))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn hello() -> &'static str {
    "mihomo-rust"
}

#[derive(Serialize)]
struct VersionResponse {
    version: String,
    meta: bool,
}

async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: "0.1.0".to_string(),
        meta: true,
    })
}

#[derive(Serialize)]
struct ProxyInfo {
    name: String,
    #[serde(rename = "type")]
    proxy_type: String,
    alive: bool,
    history: Vec<mihomo_common::DelayHistory>,
    udp: bool,
}

#[derive(Serialize)]
struct ProxiesResponse {
    proxies: std::collections::HashMap<String, ProxyInfo>,
}

async fn get_proxies(State(state): State<Arc<AppState>>) -> Json<ProxiesResponse> {
    let proxies = state.tunnel.proxies();
    let mut result = std::collections::HashMap::new();
    for (name, proxy) in &proxies {
        result.insert(
            name.clone(),
            ProxyInfo {
                name: proxy.name().to_string(),
                proxy_type: proxy.adapter_type().to_string(),
                alive: proxy.alive(),
                history: proxy.delay_history(),
                udp: proxy.support_udp(),
            },
        );
    }
    Json(ProxiesResponse { proxies: result })
}

async fn get_proxy(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<ProxyInfo>, StatusCode> {
    let proxies = state.tunnel.proxies();
    let proxy = proxies.get(&name).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(ProxyInfo {
        name: proxy.name().to_string(),
        proxy_type: proxy.adapter_type().to_string(),
        alive: proxy.alive(),
        history: proxy.delay_history(),
        udp: proxy.support_udp(),
    }))
}

#[derive(Deserialize)]
struct UpdateProxyRequest {
    name: String,
}

async fn update_proxy(
    State(_state): State<Arc<AppState>>,
    Path(group_name): Path<String>,
    Json(body): Json<UpdateProxyRequest>,
) -> StatusCode {
    // This would change the selected proxy in a Selector group
    // For now, return OK
    info!("Update proxy {} -> {}", group_name, body.name);
    StatusCode::NO_CONTENT
}

#[derive(Serialize)]
struct RuleInfo {
    #[serde(rename = "type")]
    rule_type: String,
    payload: String,
    proxy: String,
}

#[derive(Serialize)]
struct RulesResponse {
    rules: Vec<RuleInfo>,
}

async fn get_rules(State(state): State<Arc<AppState>>) -> Json<RulesResponse> {
    let rules = state.tunnel.rules_info();
    let result: Vec<RuleInfo> = rules
        .into_iter()
        .map(|(rt, payload, adapter)| RuleInfo {
            rule_type: rt,
            payload,
            proxy: adapter,
        })
        .collect();
    Json(RulesResponse { rules: result })
}

#[derive(Serialize)]
struct ConnectionsResponse {
    upload_total: i64,
    download_total: i64,
    connections: Vec<serde_json::Value>,
}

async fn get_connections(State(state): State<Arc<AppState>>) -> Json<ConnectionsResponse> {
    let stats = state.tunnel.statistics();
    let (up, down) = stats.snapshot();
    let conns = stats.active_connections();
    let connections: Vec<serde_json::Value> = conns
        .into_iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id,
                "upload": c.upload,
                "download": c.download,
                "start": c.start,
                "chains": c.chains,
                "rule": c.rule,
                "rulePayload": c.rule_payload,
            })
        })
        .collect();

    Json(ConnectionsResponse {
        upload_total: up,
        download_total: down,
        connections,
    })
}

async fn close_connection(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> StatusCode {
    state.tunnel.statistics().close_connection(&id);
    StatusCode::NO_CONTENT
}

#[derive(Serialize)]
struct ConfigResponse {
    mode: String,
    #[serde(rename = "log-level")]
    log_level: String,
}

async fn get_configs(State(state): State<Arc<AppState>>) -> Json<ConfigResponse> {
    Json(ConfigResponse {
        mode: state.tunnel.mode().to_string(),
        log_level: "info".to_string(),
    })
}

#[derive(Deserialize)]
struct UpdateConfigRequest {
    mode: Option<String>,
    #[serde(rename = "log-level")]
    log_level: Option<String>,
}

async fn update_configs(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UpdateConfigRequest>,
) -> StatusCode {
    if let Some(mode_str) = body.mode {
        match mode_str.parse::<TunnelMode>() {
            Ok(mode) => {
                state.tunnel.set_mode(mode);
                info!("Mode changed to {}", mode);
            }
            Err(_) => return StatusCode::BAD_REQUEST,
        }
    }
    // log_level handling would go here if needed
    let _ = body.log_level;
    StatusCode::NO_CONTENT
}

#[derive(Serialize)]
struct TrafficResponse {
    up: i64,
    down: i64,
}

async fn get_traffic(State(state): State<Arc<AppState>>) -> Json<TrafficResponse> {
    let (up, down) = state.tunnel.statistics().snapshot();
    Json(TrafficResponse { up, down })
}

#[derive(Deserialize)]
struct DnsQueryRequest {
    name: String,
    #[serde(rename = "type")]
    qtype: Option<String>,
}

async fn dns_query(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DnsQueryRequest>,
) -> Json<serde_json::Value> {
    let resolver = state.tunnel.resolver();
    let result = resolver.resolve_ip(&body.name).await;
    let _ = body.qtype; // Reserved for future use
    Json(serde_json::json!({
        "name": body.name,
        "answer": result.map(|ip| ip.to_string()),
    }))
}
