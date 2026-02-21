mod routes;

use mihomo_tunnel::Tunnel;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

pub struct ApiServer {
    tunnel: Tunnel,
    listen_addr: SocketAddr,
    secret: Option<String>,
}

impl ApiServer {
    pub fn new(tunnel: Tunnel, listen_addr: SocketAddr, secret: Option<String>) -> Self {
        Self {
            tunnel,
            listen_addr,
            secret,
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let state = Arc::new(routes::AppState {
            tunnel: self.tunnel.clone(),
            secret: self.secret.clone(),
        });

        let app = routes::create_router(state);

        let listener = tokio::net::TcpListener::bind(self.listen_addr).await?;
        info!("REST API listening on {}", self.listen_addr);
        axum::serve(listener, app).await?;
        Ok(())
    }
}
