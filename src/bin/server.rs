use mcp::auth;
use rmcp::transport::SseServer;
use rmcp::transport::sse_server::SseServerConfig;
use rmcp::transport::streamable_http_server::{
    StreamableHttpService, session::local::LocalSessionManager,
};
use tracing_subscriber::{
    layer::SubscriberExt,
    util::SubscriberInitExt,
    {self},
};
mod common;
use common::trustify::Trustify;

const BIND_ADDRESS: &str = "[::]:8083";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "debug".to_string().into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // start Streamable HTTP server
    let service = StreamableHttpService::new(
        || Ok(Trustify::new()),
        LocalSessionManager::default().into(),
        Default::default(),
    );

    // start SSE server
    let config = SseServerConfig {
        bind: BIND_ADDRESS.parse()?,
        sse_path: "/sse".to_string(),
        post_path: "/message".to_string(),
        ct: tokio_util::sync::CancellationToken::new(),
        sse_keep_alive: None,
    };
    let (sse_server, sse_router) = SseServer::new(config);

    let router = auth::protect_router(sse_router.nest_service("/mcp", service)).await?;
    let tcp_listener = tokio::net::TcpListener::bind(BIND_ADDRESS).await?;
    let server = axum::serve(tcp_listener, router)
        .with_graceful_shutdown(async { tokio::signal::ctrl_c().await.unwrap() });

    tokio::spawn(async move {
        if let Err(e) = server.await {
            tracing::error!(error = %e, "Server shutdown with error");
        }
    });

    let ct = sse_server.with_service(Trustify::new);
    tokio::signal::ctrl_c().await?;
    ct.cancel();

    Ok(())
}
