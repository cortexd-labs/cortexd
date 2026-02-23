pub mod engine;
pub mod linux;
pub mod providers;

use tracing_subscriber::EnvFilter;
use std::sync::Arc;
use tokio::net::TcpListener;
use axum::Router;
use rmcp::transport::streamable_http_server::{
    StreamableHttpService,
    session::local::LocalSessionManager,
};
use crate::engine::server::NeurondEngine;
use crate::engine::policy::Policy;
use crate::engine::audit::AuditLogger;
use crate::providers::system::{SystemProvider, LinuxSystemProvider};

/// Default paths for configuration and logging.
/// In production, these should be overridden by CLI args or environment variables.
const DEFAULT_POLICY_PATH: &str = "/etc/neurond/policy.toml";
const DEFAULT_AUDIT_LOG: &str = "/var/log/neurond/audit.log";

/// Fallback paths for development (relative to CWD).
const DEV_POLICY_PATH: &str = "policy.toml";
const DEV_AUDIT_LOG: &str = "audit.log";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Respect RUST_LOG if set, otherwise default to neurond=info
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("neurond=info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("Starting Neurond Linux Controller MCP server");

    // Try production path first, fall back to dev path
    let policy_path = if std::path::Path::new(DEFAULT_POLICY_PATH).exists() {
        DEFAULT_POLICY_PATH
    } else {
        DEV_POLICY_PATH
    };

    let policy = Policy::load_from_file(policy_path).unwrap_or_else(|err| {
        tracing::warn!("Failed to load {} ({}). Defaulting to Deny-All.", policy_path, err);
        Policy::default()
    });
    tracing::info!("Loaded policy from {}", policy_path);

    let audit_path = if std::path::Path::new(DEFAULT_AUDIT_LOG)
        .parent()
        .is_some_and(|p| p.exists())
    {
        DEFAULT_AUDIT_LOG
    } else {
        DEV_AUDIT_LOG
    };
    let audit_logger = AuditLogger::new(audit_path);
    tracing::info!("Audit log: {}", audit_path);

    let dbus_conn = Arc::new(zbus::Connection::system().await?);
    let session_conn = Arc::new(
        zbus::Connection::session().await
            .unwrap_or_else(|err| {
                tracing::warn!("Session D-Bus unavailable ({}). Desktop tools will fail.", err);
                // We can't easily create a no-op Connection, so we panic in non-headless setups.
                // In headless/server deployments, disable the desktop provider via policy.
                panic!("Session D-Bus required. Set DBUS_SESSION_BUS_ADDRESS or disable desktop tools in policy.toml.");
            })
    );
    let policy = Arc::new(policy);
    let audit_logger = Arc::new(audit_logger);
    let system_provider: Arc<dyn SystemProvider> = Arc::new(LinuxSystemProvider);

    let session_manager = LocalSessionManager::default();

    let mcp_service = StreamableHttpService::new(
        move || {
            let engine = NeurondEngine::new(
                dbus_conn.clone(),
                session_conn.clone(),
                policy.clone(),
                audit_logger.clone(),
                system_provider.clone()
            );
            Ok(engine)
        },
        session_manager.into(),
        Default::default(),
    );

    let app = Router::new().nest_service("/api/v1/mcp", mcp_service);
    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    
    tracing::info!("Server listening on http://0.0.0.0:8080");
    axum::serve(listener, app).await?;
    Ok(())
}
