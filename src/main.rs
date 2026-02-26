pub mod config;
pub mod federation;
pub mod upstream;
pub mod security;
pub mod registration;

use std::sync::Arc;
use tracing_subscriber::EnvFilter;
use tokio::net::TcpListener;
use axum::Router;
use rmcp::transport::streamable_http_server::{
    StreamableHttpService,
    session::local::LocalSessionManager,
};

use crate::federation::manager::FederationManager;
use crate::upstream::server::ProxyEngine;
use crate::security::policy::Policy;
use crate::security::audit::AuditLogger;

/// Default paths for configuration and logging.
const DEFAULT_POLICY_PATH: &str = "/etc/neurond/policy.toml";
const DEFAULT_AUDIT_LOG: &str = "/var/log/neurond/audit.log";

/// Fallback paths for development (relative to CWD).
const DEV_POLICY_PATH: &str = "policy.toml";
const DEV_AUDIT_LOG: &str = "audit.log";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("neurond=info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("Starting neurond Federation Proxy");

    // Load config
    let config = config::load_config()?;
    let bind_addr = format!("{}:{}", config.server.bind, config.server.port);

    // Load policy
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
    let policy = Arc::new(policy);

    // Set up audit log
    let audit_path = if std::path::Path::new(DEFAULT_AUDIT_LOG)
        .parent()
        .is_some_and(|p| p.exists())
    {
        DEFAULT_AUDIT_LOG
    } else {
        DEV_AUDIT_LOG
    };
    let audit_logger = Arc::new(AuditLogger::new(audit_path));
    tracing::info!("Audit log: {}", audit_path);

    // Initialize federation manager and connect to downstreams
    let federation = Arc::new(FederationManager::new());
    federation.init_from_config(&config.federation).await?;

    // Log connected downstreams
    let status = federation.status_summary().await;
    for (ns, state) in &status {
        tracing::info!(namespace = %ns, state = %state, "Downstream status");
    }

    let tools = federation.list_all_tools().await;
    tracing::info!("Total tools aggregated: {}", tools.len());

    // Start registration/heartbeat if cortexd configured
    let _heartbeat_shutdown = if let Some(reg) = &config.registration {
        // Register with cortexd
        let capabilities: Vec<String> = status.iter().map(|(ns, _)| ns.clone()).collect();
        let hostname = gethostname().unwrap_or_else(|| "unknown".to_string());

        let payload = registration::register::RegisterPayload {
            node_id: reg.node_id.clone(),
            hostname,
            ip_address: config.server.bind.clone(),
            port: config.server.port,
            capabilities,
        };

        if let Err(e) = registration::register::register_node(&reg.cortexd_url, &payload).await {
            tracing::warn!(error = %e, "Failed to register with cortexd — continuing without orchestrator");
        }

        // Start heartbeat
        Some(registration::heartbeat::spawn_heartbeat(
            reg.cortexd_url.clone(),
            reg.node_id.clone(),
            reg.heartbeat_interval_secs,
        ))
    } else {
        tracing::info!("No cortexd registration configured — running standalone");
        None
    };

    // Start upstream SSE server
    let session_manager = LocalSessionManager::default();

    let fed = federation.clone();
    let pol = policy.clone();
    let aud = audit_logger.clone();
    let mcp_service = StreamableHttpService::new(
        move || {
            let engine = ProxyEngine::new(fed.clone(), pol.clone(), aud.clone());
            Ok(engine)
        },
        session_manager.into(),
        Default::default(),
    );

    let app = Router::new().nest_service("/api/v1/mcp", mcp_service);
    let listener = TcpListener::bind(&bind_addr).await?;

    tracing::info!("neurond proxy listening on http://{}", bind_addr);
    axum::serve(listener, app).await?;

    Ok(())
}

/// Get the system hostname.
fn gethostname() -> Option<String> {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
}
