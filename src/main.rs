pub mod engine;
pub mod linux;
pub mod providers;

use rmcp::ServiceExt;
use tracing_subscriber::EnvFilter;
use crate::engine::server::NeurondEngine;
use crate::engine::policy::Policy;
use crate::engine::audit::AuditLogger;

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

    let dbus_conn = zbus::Connection::system().await?;

    let engine = NeurondEngine::new(dbus_conn, policy, audit_logger);

    let service = engine.serve(rmcp::transport::stdio()).await?;

    // Wait for shutdown — client disconnect closes stdin, service.waiting() handles it.
    // For future daemon mode (HTTP transport), add SIGINT/SIGTERM handling here:
    //   tokio::select! {
    //       _ = service.waiting() => {},
    //       _ = tokio::signal::ctrl_c() => { tracing::info!("Received SIGINT"); },
    //   }
    service.waiting().await?;

    tracing::info!("Neurond shutting down cleanly");
    Ok(())
}
