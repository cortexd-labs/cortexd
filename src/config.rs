use std::collections::HashMap;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub registration: Option<RegistrationConfig>,
    #[serde(default)]
    pub federation: FederationConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct RegistrationConfig {
    /// URL of the cortexd orchestrator (e.g., "https://cortexd.example.com:8443")
    pub cortexd_url: String,
    /// Persistent node identity — generated on first boot, stored locally
    #[serde(default = "generate_node_id")]
    pub node_id: String,
    /// Heartbeat interval in seconds
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,
}

#[derive(Debug, Deserialize, Default)]
pub struct FederationConfig {
    #[serde(default)]
    pub servers: Vec<DownstreamServer>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DownstreamServer {
    /// Namespace prefix for this downstream's tools (e.g., "linux", "redis")
    pub namespace: String,
    /// Transport configuration
    #[serde(flatten)]
    pub transport: DownstreamTransport,
    /// Optional: restrict which tools are exposed upstream
    #[serde(default)]
    pub expose: Vec<String>,
    /// Health check interval (default: 30s)
    #[serde(default = "default_healthcheck")]
    pub healthcheck_interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "transport")]
pub enum DownstreamTransport {
    /// Connect to a local MCP server via HTTP SSE
    #[serde(rename = "localhost")]
    Localhost {
        url: String,
    },
    /// Spawn a child process and communicate via stdio
    #[serde(rename = "stdio")]
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: HashMap<String, String>,
    },
}

impl Config {
    pub fn load_from_file(path: &str) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }
}

fn default_bind() -> String {
    // Default to localhost until TLS is implemented.
    // Override in neurond.toml for network-facing deployments.
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    8443
}

fn default_heartbeat_interval() -> u64 {
    30
}

fn default_healthcheck() -> u64 {
    30
}

fn generate_node_id() -> String {
    let dev_path = "./node_id";
    let prod_path = "/var/lib/neurond/node_id";

    // Try reading dev/prod
    if let Ok(id) = std::fs::read_to_string(dev_path) {
        return id.trim().to_string();
    }
    if let Ok(id) = std::fs::read_to_string(prod_path) {
        return id.trim().to_string();
    }

    let new_id = uuid::Uuid::new_v4().to_string();
    
    // Save to dev/prod based on access
    if std::fs::write(dev_path, &new_id).is_ok() {
        return new_id;
    }
    
    let _ = std::fs::create_dir_all("/var/lib/neurond");
    let _ = std::fs::write(prod_path, &new_id);

    new_id
}

/// Default config path
pub const DEFAULT_CONFIG_PATH: &str = "/etc/neurond/neurond.toml";
/// Fallback path for development
pub const DEV_CONFIG_PATH: &str = "neurond.toml";

/// Load config from the first available path
pub fn load_config() -> anyhow::Result<Config> {
    let path = if std::path::Path::new(DEFAULT_CONFIG_PATH).exists() {
        DEFAULT_CONFIG_PATH
    } else if std::path::Path::new(DEV_CONFIG_PATH).exists() {
        DEV_CONFIG_PATH
    } else {
        anyhow::bail!(
            "No config file found. Expected {} or {}",
            DEFAULT_CONFIG_PATH,
            DEV_CONFIG_PATH
        );
    };
    tracing::info!("Loading config from {}", path);
    Config::load_from_file(path)
}
