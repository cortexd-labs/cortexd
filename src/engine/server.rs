use rmcp::{
    handler::server::{ServerHandler, tool::ToolRouter, wrapper::Parameters},
    model::*,
    tool, tool_handler, tool_router,
    ErrorData as McpError,
};
use zbus::Connection;
use crate::engine::policy::Policy;
use crate::engine::audit::AuditLogger;
use crate::native::system::SystemProvider;
use std::sync::Arc;

#[derive(Clone)]
pub struct NeurondEngine {
    tool_router: ToolRouter<Self>,
    pub dbus_conn: Arc<Connection>,
    pub session_conn: Arc<Connection>,
    pub policy: Arc<Policy>,
    pub audit: Arc<AuditLogger>,
    pub system_provider: Arc<dyn SystemProvider>,
}

impl NeurondEngine {
    async fn start_tool_call(&self, tool: &str, params: &serde_json::Value) -> Result<std::time::Instant, McpError> {
        let start = std::time::Instant::now();
        if !self.policy.is_allowed(tool) {
            self.audit.log(tool, params, "denied", "blocked", 0).await;
            return Err(McpError {
                code: ErrorCode::INVALID_REQUEST,
                message: format!("Access denied to tool {} by security policy", tool).into(),
                data: None,
            });
        }
        Ok(start)
    }

    async fn complete_tool_call(&self, tool: &str, params: &serde_json::Value, start: std::time::Instant, success: bool) {
        let duration = start.elapsed().as_millis() as u64;
        let result_str = if success { "success" } else { "error" };
        self.audit.log(tool, params, "allowed", result_str, duration).await;
    }

    fn internal_error(e: impl std::fmt::Display) -> McpError {
        McpError {
            code: ErrorCode::INTERNAL_ERROR,
            message: e.to_string().into(),
            data: None,
        }
    }
}

// ── Argument structs ───────────────────────────────────────────────────────────

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct ProcessTopArgs {
    #[schemars(description = "Sort by 'memory' or 'cpu'")]
    pub sort_by: Option<String>,
    #[schemars(description = "Number of processes to return (default 10)")]
    pub limit: Option<usize>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct ProcessPidArgs {
    #[schemars(description = "Process ID")]
    pub pid: i32,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct ProcessKillArgs {
    #[schemars(description = "Process ID to terminate")]
    pub pid: i32,
    #[schemars(description = "If true send SIGKILL, otherwise SIGTERM (default false)")]
    pub force: Option<bool>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct ProcessSignalArgs {
    #[schemars(description = "Process ID")]
    pub pid: i32,
    #[schemars(description = "Signal number (e.g. 9 for SIGKILL, 15 for SIGTERM)")]
    pub signum: i32,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct ProcessNiceArgs {
    #[schemars(description = "Process ID")]
    pub pid: i32,
    #[schemars(description = "Nice value from -20 (highest priority) to 19 (lowest)")]
    pub priority: i32,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct ServiceStatusArgs {
    #[schemars(description = "Name of the systemd unit (e.g. sshd.service)")]
    pub name: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct ServiceLogsArgs {
    #[schemars(description = "Name of the systemd unit (e.g. sshd.service)")]
    pub name: String,
    #[schemars(description = "Number of lines to return (default 50)")]
    pub lines: Option<usize>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct SysctlSetArgs {
    #[schemars(description = "Kernel parameter key (e.g. net.ipv4.ip_forward)")]
    pub key: String,
    #[schemars(description = "Value to set")]
    pub value: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct LogTailArgs {
    #[schemars(description = "Specific systemd unit name to filter on if required")]
    pub unit: Option<String>,
    #[schemars(description = "Number of lines to return (default 50)")]
    pub lines: Option<usize>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct LogSearchArgs {
    #[schemars(description = "String keyword to find in journals")]
    pub keyword: String,
    #[schemars(description = "Optional temporal bounds (e.g. '1 hour ago')")]
    pub since: Option<String>,
    #[schemars(description = "Optional Priority filter boundaries (e.g. 'err', 'warning')")]
    pub priority: Option<String>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct LogStreamArgs {
    #[schemars(description = "Optional systemd unit to filter on")]
    pub unit: Option<String>,
    #[schemars(description = "Seconds to collect entries before returning (default 5, max 30)")]
    pub timeout_secs: Option<u64>,
    #[schemars(description = "Maximum number of entries to return (default 100)")]
    pub max_lines: Option<usize>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct LogVacuumArgs {
    #[schemars(description = "Remove journal entries until total size is below this many MB")]
    pub size_mb: Option<u64>,
    #[schemars(description = "Remove journal entries older than this many days")]
    pub days: Option<u64>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct FirewallArgs {
    #[schemars(description = "iptables table (e.g. 'filter', 'nat'). Defaults to 'filter'.")]
    pub table: Option<String>,
    #[schemars(description = "Chain name (e.g. 'INPUT', 'OUTPUT', 'FORWARD')")]
    pub chain: String,
    #[schemars(description = "Rule arguments (space-separated, e.g. '-p tcp --dport 22 -j ACCEPT')")]
    pub rule: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct FileInfoArgs {
    #[schemars(description = "Absolute path to file or directory")]
    pub path: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct FileListArgs {
    #[schemars(description = "Absolute path to directory to list")]
    pub path: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct FileReadArgs {
    #[schemars(description = "Absolute path to file")]
    pub path: String,
    #[schemars(description = "Maximum bytes to read (default 1048576)")]
    pub max_bytes: Option<usize>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct FileTailArgs {
    #[schemars(description = "Absolute path to file")]
    pub path: String,
    #[schemars(description = "Number of lines to return (default 50)")]
    pub lines: Option<usize>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct FileSearchArgs {
    #[schemars(description = "Absolute path to directory to search in")]
    pub dir: String,
    #[schemars(description = "Literal string pattern to search for")]
    pub pattern: String,
    #[schemars(description = "Maximum number of matching lines to return (default 100)")]
    pub max_results: Option<usize>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct FileWriteArgs {
    #[schemars(description = "Absolute path to write")]
    pub path: String,
    #[schemars(description = "Content to write to the file")]
    pub content: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct FileMkdirArgs {
    #[schemars(description = "Absolute path to directory to create")]
    pub path: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct FileChmodArgs {
    #[schemars(description = "Absolute path to file or directory")]
    pub path: String,
    #[schemars(description = "Permission mode in decimal (e.g. 420 = octal 644)")]
    pub mode: u32,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct ContainerStatsArgs {
    #[schemars(description = "Container ID or name")]
    pub id: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct ContainerIdArgs {
    #[schemars(description = "Container ID or name")]
    pub id: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct ContainerLogsArgs {
    #[schemars(description = "Container ID or name")]
    pub id: String,
    #[schemars(description = "Number of log lines to return (default 50)")]
    pub lines: Option<usize>,
    #[schemars(description = "Unix timestamp to show logs since")]
    pub since: Option<String>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct ContainerRemoveArgs {
    #[schemars(description = "Container ID or name")]
    pub id: String,
    #[schemars(description = "Force remove even if running (default false)")]
    pub force: Option<bool>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct PackageNameArgs {
    #[schemars(description = "Package name")]
    pub name: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct PackageUpdateArgs {
    #[schemars(description = "Package name to update, or omit to update all packages")]
    pub name: Option<String>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct PackageSearchArgs {
    #[schemars(description = "Search query (package name or description keywords)")]
    pub query: String,
}

// ── Identity ──────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct SshKeysListArgs {
    #[schemars(description = "Username whose authorized_keys to list")]
    pub username: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct SshKeysAddArgs {
    #[schemars(description = "Username to add key for")]
    pub username: String,
    #[schemars(description = "Public key string (e.g. 'ssh-ed25519 AAAA... comment')")]
    pub key: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct SshKeysRemoveArgs {
    #[schemars(description = "Username whose authorized_keys to modify")]
    pub username: String,
    #[schemars(description = "Key identifier: comment or substring that uniquely identifies the key")]
    pub key_identifier: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct UserLockArgs {
    #[schemars(description = "Username to lock")]
    pub username: String,
}

// ── Storage ───────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct SmartHealthArgs {
    #[schemars(description = "Block device path (e.g. /dev/sda)")]
    pub device: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct MountArgs {
    #[schemars(description = "Block device path (e.g. /dev/sdb1)")]
    pub device: String,
    #[schemars(description = "Directory to mount at")]
    pub mountpoint: String,
    #[schemars(description = "Filesystem type (e.g. 'ext4', 'xfs'). Optional.")]
    pub fstype: Option<String>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct UnmountArgs {
    #[schemars(description = "Mountpoint directory to unmount")]
    pub mountpoint: String,
}

// ── Schedule ──────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct CronAddArgs {
    #[schemars(description = "Username to add cron job for")]
    pub username: String,
    #[schemars(description = "Cron schedule expression (5 fields, e.g. '0 2 * * *')")]
    pub schedule: String,
    #[schemars(description = "Command to execute")]
    pub command: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct CronRemoveArgs {
    #[schemars(description = "Username whose crontab to modify")]
    pub username: String,
    #[schemars(description = "Pattern to match cron entries for removal")]
    pub command_pattern: String,
}

// ── Security ──────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct CertsCheckArgs {
    #[schemars(description = "File or directory path to scan for x509 certificates")]
    pub path: String,
}

// ── Desktop ───────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct WindowIdArgs {
    #[schemars(description = "Window ID (hex, e.g. 0x01e00003)")]
    pub window_id: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct LaunchAppArgs {
    #[schemars(description = "Application name or .desktop entry name (e.g. 'firefox', 'org.gnome.Nautilus')")]
    pub app: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct SetVolumeArgs {
    #[schemars(description = "Volume level 0-100")]
    pub percent: u32,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct SetThemeArgs {
    #[schemars(description = "'dark' or 'light'")]
    pub mode: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct NotifyArgs {
    #[schemars(description = "Notification title/summary")]
    pub summary: String,
    #[schemars(description = "Notification body text")]
    pub body: Option<String>,
    #[schemars(description = "Urgency: 0=low, 1=normal, 2=critical (default 1)")]
    pub urgency: Option<u8>,
}

// ── Tool implementations ───────────────────────────────────────────────────────

#[tool_router]
impl NeurondEngine {
    pub fn new(dbus_conn: Arc<Connection>, session_conn: Arc<Connection>, policy: Arc<Policy>, audit: Arc<AuditLogger>, system_provider: Arc<dyn SystemProvider>) -> Self {
        Self {
            tool_router: Self::tool_router(),
            dbus_conn,
            session_conn,
            policy,
            audit,
            system_provider,
        }
    }

    // ── System ────────────────────────────────────────────────────────────────

    #[tool(description = "Get system information: hostname, kernel, uptime, CPU count, total memory")]
    async fn system_info(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "system.info";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match self.system_provider.system_info().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Get CPU usage percent and core count")]
    async fn system_cpu(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "system.cpu";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match self.system_provider.system_cpu().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Get memory information including total, free, and available in MB")]
    async fn system_memory(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "system.memory";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match self.system_provider.system_memory().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Get disk mount capacities (excludes tmpfs, cgroup, etc.)")]
    async fn system_disk(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "system.disk";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match self.system_provider.system_disk().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Get system uptime and idle time in seconds")]
    async fn system_uptime(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "system.uptime";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match self.system_provider.system_uptime().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Get 1/5/15 minute load averages and process counts")]
    async fn system_load(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "system.load";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match self.system_provider.system_load().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Get kernel version, machine arch, cmdline, and first 50 loaded modules")]
    async fn system_kernel(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "system.kernel";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match self.system_provider.system_kernel().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Reboot the machine via D-Bus org.freedesktop.login1.Manager.Reboot")]
    async fn system_reboot(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "system.reboot";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::system::system_reboot(&self.dbus_conn).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Set a kernel parameter via sysctl -w key=value")]
    async fn system_sysctl_set(&self, args: Parameters<SysctlSetArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "system.sysctl.set";
        let params = serde_json::json!({"key": args.0.key, "value": args.0.value});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::system::system_sysctl_set(&args.0.key, &args.0.value).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    // ── Process ───────────────────────────────────────────────────────────────

    #[tool(description = "List all processes with PID, name, user, state, RSS, threads")]
    async fn process_list(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "process.list";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::process::process_list().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Get top processes sorted by memory or cpu usage")]
    async fn process_top(&self, args: Parameters<ProcessTopArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "process.top";
        let sort = args.0.sort_by.unwrap_or_else(|| "memory".to_string());
        let lim = args.0.limit.unwrap_or(10);
        let params = serde_json::json!({"sort_by": sort, "limit": lim});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::process::process_top(&sort, lim).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Get process tree rooted at PID 1 with parent-child relationships")]
    async fn process_tree(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "process.tree";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::process::process_tree().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Get detailed info for one PID: threads, cgroups, environ (truncated)")]
    async fn process_inspect(&self, args: Parameters<ProcessPidArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "process.inspect";
        let params = serde_json::json!({"pid": args.0.pid});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::process::process_inspect(args.0.pid).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "List open file descriptors for a process by PID")]
    async fn process_open_files(&self, args: Parameters<ProcessPidArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "process.open-files";
        let params = serde_json::json!({"pid": args.0.pid});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::process::process_open_files(args.0.pid).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Send SIGTERM (default) or SIGKILL to a process by PID")]
    async fn process_kill(&self, args: Parameters<ProcessKillArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "process.kill";
        let force = args.0.force.unwrap_or(false);
        let params = serde_json::json!({"pid": args.0.pid, "force": force});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::process::process_kill(args.0.pid, force).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Send an arbitrary signal number to a process")]
    async fn process_signal(&self, args: Parameters<ProcessSignalArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "process.signal";
        let params = serde_json::json!({"pid": args.0.pid, "signum": args.0.signum});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::process::process_signal(args.0.pid, args.0.signum).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Change process scheduling priority (nice value -20 to 19)")]
    async fn process_nice(&self, args: Parameters<ProcessNiceArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "process.nice";
        let params = serde_json::json!({"pid": args.0.pid, "priority": args.0.priority});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::process::process_nice(args.0.pid, args.0.priority).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    // ── Service ───────────────────────────────────────────────────────────────

    #[tool(description = "List all systemd service units with state and description")]
    async fn service_list(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "service.list";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::service::service_list(&self.dbus_conn).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Check the live status of a systemd unit")]
    async fn service_status(&self, args: Parameters<ServiceStatusArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "service.status";
        let params = serde_json::json!({"name": args.0.name});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::service::service_status(&args.0.name, &self.dbus_conn).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Tail journal entries for a systemd service unit")]
    async fn service_logs(&self, args: Parameters<ServiceLogsArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "service.logs";
        let lim = args.0.lines.unwrap_or(50);
        let params = serde_json::json!({"name": args.0.name, "lines": lim});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::service::service_logs(&args.0.name, lim).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Get dependency tree for a systemd unit (requires, wants, after, before)")]
    async fn service_dependencies(&self, args: Parameters<ServiceStatusArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "service.dependencies";
        let params = serde_json::json!({"name": args.0.name});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::service::service_dependencies(&args.0.name, &self.dbus_conn).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Start a systemd unit")]
    async fn service_start(&self, args: Parameters<ServiceStatusArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "service.start";
        let params = serde_json::json!({"name": args.0.name});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::service::service_start(&args.0.name, &self.dbus_conn).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Stop a systemd unit")]
    async fn service_stop(&self, args: Parameters<ServiceStatusArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "service.stop";
        let params = serde_json::json!({"name": args.0.name});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::service::service_stop(&args.0.name, &self.dbus_conn).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Restart a systemd unit")]
    async fn service_restart(&self, args: Parameters<ServiceStatusArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "service.restart";
        let params = serde_json::json!({"name": args.0.name});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::service::service_restart(&args.0.name, &self.dbus_conn).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Enable a systemd unit to start on boot (--now)")]
    async fn service_enable(&self, args: Parameters<ServiceStatusArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "service.enable";
        let params = serde_json::json!({"name": args.0.name});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::service::service_enable(&args.0.name, &self.dbus_conn).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Disable a systemd unit from starting on boot (--now)")]
    async fn service_disable(&self, args: Parameters<ServiceStatusArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "service.disable";
        let params = serde_json::json!({"name": args.0.name});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::service::service_disable(&args.0.name, &self.dbus_conn).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    // ── Log ───────────────────────────────────────────────────────────────────

    #[tool(description = "Tail global system journal entries, optionally filtered by unit")]
    async fn log_tail(&self, args: Parameters<LogTailArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "log.tail";
        let lim = args.0.lines.unwrap_or(50);
        let params = serde_json::json!({"unit": args.0.unit.clone(), "lines": lim});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::log::log_tail(args.0.unit.as_deref(), lim).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Search system logs for a keyword with optional time range and priority")]
    async fn log_search(&self, args: Parameters<LogSearchArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "log.search";
        let params = serde_json::json!({"keyword": args.0.keyword, "since": args.0.since.clone(), "priority": args.0.priority.clone()});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::log::log_search(&args.0.keyword, args.0.since.as_deref(), args.0.priority.as_deref()).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "List all systemd units that have journal entries")]
    async fn log_units(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "log.units";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::log::log_units().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Long-poll stream of new journal entries, returns after timeout_secs (default 5)")]
    async fn log_stream(&self, args: Parameters<LogStreamArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "log.stream";
        let timeout = args.0.timeout_secs.unwrap_or(5);
        let max_lines = args.0.max_lines.unwrap_or(100);
        let params = serde_json::json!({"unit": args.0.unit.clone(), "timeout_secs": timeout, "max_lines": max_lines});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::log::log_stream(args.0.unit.as_deref(), timeout, max_lines).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Trigger log rotation (journalctl --rotate)")]
    async fn log_rotate(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "log.rotate";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::log::log_rotate().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Remove old journal entries by size (size_mb) or age (days)")]
    async fn log_vacuum(&self, args: Parameters<LogVacuumArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "log.vacuum";
        let params = serde_json::json!({"size_mb": args.0.size_mb, "days": args.0.days});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::log::log_vacuum(args.0.size_mb, args.0.days).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    // ── Network ───────────────────────────────────────────────────────────────

    #[tool(description = "List network interfaces with name, MAC, MTU, and up/down status")]
    async fn network_interfaces(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "network.interfaces";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::network::network_interfaces().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "List IP addresses assigned to network interfaces")]
    async fn network_addresses(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "network.addresses";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::network::network_addresses().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "List routing table entries with destination, gateway, and prefix length")]
    async fn network_routes(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "network.routes";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::network::network_routes().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "List active TCP/UDP connections with state and UID")]
    async fn network_connections(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "network.connections";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::network::network_connections().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "List listening ports with PID and process name")]
    async fn network_ports(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "network.ports";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::network::network_ports() {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Get current DNS resolvers and search domains from /etc/resolv.conf")]
    async fn network_dns(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "network.dns";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::network::network_dns() {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Add an iptables rule to a chain")]
    async fn network_firewall_add(&self, args: Parameters<FirewallArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "network.firewall.add";
        let table = args.0.table.as_deref().unwrap_or("filter");
        let params = serde_json::json!({"table": table, "chain": args.0.chain, "rule": args.0.rule});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::network::network_firewall_add(table, &args.0.chain, &args.0.rule).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Remove an iptables rule from a chain")]
    async fn network_firewall_remove(&self, args: Parameters<FirewallArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "network.firewall.remove";
        let table = args.0.table.as_deref().unwrap_or("filter");
        let params = serde_json::json!({"table": table, "chain": args.0.chain, "rule": args.0.rule});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::network::network_firewall_remove(table, &args.0.chain, &args.0.rule).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    // ── File ──────────────────────────────────────────────────────────────────

    #[tool(description = "Get file or directory metadata: size, permissions, timestamps")]
    async fn file_info(&self, args: Parameters<FileInfoArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "file.stat";
        let params = serde_json::json!({"path": args.0.path});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::file::file_info(&args.0.path).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "List directory contents with name, type, and size")]
    async fn file_list(&self, args: Parameters<FileListArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "file.list-dir";
        let params = serde_json::json!({"path": args.0.path});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::file::file_list(&args.0.path).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Read file contents (text, up to max_bytes)")]
    async fn file_read(&self, args: Parameters<FileReadArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "file.read";
        let params = serde_json::json!({"path": args.0.path, "max_bytes": args.0.max_bytes});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::file::file_read(&args.0.path, args.0.max_bytes).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Get the last N lines of a file")]
    async fn file_tail(&self, args: Parameters<FileTailArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "file.tail";
        let lines = args.0.lines.unwrap_or(50);
        let params = serde_json::json!({"path": args.0.path, "lines": lines});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::file::file_tail(&args.0.path, lines).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Search files in a directory for a literal string pattern")]
    async fn file_search(&self, args: Parameters<FileSearchArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "file.search";
        let params = serde_json::json!({"dir": args.0.dir, "pattern": args.0.pattern, "max_results": args.0.max_results});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::file::file_search(&args.0.dir, &args.0.pattern, args.0.max_results).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Write content to a file (allowed directories only, sensitive files blocked)")]
    async fn file_write(&self, args: Parameters<FileWriteArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "file.write";
        let params = serde_json::json!({"path": args.0.path, "bytes": args.0.content.len()});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::file::file_write(&args.0.path, &args.0.content).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Create a directory (and all parents) at path")]
    async fn file_mkdir(&self, args: Parameters<FileMkdirArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "file.mkdir";
        let params = serde_json::json!({"path": args.0.path});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::file::file_mkdir(&args.0.path).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Change file permissions (mode in decimal, e.g. 420 = 0o644)")]
    async fn file_chmod(&self, args: Parameters<FileChmodArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "file.chmod";
        let params = serde_json::json!({"path": args.0.path, "mode": args.0.mode});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::file::file_chmod(&args.0.path, args.0.mode).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    // ── Container ─────────────────────────────────────────────────────────────

    #[tool(description = "List all Docker containers with state and image")]
    async fn container_list(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "container.list";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::container::container_list().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Get detailed state for one container (running, exit_code, started_at)")]
    async fn container_status(&self, args: Parameters<ContainerIdArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "container.status";
        let params = serde_json::json!({"id": args.0.id});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::container::container_status(&args.0.id).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Get container log output (last N lines or since timestamp)")]
    async fn container_logs(&self, args: Parameters<ContainerLogsArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "container.logs";
        let params = serde_json::json!({"id": args.0.id, "lines": args.0.lines, "since": args.0.since.clone()});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::container::container_logs(&args.0.id, args.0.lines, args.0.since.as_deref()).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Get live CPU, memory, and network stats for a Docker container")]
    async fn container_stats(&self, args: Parameters<ContainerStatsArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "container.stats";
        let params = serde_json::json!({"id": args.0.id});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::container::container_stats(&args.0.id).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Get full container config and state (Mounts, Env, NetworkSettings)")]
    async fn container_inspect(&self, args: Parameters<ContainerIdArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "container.inspect";
        let params = serde_json::json!({"id": args.0.id});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::container::container_inspect(&args.0.id).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Start a stopped container")]
    async fn container_start(&self, args: Parameters<ContainerIdArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "container.start";
        let params = serde_json::json!({"id": args.0.id});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::container::container_start(&args.0.id).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Stop a running container")]
    async fn container_stop(&self, args: Parameters<ContainerIdArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "container.stop";
        let params = serde_json::json!({"id": args.0.id});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::container::container_stop(&args.0.id).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Restart a container")]
    async fn container_restart(&self, args: Parameters<ContainerIdArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "container.restart";
        let params = serde_json::json!({"id": args.0.id});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::container::container_restart(&args.0.id).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Remove a stopped container (force=true to remove running)")]
    async fn container_remove(&self, args: Parameters<ContainerRemoveArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "container.remove";
        let force = args.0.force.unwrap_or(false);
        let params = serde_json::json!({"id": args.0.id, "force": force});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::container::container_remove(&args.0.id, force).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    // ── Package ───────────────────────────────────────────────────────────────

    #[tool(description = "List installed system packages from the dpkg database")]
    async fn package_list(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "package.list";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::package::package_list().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "List available package updates")]
    async fn package_updates(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "package.updates";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::package::package_updates().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Search available packages by name or description")]
    async fn package_search(&self, args: Parameters<PackageSearchArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "package.search";
        let params = serde_json::json!({"query": args.0.query});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::package::package_search(&args.0.query).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Get detailed info for an installed package")]
    async fn package_info(&self, args: Parameters<PackageNameArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "package.info";
        let params = serde_json::json!({"name": args.0.name});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::package::package_info(&args.0.name).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Install a package via apt-get (requires root)")]
    async fn package_install(&self, args: Parameters<PackageNameArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "package.install";
        let params = serde_json::json!({"name": args.0.name});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::package::package_install(&args.0.name).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Update a specific package or all packages if name is omitted")]
    async fn package_update(&self, args: Parameters<PackageUpdateArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "package.update";
        let params = serde_json::json!({"name": args.0.name});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::package::package_update(args.0.name.as_deref()).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Remove a package via apt-get")]
    async fn package_remove(&self, args: Parameters<PackageNameArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "package.remove";
        let params = serde_json::json!({"name": args.0.name});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::package::package_remove(&args.0.name).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    // ── Identity ──────────────────────────────────────────────────────────────

    #[tool(description = "List all local users from /etc/passwd")]
    async fn identity_users(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "identity.users";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::identity::identity_users().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "List all local groups and their members from /etc/group")]
    async fn identity_groups(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "identity.groups";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::identity::identity_groups().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Parse /etc/sudoers and drop-ins to map privilege escalation rules")]
    async fn identity_sudoers(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "identity.sudoers";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::identity::identity_sudoers().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "List authorized SSH public keys for a user")]
    async fn identity_ssh_keys_list(&self, args: Parameters<SshKeysListArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "identity.ssh-keys.list";
        let params = serde_json::json!({"username": args.0.username});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::identity::identity_ssh_keys_list(&args.0.username).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Add an SSH public key to a user's authorized_keys")]
    async fn identity_ssh_keys_add(&self, args: Parameters<SshKeysAddArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "identity.ssh-keys.add";
        let params = serde_json::json!({"username": args.0.username});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::identity::identity_ssh_keys_add(&args.0.username, &args.0.key).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Remove an SSH key matching key_identifier from a user's authorized_keys")]
    async fn identity_ssh_keys_remove(&self, args: Parameters<SshKeysRemoveArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "identity.ssh-keys.remove";
        let params = serde_json::json!({"username": args.0.username, "key_identifier": args.0.key_identifier});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::identity::identity_ssh_keys_remove(&args.0.username, &args.0.key_identifier).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Lock a user account (passwd -l)")]
    async fn identity_user_lock(&self, args: Parameters<UserLockArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "identity.user.lock";
        let params = serde_json::json!({"username": args.0.username});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::identity::identity_user_lock(&args.0.username).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    // ── Storage ───────────────────────────────────────────────────────────────

    #[tool(description = "List physical block devices, partitions, sizes, and filesystem types")]
    async fn storage_block_list(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "storage.block.list";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::storage::storage_block_list().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Parse /etc/fstab to show persistent mount configurations")]
    async fn storage_mounts_fstab(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "storage.mounts.fstab";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::storage::storage_mounts_fstab().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "List LVM Physical Volumes, Volume Groups, and Logical Volumes")]
    async fn storage_lvm_list(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "storage.lvm.list";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::storage::storage_lvm_list().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Get S.M.A.R.T. health metrics for a physical drive (requires smartmontools)")]
    async fn storage_smart_health(&self, args: Parameters<SmartHealthArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "storage.smart.health";
        let params = serde_json::json!({"device": args.0.device});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::storage::storage_smart_health(&args.0.device).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Mount a block device to a directory")]
    async fn storage_mount(&self, args: Parameters<MountArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "storage.mount";
        let params = serde_json::json!({"device": args.0.device, "mountpoint": args.0.mountpoint});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::storage::storage_mount(&args.0.device, &args.0.mountpoint, args.0.fstype.as_deref()).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Safely unmount a filesystem")]
    async fn storage_unmount(&self, args: Parameters<UnmountArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "storage.unmount";
        let params = serde_json::json!({"mountpoint": args.0.mountpoint});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::storage::storage_unmount(&args.0.mountpoint).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    // ── Schedule ──────────────────────────────────────────────────────────────

    #[tool(description = "List all cron jobs from system-wide and user crontabs")]
    async fn schedule_cron_list(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "schedule.cron.list";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::schedule::schedule_cron_list().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "List active systemd timers and their next execution time")]
    async fn schedule_timers_list(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "schedule.timers.list";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::schedule::schedule_timers_list().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Add a new cron job for a user")]
    async fn schedule_cron_add(&self, args: Parameters<CronAddArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "schedule.cron.add";
        let params = serde_json::json!({"username": args.0.username, "schedule": args.0.schedule, "command": args.0.command});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::schedule::schedule_cron_add(&args.0.username, &args.0.schedule, &args.0.command).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Remove cron jobs matching a command pattern for a user")]
    async fn schedule_cron_remove(&self, args: Parameters<CronRemoveArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "schedule.cron.remove";
        let params = serde_json::json!({"username": args.0.username, "command_pattern": args.0.command_pattern});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::schedule::schedule_cron_remove(&args.0.username, &args.0.command_pattern).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    // ── Security ──────────────────────────────────────────────────────────────

    #[tool(description = "Check SELinux or AppArmor enforcement state")]
    async fn security_mac_status(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "security.mac.status";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::security::security_mac_status().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Scan a path for x509 certificates and return expiry dates (soonest first)")]
    async fn security_certs_check(&self, args: Parameters<CertsCheckArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "security.certs.check";
        let params = serde_json::json!({"path": args.0.path});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::security::security_certs_check(&args.0.path).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "List active auditd kernel audit rules (requires auditd)")]
    async fn security_auditd_rules(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "security.auditd.rules";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::security::security_auditd_rules().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    // ── Time ──────────────────────────────────────────────────────────────────

    #[tool(description = "Get NTP sync state, stratum, offset, and active NTP servers")]
    async fn time_status(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "time.status";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::time::time_status(&self.dbus_conn).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Force an immediate NTP clock synchronization via chronyc makestep")]
    async fn time_sync(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "time.sync";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::time::time_sync().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    // ── Hardware ──────────────────────────────────────────────────────────────

    #[tool(description = "Read CPU temperatures and fan speeds from sysfs thermal zones and hwmon")]
    async fn hardware_sensors(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "hardware.sensors";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::hardware::hardware_sensors().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "List PCI devices and kernel drivers using lspci")]
    async fn hardware_pci(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "hardware.pci";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::hardware::hardware_pci().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "List connected USB devices from /sys/bus/usb/devices")]
    async fn hardware_usb(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "hardware.usb";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::hardware::hardware_usb().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    // ── Desktop ───────────────────────────────────────────────────────────────

    #[tool(description = "List open windows with title, geometry, and desktop (requires wmctrl)")]
    async fn desktop_windows(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "desktop.windows";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::desktop::desktop_windows().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "List running application class names (requires wmctrl)")]
    async fn desktop_apps(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "desktop.apps";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::desktop::desktop_apps().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Get current clipboard content (text)")]
    async fn desktop_clipboard(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "desktop.clipboard";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::desktop::desktop_clipboard().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Get now-playing media info via MPRIS D-Bus (track, artist, state)")]
    async fn desktop_media(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "desktop.media";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::desktop::desktop_media(&self.session_conn).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Get current desktop theme (dark/light) and color scheme")]
    async fn desktop_theme(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "desktop.theme";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::desktop::desktop_theme().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Get current audio volume level and mute state")]
    async fn desktop_volume(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "desktop.volume";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::desktop::desktop_volume().await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Focus a window by ID (requires wmctrl)")]
    async fn desktop_focus(&self, args: Parameters<WindowIdArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "desktop.focus";
        let params = serde_json::json!({"window_id": args.0.window_id});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::desktop::desktop_focus(&args.0.window_id).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Close a window by ID (requires wmctrl)")]
    async fn desktop_close(&self, args: Parameters<WindowIdArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "desktop.close";
        let params = serde_json::json!({"window_id": args.0.window_id});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::desktop::desktop_close(&args.0.window_id).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Launch an application by name or .desktop entry")]
    async fn desktop_launch(&self, args: Parameters<LaunchAppArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "desktop.launch";
        let params = serde_json::json!({"app": args.0.app});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::desktop::desktop_launch(&args.0.app).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Set audio volume level (0-100)")]
    async fn desktop_set_volume(&self, args: Parameters<SetVolumeArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "desktop.set-volume";
        let params = serde_json::json!({"percent": args.0.percent});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::desktop::desktop_set_volume(args.0.percent).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Toggle desktop theme: 'dark' or 'light' (gsettings)")]
    async fn desktop_set_theme(&self, args: Parameters<SetThemeArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "desktop.set-theme";
        let params = serde_json::json!({"mode": args.0.mode});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::desktop::desktop_set_theme(&args.0.mode).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }

    #[tool(description = "Send a desktop notification via org.freedesktop.Notifications")]
    async fn desktop_notify(&self, args: Parameters<NotifyArgs>) -> Result<CallToolResult, McpError> {
        let tool_name = "desktop.notify";
        let urgency = args.0.urgency.unwrap_or(1);
        let body = args.0.body.as_deref().unwrap_or("");
        let params = serde_json::json!({"summary": args.0.summary, "urgency": urgency});
        let start = self.start_tool_call(tool_name, &params).await?;
        match crate::native::desktop::desktop_notify(&self.session_conn, &args.0.summary, body, urgency).await {
            Ok(v)  => { self.complete_tool_call(tool_name, &params, start, true).await;  Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&v).unwrap_or_default())])) }
            Err(e) => { self.complete_tool_call(tool_name, &params, start, false).await; Err(Self::internal_error(e)) }
        }
    }
}

#[tool_handler]
impl ServerHandler for NeurondEngine {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "Neurond is a Linux system controller. It provides tools to observe \
                 and manage system resources, services, processes, logs, network, \
                 files, containers, packages, identity, storage, schedule, security, \
                 time, hardware, and desktop.".into()
            ),
        }
    }
}
