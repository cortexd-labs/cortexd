use rmcp::{
    handler::server::{ServerHandler, tool::ToolRouter, wrapper::Parameters},
    model::*,
    tool, tool_handler, tool_router,
    ErrorData as McpError,
};
use zbus::Connection;
use crate::engine::policy::Policy;
use crate::engine::audit::AuditLogger;
use crate::providers::system::SystemProvider;
use std::sync::Arc;

#[derive(Clone)]
pub struct NeurondEngine {
    tool_router: ToolRouter<Self>,
    pub dbus_conn: Arc<Connection>,
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

// ── Argument structs ──────────────────────────────────────────────────

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct ProcessTopArgs {
    #[schemars(description = "Sort by 'memory' or 'cpu'")]
    pub sort_by: Option<String>,
    #[schemars(description = "Number of processes to return (default 10)")]
    pub limit: Option<usize>,
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
pub struct ContainerStatsArgs {
    #[schemars(description = "Container ID or name")]
    pub id: String,
}

// ── Tool implementations ──────────────────────────────────────────────

#[tool_router]
impl NeurondEngine {
    pub fn new(dbus_conn: Arc<Connection>, policy: Arc<Policy>, audit: Arc<AuditLogger>, system_provider: Arc<dyn SystemProvider>) -> Self {
        Self {
            tool_router: Self::tool_router(),
            dbus_conn,
            policy,
            audit,
            system_provider,
        }
    }

    // ── System tools ──────────────────────────────────────────────────

    #[tool(description = "Get system information: hostname, kernel, uptime, CPU count, total memory")]
    async fn system_info(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "system.info";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;

        match self.system_provider.system_info().await {
            Ok(info) => {
                self.complete_tool_call(tool_name, &params, start, true).await;
                Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&info).unwrap_or_default())]))
            }
            Err(e) => {
                self.complete_tool_call(tool_name, &params, start, false).await;
                Err(Self::internal_error(e))
            }
        }
    }

    #[tool(description = "Get short CPU information mapping total percent usage and core count")]
    async fn system_cpu(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "system.cpu";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;

        match self.system_provider.system_cpu().await {
            Ok(info) => {
                self.complete_tool_call(tool_name, &params, start, true).await;
                Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&info).unwrap_or_default())]))
            }
            Err(e) => {
                self.complete_tool_call(tool_name, &params, start, false).await;
                Err(Self::internal_error(e))
            }
        }
    }

    #[tool(description = "Get memory information including total, free, and available in MB")]
    async fn system_memory(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "system.memory";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;

        match self.system_provider.system_memory().await {
            Ok(info) => {
                self.complete_tool_call(tool_name, &params, start, true).await;
                Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&info).unwrap_or_default())]))
            }
            Err(e) => {
                self.complete_tool_call(tool_name, &params, start, false).await;
                Err(Self::internal_error(e))
            }
        }
    }

    #[tool(description = "Get disk mount capacities ignoring synthetic systems like tmpfs or cgroup")]
    async fn system_disk(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "system.disk";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;

        match self.system_provider.system_disk().await {
            Ok(info) => {
                self.complete_tool_call(tool_name, &params, start, true).await;
                Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&info).unwrap_or_default())]))
            }
            Err(e) => {
                self.complete_tool_call(tool_name, &params, start, false).await;
                Err(Self::internal_error(e))
            }
        }
    }

    #[tool(description = "Get system uptime bounds")]
    async fn system_uptime(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "system.uptime";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;

        match self.system_provider.system_uptime().await {
            Ok(info) => {
                self.complete_tool_call(tool_name, &params, start, true).await;
                Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&info).unwrap_or_default())]))
            }
            Err(e) => {
                self.complete_tool_call(tool_name, &params, start, false).await;
                Err(Self::internal_error(e))
            }
        }
    }

    // ── Process tools ─────────────────────────────────────────────────

    #[tool(description = "Get a list of all processes on the system mapped from procfs")]
    async fn process_list(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "process.list";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;

        match crate::providers::process::process_list().await {
            Ok(info) => {
                self.complete_tool_call(tool_name, &params, start, true).await;
                Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&info).unwrap_or_default())]))
            }
            Err(e) => {
                self.complete_tool_call(tool_name, &params, start, false).await;
                Err(Self::internal_error(e))
            }
        }
    }

    #[tool(description = "Get top processes sorted by memory or cpu usage")]
    async fn process_top(
        &self,
        params: Parameters<ProcessTopArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool_name = "process.top";
        let sort = params.0.sort_by.unwrap_or_else(|| "memory".to_string());
        let lim = params.0.limit.unwrap_or(10);
        let params_json = serde_json::json!({"sort_by": sort, "limit": lim});

        let start = self.start_tool_call(tool_name, &params_json).await?;

        match crate::providers::process::process_top(&sort, lim).await {
            Ok(info) => {
                self.complete_tool_call(tool_name, &params_json, start, true).await;
                Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&info).unwrap_or_default())]))
            }
            Err(e) => {
                self.complete_tool_call(tool_name, &params_json, start, false).await;
                Err(Self::internal_error(e))
            }
        }
    }

    // ── Service tools ─────────────────────────────────────────────────

    #[tool(description = "List all D-bus service units managed by systemd")]
    async fn service_list(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "service.list";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;

        match crate::providers::service::service_list(&self.dbus_conn).await {
            Ok(info) => {
                self.complete_tool_call(tool_name, &params, start, true).await;
                Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&info).unwrap_or_default())]))
            }
            Err(e) => {
                self.complete_tool_call(tool_name, &params, start, false).await;
                Err(Self::internal_error(e))
            }
        }
    }

    #[tool(description = "Check the live status of a systemd unit")]
    async fn service_status(
        &self,
        args: Parameters<ServiceStatusArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool_name = "service.status";
        let params = serde_json::json!({"name": args.0.name});
        let start = self.start_tool_call(tool_name, &params).await?;

        match crate::providers::service::service_status(&args.0.name, &self.dbus_conn).await {
            Ok(info) => {
                self.complete_tool_call(tool_name, &params, start, true).await;
                Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&info).unwrap_or_default())]))
            }
            Err(e) => {
                self.complete_tool_call(tool_name, &params, start, false).await;
                Err(Self::internal_error(e))
            }
        }
    }

    #[tool(description = "Tail log entries from the journal for a local systemd service unit")]
    async fn service_logs(
        &self,
        args: Parameters<ServiceLogsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool_name = "service.logs";
        let lim = args.0.lines.unwrap_or(50);
        let params = serde_json::json!({"name": args.0.name, "lines": lim});
        let start = self.start_tool_call(tool_name, &params).await?;

        match crate::providers::service::service_logs(&args.0.name, lim).await {
            Ok(info) => {
                self.complete_tool_call(tool_name, &params, start, true).await;
                Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&info).unwrap_or_default())]))
            }
            Err(e) => {
                self.complete_tool_call(tool_name, &params, start, false).await;
                Err(Self::internal_error(e))
            }
        }
    }

    // ── Log tools ─────────────────────────────────────────────────────

    #[tool(description = "Tail global system log entries from the journald service")]
    async fn log_tail(
        &self,
        args: Parameters<LogTailArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool_name = "log.tail";
        let lim = args.0.lines.unwrap_or(50);
        let params = serde_json::json!({"unit": args.0.unit.clone(), "lines": lim});
        let start = self.start_tool_call(tool_name, &params).await?;

        match crate::providers::log::log_tail(args.0.unit.as_deref(), lim).await {
            Ok(info) => {
                self.complete_tool_call(tool_name, &params, start, true).await;
                Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&info).unwrap_or_default())]))
            }
            Err(e) => {
                self.complete_tool_call(tool_name, &params, start, false).await;
                Err(Self::internal_error(e))
            }
        }
    }

    #[tool(description = "Search system logs for a string keyword matched strictly")]
    async fn log_search(
        &self,
        args: Parameters<LogSearchArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool_name = "log.search";
        let params = serde_json::json!({"keyword": args.0.keyword, "since": args.0.since.clone(), "priority": args.0.priority.clone()});
        let start = self.start_tool_call(tool_name, &params).await?;

        match crate::providers::log::log_search(&args.0.keyword, args.0.since.as_deref(), args.0.priority.as_deref()).await {
             Ok(info) => {
                self.complete_tool_call(tool_name, &params, start, true).await;
                Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&info).unwrap_or_default())]))
            }
            Err(e) => {
                self.complete_tool_call(tool_name, &params, start, false).await;
                Err(Self::internal_error(e))
            }
        }
    }

    // ── Network tools ─────────────────────────────────────────────────

    #[tool(description = "List network interfaces with name, MAC, MTU, and up/down status")]
    async fn network_interfaces(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "network.interfaces";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;

        match crate::providers::network::network_interfaces().await {
            Ok(info) => {
                self.complete_tool_call(tool_name, &params, start, true).await;
                Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&info).unwrap_or_default())]))
            }
            Err(e) => {
                self.complete_tool_call(tool_name, &params, start, false).await;
                Err(Self::internal_error(e))
            }
        }
    }

    #[tool(description = "List IP addresses assigned to network interfaces")]
    async fn network_addresses(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "network.addresses";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;

        match crate::providers::network::network_addresses().await {
            Ok(info) => {
                self.complete_tool_call(tool_name, &params, start, true).await;
                Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&info).unwrap_or_default())]))
            }
            Err(e) => {
                self.complete_tool_call(tool_name, &params, start, false).await;
                Err(Self::internal_error(e))
            }
        }
    }

    #[tool(description = "List routing table entries with destination, gateway, and prefix length")]
    async fn network_routes(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "network.routes";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;

        match crate::providers::network::network_routes().await {
            Ok(info) => {
                self.complete_tool_call(tool_name, &params, start, true).await;
                Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&info).unwrap_or_default())]))
            }
            Err(e) => {
                self.complete_tool_call(tool_name, &params, start, false).await;
                Err(Self::internal_error(e))
            }
        }
    }

    #[tool(description = "List active TCP connections with local/remote addresses, state, and UID")]
    async fn network_connections(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "network.connections";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;

        match crate::providers::network::network_connections().await {
            Ok(info) => {
                self.complete_tool_call(tool_name, &params, start, true).await;
                Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&info).unwrap_or_default())]))
            }
            Err(e) => {
                self.complete_tool_call(tool_name, &params, start, false).await;
                Err(Self::internal_error(e))
            }
        }
    }

    // ── File tools ────────────────────────────────────────────────────

    #[tool(description = "Get file or directory metadata: size, permissions, timestamps")]
    async fn file_info(
        &self,
        args: Parameters<FileInfoArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool_name = "file.info";
        let params = serde_json::json!({"path": args.0.path});
        let start = self.start_tool_call(tool_name, &params).await?;

        match crate::providers::file::file_info(&args.0.path).await {
            Ok(info) => {
                self.complete_tool_call(tool_name, &params, start, true).await;
                Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&info).unwrap_or_default())]))
            }
            Err(e) => {
                self.complete_tool_call(tool_name, &params, start, false).await;
                Err(Self::internal_error(e))
            }
        }
    }

    #[tool(description = "List directory contents with name, type, and size")]
    async fn file_list(
        &self,
        args: Parameters<FileListArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool_name = "file.list";
        let params = serde_json::json!({"path": args.0.path});
        let start = self.start_tool_call(tool_name, &params).await?;

        match crate::providers::file::file_list(&args.0.path).await {
            Ok(info) => {
                self.complete_tool_call(tool_name, &params, start, true).await;
                Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&info).unwrap_or_default())]))
            }
            Err(e) => {
                self.complete_tool_call(tool_name, &params, start, false).await;
                Err(Self::internal_error(e))
            }
        }
    }

    // ── Container tools ───────────────────────────────────────────────

    #[tool(description = "List all Docker containers with their state and image")]
    async fn container_list(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "container.list";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;

        match crate::providers::container::container_list().await {
            Ok(info) => {
                self.complete_tool_call(tool_name, &params, start, true).await;
                Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&info).unwrap_or_default())]))
            }
            Err(e) => {
                self.complete_tool_call(tool_name, &params, start, false).await;
                Err(Self::internal_error(e))
            }
        }
    }

    #[tool(description = "Get live CPU, memory, and network stats for a Docker container")]
    async fn container_stats(
        &self,
        args: Parameters<ContainerStatsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool_name = "container.stats";
        let params = serde_json::json!({"id": args.0.id});
        let start = self.start_tool_call(tool_name, &params).await?;

        match crate::providers::container::container_stats(&args.0.id).await {
            Ok(info) => {
                self.complete_tool_call(tool_name, &params, start, true).await;
                Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&info).unwrap_or_default())]))
            }
            Err(e) => {
                self.complete_tool_call(tool_name, &params, start, false).await;
                Err(Self::internal_error(e))
            }
        }
    }

    // ── Package tools ─────────────────────────────────────────────────

    #[tool(description = "List installed system packages from the dpkg database")]
    async fn package_list(&self) -> Result<CallToolResult, McpError> {
        let tool_name = "package.list";
        let params = serde_json::json!({});
        let start = self.start_tool_call(tool_name, &params).await?;

        match crate::providers::package::package_list().await {
            Ok(info) => {
                self.complete_tool_call(tool_name, &params, start, true).await;
                Ok(CallToolResult::success(vec![Content::text(serde_json::to_string(&info).unwrap_or_default())]))
            }
            Err(e) => {
                self.complete_tool_call(tool_name, &params, start, false).await;
                Err(Self::internal_error(e))
            }
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
                 files, containers, and packages.".into()
            ),
        }
    }
}
