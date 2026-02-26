use rmcp::{
    handler::server::ServerHandler,
    model::*,
    ErrorData as McpError,
    service::{RequestContext, RoleServer},
};
use std::sync::Arc;
use crate::federation::manager::FederationManager;
use crate::security::policy::Policy;
use crate::security::audit::AuditLogger;

/// ProxyEngine is the MCP ServerHandler that neurond exposes upstream (to cortexd).
///
/// It doesn't implement any tools directly — it delegates all tool calls
/// to the FederationManager, which routes them to the correct downstream.
#[derive(Clone)]
pub struct ProxyEngine {
    federation: Arc<FederationManager>,
    policy: Arc<Policy>,
    audit: Arc<AuditLogger>,
}

impl ProxyEngine {
    pub fn new(federation: Arc<FederationManager>, policy: Arc<Policy>, audit: Arc<AuditLogger>) -> Self {
        Self { federation, policy, audit }
    }

    /// Evaluates tool calls against the configured Policy and Audit log,
    /// before forwarding allowed calls to the federation multiplexer.
    pub async fn execute_tool_call(&self, request: CallToolRequestParams) -> Result<CallToolResult, McpError> {
        let tool_name = request.name.clone();
        let arguments = match request.arguments {
            Some(map) => serde_json::Value::Object(map),
            None => serde_json::json!({}),
        };

        let start = std::time::Instant::now();

        if !self.policy.is_allowed(&tool_name) {
            let _ = self.audit.log(&tool_name, &arguments, "denied", "blocked", 0).await;
            return Err(McpError {
                code: ErrorCode::INVALID_REQUEST,
                message: format!("Access denied to tool {} by security policy", tool_name).into(),
                data: None,
            });
        }

        tracing::info!(tool = %tool_name, "Routing tool call to downstream");

        let result = self.federation
            .route_tool_call(&tool_name, arguments.clone())
            .await;

        let duration = start.elapsed().as_millis() as u64;
        let result_str = if result.is_ok() { "success" } else { "error" };
        
        self.audit.log(&tool_name, &arguments, "allowed", result_str, duration)
            .await
            .map_err(|e| McpError {
                code: ErrorCode::INTERNAL_ERROR,
                message: format!("Audit logging failed (disk full?): {}", e).into(),
                data: None,
            })?;

        result
    }
}

#[allow(clippy::manual_async_fn)]
impl ServerHandler for ProxyEngine {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            server_info: Implementation {
                name: "neurond".to_string(),
                title: Some("neurond Federation Proxy".to_string()),
                version: env!("CARGO_PKG_VERSION").to_string(),
                description: Some("Routes tool calls to downstream MCP servers".to_string()),
                icons: None,
                website_url: None,
            },
            instructions: Some("neurond federation proxy — routes tool calls to downstream MCP servers".to_string()),
            ..Default::default()
        }
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
        async {
            let tools = self.federation.list_all_tools().await;
            Ok(ListToolsResult {
                tools,
                next_cursor: None,
                meta: None,
            })
        }
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResult, McpError>> + Send + '_ {
        async move {
            self.execute_tool_call(request).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_proxy_engine_info() {
        let mgr = Arc::new(FederationManager::new());
        let policy = Arc::new(Policy::default());
        let audit = Arc::new(AuditLogger::new("ignore.log"));
        let engine = ProxyEngine::new(mgr, policy, audit);
        let info = engine.get_info();
        assert_eq!(info.server_info.name, "neurond");
    }

    #[tokio::test]
    async fn test_proxy_engine_list_tools_empty() {
        let mgr = Arc::new(FederationManager::new());
        let policy = Arc::new(Policy::default());
        let audit = Arc::new(AuditLogger::new("ignore.log"));
        let engine = ProxyEngine::new(mgr, policy, audit);

        // Create a minimal RequestContext for testing
        // We use the default ServerHandler trait method through direct async call
        let tools = mgr_list_tools(&engine).await;
        assert!(tools.is_empty());
    }

    // Helper to call list_all_tools on the federation manager directly
    async fn mgr_list_tools(engine: &ProxyEngine) -> Vec<Tool> {
        engine.federation.list_all_tools().await
    }

    #[tokio::test]
    async fn test_proxy_engine_route_unknown_tool() {
        let mgr = Arc::new(FederationManager::new());
        let result = mgr.route_tool_call("unknown.tool", serde_json::json!({})).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_proxy_engine_policy_enforcement() {
        let mgr = Arc::new(FederationManager::new());

        // Create a policy that denies "dangerous.tool" but allows others
        let policy = Policy {
            default_action: crate::security::policy::Effect::Allow,
            rules: vec![crate::security::policy::PolicyRule {
                id: "deny-danger".into(),
                description: None,
                effect: crate::security::policy::Effect::Deny,
                tools: vec!["dangerous.*".into()],
            }],
        };

        let audit = Arc::new(AuditLogger::new("ignore.log"));
        let engine = ProxyEngine::new(mgr, Arc::new(policy), audit);

        let req = CallToolRequestParams {
            name: "dangerous.tool".into(),
            arguments: None,
            meta: None,
            task: None,
        };

        let result = engine.execute_tool_call(req).await;
        
        // It should be blocked before it even tries to route
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::INVALID_REQUEST);
        assert!(err.message.contains("Access denied to tool"));
    }
}
