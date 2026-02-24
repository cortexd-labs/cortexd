// Local Federation Proxy — manages downstream MCP server connections.
//
// neurond acts as both an MCP server (upstream to cortexd) and an MCP client
// (downstream to local MCP servers like redis-mcp, postgres-mcp, etc.).
//
// See specs/neurond-federation-spec.md for the full design.
//
// TODO: implement FederationManager — see tasks/todo.md "Roadmap — Local Federation Proxy"

pub mod connection;
pub mod lifecycle;
pub mod namespace;
pub mod transport;
