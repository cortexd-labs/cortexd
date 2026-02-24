// Top-level tool routing.
//
// Routes an incoming tool call to the correct handler:
//   - Native tools (system.*, process.*, …) → engine/server.rs handlers
//   - Namespaced federated tools (redis.get, pg.query, …) → federation/
//
// Currently all routing lives inside NeurondEngine in engine/server.rs.
// This module will extract that routing logic when federation is implemented.
//
// TODO: implement route_tool_call() — see tasks/todo.md "FEAT: Namespace routing"
