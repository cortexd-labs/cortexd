// Downstream spawn, restart policy, health checking, graceful shutdown.
//
// spawn_stdio_downstream()    — spawn a child process MCP server via stdio
// connect_localhost_downstream() — connect to a localhost HTTP MCP server
// monitor_downstream()        — watches for disconnect, restarts with backoff
// shutdown_all_downstreams()  — graceful shutdown on SIGTERM/SIGINT
//
// TODO: implement — see tasks/todo.md "FEAT: Lifecycle management"
