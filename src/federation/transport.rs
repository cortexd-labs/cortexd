// Transport helpers for downstream connections.
//
// stdio:     TokioChildProcess (rmcp) — private pipe pair, kill_on_drop(true)
// localhost: SseClientTransport (rmcp) — loopback-only, verify_loopback() enforced
//
// TODO: implement — see tasks/todo.md "FEAT: localhost HTTP downstream connection"
