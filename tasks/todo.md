# neurond: Federation Proxy — Task Backlog

Derived from senior tech lead review (2026-02-26).
neurond is the federation proxy that aggregates tools from downstream MCP servers
(e.g., mcpd) and exposes them upstream to cortexd.

Priority scale: **P1** = security/correctness bug · **P2** = reliability/maintainability · **P3** = Rust idioms · **P4** = testing gaps

---

## P1 — Security & Correctness

---

### [ ] FIX: Default bind `127.0.0.1` — implement TLS before opening to network

**Category:** Security
**File:** `src/config.rs`
**Status:** Default changed to `127.0.0.1` (2026-02-26)

**Problem:**
neurond is designed to listen on `:8443` for cortexd over mTLS, but there is zero TLS implementation. Opening to the network without TLS allows unauthenticated remote tool invocation.

**Fix:**
Implement TLS using `axum-server` + `rustls`:

1. Add `tls` section to `neurond.toml` (cert_path, key_path, ca_path)
2. Use `axum_server::bind_rustls()` when TLS config is present
3. Validate certs at startup, fail-fast on invalid certs
4. Only then change default bind back to `0.0.0.0`

---

### [ ] FIX: `node_id` regenerated on every startup

**Category:** Security / Correctness
**File:** `src/config.rs:97`

**Problem:**
`generate_node_id()` creates a new UUID on every cold start. cortexd sees a new node each time — no persistence across reboots.

**Fix:**
Persist to `/var/lib/neurond/node_id`:

```rust
fn generate_or_load_node_id() -> String {
    let path = "/var/lib/neurond/node_id";
    if let Ok(id) = std::fs::read_to_string(path) {
        return id.trim().to_string();
    }
    let id = uuid::Uuid::new_v4().to_string();
    let _ = std::fs::create_dir_all("/var/lib/neurond");
    let _ = std::fs::write(path, &id);
    id
}
```

Dev fallback: use `./node_id` in CWD.

---

### [ ] FIX: Audit log failure must not silently allow mutations

**Category:** Security
**Files:** `src/security/audit.rs`, `src/upstream/server.rs`

**Problem:**
`AuditLogger::log()` returns `()`. Disk-full + mutation = unaudited action.

**Fix:**
Return `anyhow::Result<()>`, propagate failures for mutation tools.

---

### [ ] FIX: Policy engine — deny-wins semantics

**Category:** Security / Correctness
**File:** `src/security/policy.rs`

**Problem:**
Last-matching-rule-wins semantics. Deny should always win.

**Fix:**
If any deny matches, return false immediately. Short-circuit.

---

### [ ] FIX: No graceful shutdown — heartbeat orphaned, no deregister

**Category:** Correctness
**File:** `src/main.rs`

**Problem:**
`axum::serve().await` blocks until killed. On SIGTERM:

- `deregister_node()` exists but is never called
- Heartbeat `watch::Sender` dropped without flush
- Downstream connections not drained

**Fix:**
Add signal handler:

```rust
tokio::spawn(async move {
    tokio::signal::ctrl_c().await.ok();
    // deregister, drop heartbeat, shutdown
});
axum::serve(listener, app)
    .with_graceful_shutdown(...)
    .await?;
```

---

### [ ] FIX: Config validation missing

**Category:** Security / Correctness
**File:** `src/config.rs`

**Problem:**
No validation after parsing:

- `namespace` could be empty or contain dots (breaks routing)
- `url` in Localhost variant could be malformed
- `command` in Stdio variant could be relative (PATH injection)
- Duplicate namespaces silently route to first match

**Fix:**
Add `Config::validate(&self) -> anyhow::Result<()>`:

```rust
fn validate(&self) -> anyhow::Result<()> {
    let mut seen = HashSet::new();
    for server in &self.federation.servers {
        anyhow::ensure!(!server.namespace.is_empty(), "namespace cannot be empty");
        anyhow::ensure!(!server.namespace.contains('.'), "namespace cannot contain dots");
        anyhow::ensure!(seen.insert(&server.namespace), "duplicate namespace: {}", server.namespace);
        match &server.transport {
            DownstreamTransport::Localhost { url } => {
                url.parse::<url::Url>().context("invalid downstream URL")?;
            }
            DownstreamTransport::Stdio { command, .. } => {
                anyhow::ensure!(command.starts_with('/'), "stdio command must be absolute path: {command}");
            }
        }
    }
    Ok(())
}
```

---

### [ ] IMPROVE: Extend wildcard matching to full glob patterns

**Category:** Usability
**File:** `src/security/policy.rs`

**Fix:**
Replace hand-rolled matching with `glob = "0.3"`.

---

## P2 — Reliability & Robustness

---

### [ ] FIX: `route_tool_call` holds RwLock across network I/O

**Category:** Reliability
**File:** `src/federation/manager.rs:98-148`

**Problem:**
Read guard held while `client.peer().call_tool().await` executes. Slow downstream (30s timeout) blocks all other calls because `add_downstream` needs a write guard.

**Fix:**
Clone client handle, drop lock before network call:

```rust
let client = {
    let downstreams = self.downstreams.read().await;
    // ... resolve, find conn ...
    conn.client.clone()
    // lock dropped here
};
client.peer().call_tool(params).await
```

---

### [ ] FIX: No reconnection logic for failed downstreams

**Category:** Reliability
**Files:** `src/federation/connection.rs`, `src/federation/manager.rs`

**Problem:**
`MAX_RETRIES` defined but never used. `mark_restarting()` exists but never called. Dead downstream stays `Healthy` with dead client.

**Fix:**
Implement background health check loop:

1. Spawn `tokio::spawn` per downstream
2. Periodic `client.peer().ping()` (or list_tools)
3. On failure: `mark_restarting()` → retry connect → `mark_healthy()` or `mark_failed()`
4. Respect `MAX_RETRIES` and `healthcheck_interval_secs` from config

---

### [ ] FIX: `reqwest::Client` created per-request in registration

**Category:** Performance
**File:** `src/registration/register.rs`

**Problem:**
Two separate `reqwest::Client::new()` calls (register + deregister). Client maintains connection pool; reusing saves FDs.

**Fix:**
Pass shared `reqwest::Client` from `main.rs` or use `once_cell::sync::Lazy`.

---

### [ ] IMPROVE: Cache aggregated tool list

**Category:** Performance
**File:** `src/federation/manager.rs:80-87`

**Problem:**
`.flat_map(|c| c.tools.clone())` allocates full clone on every `list_tools` request.

**Fix:**
Cache in `Arc<Vec<Tool>>`, rebuild only when downstreams change. list_tools becomes `Arc::clone()`.

---

## P3 — Rust Idioms & Code Quality

---

### [x] DONE: Added `Default` impl for `FederationManager`

**Status:** Fixed 2026-02-26

---

### [x] DONE: `sort_by` → `sort_by_key(Reverse)`

**Status:** Fixed 2026-02-26

---

### [x] DONE: Format string variables (`{var}` syntax)

**Status:** Fixed 2026-02-26

---

### [x] DONE: Removed unused `use tracing;`

**Status:** Fixed 2026-02-26

---

### [x] DONE: Suppressed `manual_async_fn` on `ServerHandler` impl

**Status:** Fixed 2026-02-26

---

### [x] DONE: Removed unused deps (`dashmap`, `schemars`, `tokio-stream`)

**Status:** Fixed 2026-02-26

---

### [x] DONE: Default bind changed `0.0.0.0` → `127.0.0.1`

**Status:** Fixed 2026-02-26

### [ ] CLEANUP: `Effect` should derive `Copy`

**File:** `src/security/policy.rs`

---

### [ ] CLEANUP: `DownstreamConnection` fields should be `pub(crate)` or private

**Category:** Encapsulation
**File:** `src/federation/connection.rs`

**Problem:**
All fields are `pub`, bypassing the state machine methods.

**Fix:**
Make fields `pub(crate)` or private with getters.

---

### [ ] CLEANUP: `gethostname()` should use syscall, not read `/etc/hostname`

**Category:** Linux best practice
**File:** `src/main.rs:99-103`

**Problem:**
Reading `/etc/hostname` may return stale value if hostname changed at runtime.

**Fix:**
Use `nix::unistd::gethostname()` or add `hostname = "0.3"` crate.

---

## P4 — Testing Gaps

---

### [ ] ADD: Tests for `connection.rs` state machine

**Category:** Testing
**File:** `src/federation/connection.rs` — **0 tests**

**Tests needed:**

- `Configured → Starting → Healthy` transition
- `Healthy → Restarting → Failed` transition
- `mark_restarting()` increments attempt counter
- `mark_failed()` clears tools and client
- `is_healthy()` requires both `Healthy` state and `client.is_some()`

---

### [ ] ADD: Tests for `config.rs` parsing

**Category:** Testing
**File:** `src/config.rs` — **0 tests**

**Tests needed:**

- Parse valid `neurond.toml` with all sections
- Parse minimal config (defaults applied correctly)
- Missing required fields → error
- Invalid transport type → error
- Default bind is `127.0.0.1`, default port is `8443`

---

### [ ] ADD: Integration test for transport layer

**Category:** Testing
**File:** `src/federation/transport.rs` — **0 tests**

**Tests needed:**

- Integration test: spin up in-process MCP server → connect via localhost → list_tools
- Stdio transport: spawn a simple echo MCP server → verify connection
- Invalid URL → meaningful error

---

### [ ] IMPROVE: `manager.rs` tests with mock downstreams

**Category:** Testing
**File:** `src/federation/manager.rs`

**Problem:**
Only empty-state tests exist. No tests with actual connected downstreams.

**Fix:**
Create a mock MCP server using rmcp's `ServerHandler` trait → connect manager → test routing.

---

## Architecture — Future Work

---

### [ ] DESIGN: Shared types crate (`neurond-protocol` or `mcp-types`)

**Problem:**
`RegisterPayload`, namespace conventions, API paths defined independently across neurond, mcpd, and eventually cortexd.

**Fix:**
Extract shared crate with registration payloads, heartbeat payloads, status enums, API path constants.

---

## Linux Best Practices

---

### [ ] ADD: systemd service file `neurond.service`

- `Type=simple`
- `User=neurond` (non-root service account)
- `Restart=on-failure`
- `ProtectSystem=strict`, `ProtectHome=yes`
- `After=network-online.target mcpd.service`

---

### [ ] ADD: Sample config file `neurond.toml.example`

Create a well-documented example config showing:

- Server bind/port
- mcpd downstream (localhost transport)
- Optional cortexd registration
- Stdio transport example

---

### [ ] ADD: PID file or systemd socket activation support

For production daemon management.

---

## End-to-End Integration Tests

---

### [ ] ADD: End-to-End Integration Tests for neurond

**Problem:**
Right now, `neurond` and `mcpd` are completely decoupled. We lack tests validating that `neurond` correctly manages the lifecycle of a downstream proxy, prefixes namespaces appropriately, enforces policy at the router edge, and handles timeouts/panics safely over IPC or Network layers.

**Fix:**
Create a dedicated `tests/integration/` suite validating standard workflows under real process execution.

**Specific Test Scenarios to Implement:**

1. **Stdio Lifecycle & Discovery (`test_stdio_discovery.rs`)**
   - **Setup:** Configure neurond to spawn `mcpd` across the `stdio` transport using `cargo run --bin mcpd`.
   - **Verify:** neurond successfully handshakes `initialize` with the child process, retrieves its tools, and correctly exposes them upstream prefixed with the `namespace` defined in `neurond.toml`.
   - **Teardown:** Verify that shutting down neurond safely sends a SIGTERM to the `mcpd` child process, avoiding orphaned zombied processes.

2. **Policy Enforcement Edge Context (`test_strict_policy_routing.rs`)**
   - **Setup:** Spin up neurond with a mock HTTP downstream and a strict `/etc/neurond/policy.toml` that denies `system.*` but allows `network.ping`.
   - **Verify:** Make a tool call upstream for `network.ping` and assert the downstream actually received the request.
   - **Verify:** Make a tool call upstream for `system.reboot` and assert it is instantly rejected with `INVALID_REQUEST` without any traffic reaching the downstream MCP.
   - **Verify:** Assert that both the ALLOWED and DENIED requests were successfully flushed to the `audit.log` file.

3. **Multi-Tenant Federation Integrity (`test_multi_downstream_isolation.rs`)**
   - **Setup:** Configure neurond with 3 different downstreams: Two `stdio` transports pointing to dummy MCP servers, and one `localhost` HTTP downstream.
   - **Verify:** `list_tools` across neurond successfully aggregates tools from all 3 downstreams linearly.
   - **Verify:** Issuing a tool call to downstream "A" does not accidentally execute or leak data to downstream "C".

4. **Network Resilience & Timeouts (`test_downstream_network_failures.rs`)**
   - **Setup:** Connect neurond to an HTTP downstream that accepts connections but sleeps infinitely (mock tarpit).
   - **Verify:** Firing a tool call to the tarpit downstream gracefully times out after 30 seconds rather than locking the `RwLock` federation manager permanently. Other concurrent tool calls should remain responsive.
