# neurond

**MCP Federation Proxy** — aggregates multiple [MCP](https://modelcontextprotocol.io/) servers behind a single endpoint with namespaced tool routing.

neurond connects to downstream MCP servers (like [mcpd](https://github.com/cortexd-labs/mcpd)), discovers their tools, prefixes them with a namespace, and exposes them upstream as a unified tool registry.

---

## Architecture

```text
                    ┌─────────────────────────────────────────────┐
                    │                  Host                       │
                    │                                             │
  cortexd ──────────┤  ┌─────────────────────────────────────┐    │
  (fleet)   :8443   │  │           neurond                   │    │
                    │  │                                     │    │
                    │  │  ┌─────────────┐  ┌──────────────┐  │    │
                    │  │  │ upstream/   │  │ federation/  │  │    │
                    │  │  │             │  │              │  │    │
                    │  │  │ ProxyEngine │  │ manager.rs   │  │    │
                    │  │  │             │  │ namespace.rs │  │    │
                    │  │  │ security/   │  │ transport.rs │  │    │
                    │  │  │             │  │              │  │    │
                    │  │  │ policy.rs   │  │              │  │    │
                    │  │  │ audit.rs    │  │              │  │    │
                    │  │  └──────┬──────┘  └──────┬───────┘  │    │
                    │  │         │                 │          │    │
                    │  │         └─────────────────┘          │    │
                    │  │                  │                   │    │
                    │  └──────────────────┼───────────────────┘    │
                    │                     │                        │
                    │          ┌──────────┴──────────┐             │
                    │          ▼                     ▼             │
                    │  mcpd (localhost:8080)   redis-mcp (stdio)   │
                    │  namespace: "linux"      namespace: "redis"  │
                    │  linux.system.info       redis.get           │
                    │  linux.process.list      redis.set           │
                    │  linux.service.restart   redis.keys          │
                    └─────────────────────────────────────────────┘
```

---

## How It Works

1. **Config** — `neurond.toml` declares downstream MCP servers with namespace prefixes and transport types
2. **Connect** — On startup, neurond connects to each downstream and discovers their tools
3. **Namespace** — Each tool is prefixed: `system.info` from mcpd becomes `linux.system.info`
4. **Expose** — All namespaced tools are exposed as a single MCP server on `:8443`
5. **Security** — All incoming tool calls are evaluated against `policy.toml` and recorded in `audit.log`
6. **Route** — Incoming `linux.system.info` call → strip prefix → forward `system.info` to mcpd

---

## Configuration

```toml
# neurond.toml

[server]
bind = "127.0.0.1"   # localhost until TLS is implemented
port = 8443

# Optional: register with cortexd fleet orchestrator
# [registration]
# cortexd_url = "https://cortexd.example.com:9443"
# heartbeat_interval_secs = 30

# Downstream MCP servers
[[federation.servers]]
namespace = "linux"
transport = "localhost"
url = "http://127.0.0.1:8080/api/v1/mcp"

[[federation.servers]]
namespace = "redis"
transport = "stdio"
command = "/usr/local/bin/redis-mcp"
args = ["--mode", "stdio"]
```

### Transport Types

| Transport   | Description                                         | Use Case                  |
| ----------- | --------------------------------------------------- | ------------------------- |
| `localhost` | Connect via HTTP to a running MCP server            | mcpd, any HTTP MCP server |
| `stdio`     | Spawn a child process, communicate via stdin/stdout | Single-binary MCP tools   |

---

## Getting Started

### Prerequisites

- Linux (Debian 12 / Ubuntu 22.04+)
- Rust 1.75+
- At least one downstream MCP server (e.g., [mcpd](https://github.com/cortexd-labs/mcpd))

### Build & Run

```bash
git clone https://github.com/cortexd-labs/neurond.git
cd neurond
cargo build --release

# Create config
cp neurond.toml.example neurond.toml
# Edit neurond.toml to point at your downstream(s)

# Run (development)
cargo run

# Run (production)
./target/release/neurond
```

Server listens on `http://127.0.0.1:8443/api/v1/mcp`.

---

## Security

- **Deny-by-default policy** — `/etc/neurond/policy.toml` controls which namespaced tools are allowed. Mutations are blocked unless explicitly enabled.
- **Audit log** — Every tool call is logged as JSONL in `/var/log/neurond/audit.log` (timestamp, tool, params, decision, result, duration).

### Configure Policy (.toml)

```toml
default_action = "deny"

[[rules]]
id = "allow-safe-observability"
effect = "allow"
# You can use wildcards and namespaces
tools = ["linux.system.*", "redis.get", "linux.service.status"]

[[rules]]
id = "allow-linux-restart"
effect = "allow"
tools = ["linux.service.restart"]
```

---

## Testing

```bash
cargo test          # 14 tests
cargo clippy -- -W clippy::all
```

Test with the MCP Inspector:

```bash
npx -y @modelcontextprotocol/inspector
# Transport: HTTP+SSE, URL: http://localhost:8443/api/v1/mcp
```

---

## Project Structure

```text
src/
├── main.rs                # Entry point, config loading, server startup
├── config.rs              # neurond.toml parsing
│
├── federation/
│   ├── manager.rs         # Downstream orchestration, tool aggregation, call routing
│   ├── connection.rs      # Downstream lifecycle state machine
│   ├── namespace.rs       # Tool name prefixing/stripping/resolution
│   └── transport.rs       # Localhost (HTTP) and stdio (child process) transports
│
├── upstream/
│   └── server.rs          # ProxyEngine — MCP ServerHandler exposed to cortexd
│
└── registration/
    ├── register.rs        # cortexd registration/deregistration
    └── heartbeat.rs       # Background heartbeat task
```

---

## Related Projects

- **[mcpd](https://github.com/cortexd-labs/mcpd)** — Linux MCP server exposing 100+ system tools (the primary downstream for neurond)
- **cortexd** — Fleet orchestrator for managing multiple neurond nodes (planned)

---

## License

MIT
