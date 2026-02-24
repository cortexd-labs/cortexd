# neurond

`neurond` is an AI-native Linux system controller and **local federation proxy**. It exposes ~100 tools across 15 providers — covering system telemetry, process management, services, logs, networking, containers, packages, identity, storage, scheduling, security, time, hardware, and desktop — as a single [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server over HTTP+SSE.

AI models like Claude can use `neurond` to observe and manage a live Linux host in real time, with every action governed by a configurable policy and written to a structured audit log. As a federation proxy, neurond also aggregates third-party MCP servers (redis-mcp, postgres-mcp, custom tools) behind a single authenticated endpoint — cortexd connects once per machine.

---

## Providers

| Provider | Tools | Description |
| --- | --- | --- |
| `system` | 9 | CPU, memory, disk, uptime, load, kernel, reboot, sysctl |
| `process` | 6 | List, top, tree, inspect, open files, kill, signal, nice |
| `service` | 9 | Systemd unit list, status, logs, deps, start/stop/restart/enable/disable |
| `log` | 6 | Journal tail, search, units, stream, rotate, vacuum |
| `network` | 7 | Interfaces, addresses, routes, connections, ports, DNS, firewall |
| `file` | 8 | Stat, list, read, tail, search, write, mkdir, chmod |
| `container` | 9 | Docker list, status, logs, stats, inspect, start/stop/restart/remove |
| `package` | 7 | dpkg list, upgradable, search, info, install, update, remove |
| `identity` | 7 | Users, groups, sudoers, SSH key list/add/remove, user lock |
| `storage` | 6 | Block devices, fstab, LVM, SMART health, mount, unmount |
| `schedule` | 4 | Cron list, systemd timers, cron add/remove |
| `security` | 3 | SELinux/AppArmor status, certificate expiry, auditd rules |
| `time` | 2 | NTP sync status, force sync |
| `hardware` | 3 | Thermal sensors, PCI devices, USB devices |
| `desktop` | 12 | Windows, apps, clipboard, MPRIS media, theme, volume, notifications |

---

## Architecture

```text
                    ┌─────────────────────────────────────────────┐
                    │              Node (Linux host)              │
                    │                                             │
                    │  ┌─────────────────────────────────────┐    │
  cortexd ── mTLS ──┤  │             neurond                 │    │
  (fleet)    :8080  │  │                                     │    │
                    │  │  ┌───────────┐  ┌────────────────┐  │    │
                    │  │  │  native/  │  │  federation/   │  │    │
                    │  │  │           │  │                │  │    │
                    │  │  │ system.*  │  │ redis.*  ──────┼──┼──→ redis-mcp (stdio)
                    │  │  │ process.* │  │ pg.*     ──────┼──┼──→ postgres-mcp (127.0.0.1)
                    │  │  │ service.* │  │ custom.* ──────┼──┼──→ custom-mcp (stdio)
                    │  │  │ log.*     │  │                │  │
                    │  │  │ ...       │  └────────────────┘  │
                    │  │  └───────────┘                      │
                    │  │  engine/ — policy · audit · server  │
                    │  └─────────────────────────────────────┘    │
                    └─────────────────────────────────────────────┘
```

**Source layout:**

```text
src/
├── main.rs              # Entry point, signal handling
├── config.rs            # neurond.toml parsing (server, audit, federation)
├── router.rs            # Top-level tool routing: native → engine, namespaced → federation
│
├── engine/
│   ├── server.rs        # NeurondEngine — all 100 tool registrations (#[tool] handlers)
│   ├── policy.rs        # Deny-by-default TOML policy engine
│   └── audit.rs         # Structured JSONL audit logger
│
├── native/              # One module per Linux provider domain
│   └── system.rs · process.rs · service.rs · log.rs · network.rs · file.rs
│       container.rs · package.rs · identity.rs · storage.rs · schedule.rs
│       security.rs · time.rs · hardware.rs · desktop.rs
│
├── linux/               # Low-level OS interface layer
│   ├── systemd.rs       # D-Bus proxies (systemd, journald)
│   ├── network.rs       # Netlink (rtnetlink), /proc/net parsing
│   └── desktop.rs       # D-Bus session bus (MPRIS, notifications)
│
└── federation/          # Local Federation Proxy (Phase 3)
    ├── connection.rs    # DownstreamConnection, DownstreamState machine
    ├── namespace.rs     # Tool rewriting (redis.get), request routing
    ├── lifecycle.rs     # Spawn, restart with backoff, healthcheck
    └── transport.rs     # stdio (TokioChildProcess) + localhost HTTP helpers
```

- **`engine/`** — MCP server, deny-by-default policy enforcement, JSONL audit log.
- **`native/`** — One module per provider domain. Input validation, pure Rust logic, no raw syscalls.
- **`linux/`** — Low-level OS access: D-Bus proxies (systemd, desktop), Netlink, `/proc` and `/sys` parsing.
- **`federation/`** — Local Federation Proxy: aggregates downstream MCP servers behind a single endpoint. Stub today, implemented in Phase 3.

Mutation tools (reboot, kill, firewall, package install, etc.) are **denied by default** and must be explicitly allowed in `policy.toml`.

---

## Security

- **Policy engine** — `policy.toml` defines allow/deny rules with glob patterns (`system.*`, `network.firewall.*`). Default action is `deny`.
- **Audit log** — Every tool call is logged as a JSON line: timestamp, tool, params, decision, result, duration.
- **Input validation** — All user-controlled strings (unit names, package names, file paths, signal numbers) are validated before use. Shell metacharacter injection is rejected at the validation layer.
- **Path allowlist** — File operations are restricted to `/var/log`, `/var/lib`, `/etc`, `/tmp`, `/home`, `/opt`, `/srv`, `/usr/share`, `/proc`, `/sys/class`. Sensitive files (`/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`) are always blocked.
- **Direct syscalls over subprocesses** — Where possible, kernel interfaces are used directly: systemd unit control via D-Bus, sysctl via `/proc/sys`, reboot via `org.freedesktop.login1`.

---

## Getting Started

### Prerequisites

- Linux with systemd (Debian 12 / Ubuntu 22.04+ recommended)
- Rust 1.75+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- D-Bus system socket (standard on any systemd host)
- For desktop tools: D-Bus session socket, `wmctrl`, `pactl`, `gsettings`
- For container tools: Docker daemon running

### Build

```bash
git clone https://github.com/cortexd-labs/neurond.git
cd neurond
cargo build --release
```

### Run

```bash
# Development (uses ./policy.toml and ./audit.log)
cargo run

# Production (uses /etc/neurond/policy.toml and /var/log/neurond/audit.log)
sudo ./target/release/neurond
```

The server listens on `http://0.0.0.0:8080/api/v1/mcp`.

Log level is controlled by `RUST_LOG` (default: `neurond=info`).

### Configure Policy

Copy and edit the included `policy.toml`:

```toml
default_action = "deny"

# Allow all read-only system tools
[[rules]]
id = "allow-observability"
effect = "allow"
tools = ["system.*", "process.*", "service.list", "service.status", "service.logs"]

# Explicitly allow a mutation tool
[[rules]]
id = "allow-service-restart"
effect = "allow"
tools = ["service.restart"]
```

Rules are evaluated with **deny-wins** semantics: if any matching rule is `deny`, the tool is blocked regardless of other rules.

---

## Testing with Claude Desktop

1. Build the release binary: `cargo build --release`
2. Add to `~/.config/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "neurond": {
      "type": "http",
      "url": "http://localhost:8080/api/v1/mcp"
    }
  }
}
```

3. Start `neurond`, then restart Claude Desktop.

---

## Testing with the MCP Inspector

```bash
npx -y @modelcontextprotocol/inspector
```

Set transport to **HTTP+SSE**, URL to `http://localhost:8080/api/v1/mcp`, then call any tool interactively.

---

## Development

```bash
# Run all tests
cargo test

# Strict lint (CI requirement — zero warnings)
cargo clippy -- -D warnings

# Run a specific provider's tests
cargo test native::process
```

Tests are written alongside every provider. Mutation tools are tested by validating rejection of malformed input (injection strings, out-of-range values) without requiring root or a live system.

---

## Contributing

1. Add new tools under `src/native/` with a matching `#[cfg(test)]` block.
2. If the tool requires raw OS access, add the low-level function to `src/linux/`.
3. Register the tool in `src/engine/server.rs` following the existing `#[tool]` pattern.
4. Add a `policy.toml` rule (read tools to the allow group, mutation tools left denied with a comment).
5. Ensure `cargo build && cargo clippy -- -D warnings && cargo test` all pass.

See [`tasks/todo.md`](tasks/todo.md) for the improvement backlog and federation roadmap.

---

## License

MIT — see [LICENSE](LICENSE).
