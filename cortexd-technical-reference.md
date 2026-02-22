# cortexd — Complete Technical Reference

**Rust crate recommendations, API patterns, and implementation strategies for all 9 providers + core infrastructure.**

This document is the companion to the zbus/systemd D-Bus report. Together they form the complete foundation for building cortexd.

---

## Table of Contents

1. [Core Infrastructure](#1-core-infrastructure)
   - MCP Protocol (rmcp SDK)
   - Async Runtime & Daemon Patterns
   - Policy Engine & Config
2. [System Provider](#2-system-provider) — procfs, sysfs, nix
3. [Service Provider](#3-service-provider) — zbus, systemd, journald _(covered in prior report)_
4. [Process Provider](#4-process-provider) — procfs per-process
5. [Log Provider](#5-log-provider) — systemd journal FFI
6. [Network Provider](#6-network-provider) — rtnetlink, sock-diag
7. [File Provider](#7-file-provider) — inotify, notify
8. [Container Provider](#8-container-provider) — bollard, podman-api
9. [Package Provider](#9-package-provider) — dpkg/apt, rpm
10. [Desktop Provider](#10-desktop-provider) — D-Bus session bus
11. [Dependency Matrix](#11-dependency-matrix)
12. [Architecture Decisions](#12-architecture-decisions)

---

## 1. Core Infrastructure

### 1.1 MCP Protocol — Use the Official `rmcp` SDK

**The question of whether to hand-roll MCP or use a library is now settled.** The official Rust SDK is `rmcp` (crate name `rmcp`), maintained under `modelcontextprotocol/rust-sdk` on GitHub. It's at v0.16.0 with 3k+ stars, 358 commits, actively developed, and used by production MCP servers.

**This changes your architecture.** Your current hand-rolled MCP transport (JSON-RPC parsing, envelope formatting, stdio loop) should be replaced with rmcp. The SDK handles protocol negotiation, capability advertisement, tool schema generation, and both stdio and HTTP transports. You get correctness for free.

#### Why rmcp eliminates your Provider trait

rmcp provides `#[tool]` and `#[tool_router]` macros that auto-generate tool schemas from Rust types. Instead of your current Provider trait → Registry → MCP transport chain, you define tools directly:

```rust
use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::tool::ToolRouter,
    model::*, tool, tool_handler, tool_router,
    transport::stdio,
    ErrorData as McpError,
};
use schemars;

#[derive(Clone)]
pub struct cortexd {
    tool_router: ToolRouter<Self>,
    // ... your state (D-Bus connection, procfs handle, etc.)
}

#[tool_router]
impl cortexd {
    pub fn new(/* dependencies */) -> Self {
        Self {
            tool_router: Self::tool_router(),
            // ...
        }
    }

    #[tool(description = "Get system information: hostname, kernel, uptime, CPU count, total memory")]
    async fn system_info(&self) -> Result<CallToolResult, McpError> {
        let info = self.read_system_info().await;
        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&info).unwrap()
        )]))
    }

    #[tool(description = "List all systemd services with their active/load/sub states")]
    async fn service_list(&self) -> Result<CallToolResult, McpError> {
        let units = self.dbus_manager.list_units().await
            .map_err(|e| McpError {
                code: ErrorCode::INTERNAL_ERROR,
                message: format!("D-Bus error: {}", e).into(),
                data: None,
            })?;
        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&units).unwrap()
        )]))
    }

    #[tool(description = "Get top processes sorted by memory or CPU usage")]
    async fn process_top(
        &self,
        #[tool(param)]
        #[schemars(description = "Sort by 'memory' or 'cpu'")]
        sort_by: Option<String>,
        #[tool(param)]
        #[schemars(description = "Number of processes to return (default 10)")]
        count: Option<usize>,
    ) -> Result<CallToolResult, McpError> {
        // rmcp auto-generates the JSON schema for these params
        let sort = sort_by.unwrap_or("memory".into());
        let n = count.unwrap_or(10);
        // ...implementation
    }
}

#[tool_handler]
impl ServerHandler for cortexd {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .build(),
            server_info: Implementation::new("cortexd", env!("CARGO_PKG_VERSION")),
            instructions: Some(
                "cortexd is a Linux system controller. It provides tools to observe \
                 and manage system resources, services, processes, logs, network, \
                 files, containers, and packages.".into()
            ),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let service = cortexd::new().serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
```

#### Key rmcp concepts

- **`#[tool_router]`** on an `impl` block: generates the routing table. Each `#[tool]` method becomes a callable MCP tool.
- **`#[tool_handler]`** on `impl ServerHandler`: wires the tool router to the MCP server handler.
- **`Parameters<T>`** wrapper: for structured input params. rmcp auto-derives JSON Schema via `schemars`.
- **`CallToolResult::success(vec![Content::text(...)])`**: standard response envelope.
- **Transport**: `stdio()` for Claude Desktop; `StreamableHttpServer` for HTTP+SSE.

#### Cargo.toml for rmcp

```toml
[dependencies]
rmcp = { version = "0.16", features = ["server", "transport-io", "macros"] }
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
schemars = "0.8"
anyhow = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
```

#### What this means for your existing code

Your hand-rolled `transport/mcp.rs`, `core/provider.rs`, and `core/registry.rs` are **replaced** by rmcp. The Provider trait, ProviderRegistry, and JSON-RPC parsing code all go away. Your actual Linux integration code (procfs parsing, D-Bus calls, etc.) stays — it just gets called from `#[tool]` methods instead of from `Provider::call()`.

This is a net deletion of code. Your `providers/system.rs` match arms become `#[tool]` methods. Your `linux/procfs.rs` and `linux/systemd.rs` modules remain unchanged — they're the real work.

**Impact on the async question:** rmcp is natively async (tokio). All `#[tool]` methods are async. Your Option 2 (manual `Pin<Box<dyn Future>>`) question is moot — rmcp handles the dispatch internally. You just write `async fn` methods.

---

### 1.2 Async Runtime & Daemon Patterns

#### Tokio setup for a daemon

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Initialize logging (to stderr — critical for stdio MCP)
    tracing_subscriber::fmt()
        .with_env_filter("cortexd=info")
        .with_writer(std::io::stderr)  // NEVER write to stdout with stdio transport
        .init();

    // 2. Shared state: create once, pass to cortexd
    let dbus_conn = zbus::Connection::system().await?;

    // 3. Build and serve
    let cortexd = cortexd::new(dbus_conn);
    let service = cortexd.serve(rmcp::transport::stdio()).await?;

    // 4. Wait for shutdown (client disconnect or signal)
    service.waiting().await?;
    tracing::info!("cortexd shutting down cleanly");
    Ok(())
}
```

#### Signal handling

For daemon mode (Phase 2, when you add HTTP transport), use tokio's signal handling:

```rust
use tokio::signal;

async fn shutdown_signal() {
    let ctrl_c = signal::ctrl_c();
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");

    tokio::select! {
        _ = ctrl_c => tracing::info!("Received SIGINT"),
        _ = sigterm.recv() => tracing::info!("Received SIGTERM"),
    }
}
```

For the MVP with stdio transport, you don't need signal handling — the MCP client disconnecting (closing stdin) is your shutdown signal, and `service.waiting().await` handles that.

#### CancellationToken pattern for graceful shutdown

When you have multiple subsystems (MCP server + journal tailing + file watching), use `tokio_util::sync::CancellationToken`:

```rust
use tokio_util::sync::CancellationToken;

let token = CancellationToken::new();

// Spawn subsystem
let t = token.clone();
tokio::spawn(async move {
    tokio::select! {
        _ = t.cancelled() => { /* cleanup */ }
        _ = some_long_running_task() => {}
    }
});

// On shutdown signal
token.cancel();
```

---

### 1.3 Policy Engine & Config (Phase 2)

For TOML config parsing, use `toml` + `serde`:

```toml
# /etc/cortexd/policy.toml
[trust]
level = "observer"  # observer | operator | admin

[providers]
system = true
service = true
process = true
log = true
network = false
file = false
container = false
package = false

[limits]
max_log_lines = 1000
max_process_list = 500
```

```rust
use serde::Deserialize;

#[derive(Deserialize)]
struct Config {
    trust: TrustConfig,
    providers: ProviderConfig,
    limits: LimitsConfig,
}

let config: Config = toml::from_str(&std::fs::read_to_string("/etc/cortexd/policy.toml")?)?;
```

For live config reload, use the `notify` crate (covered in File Provider section) to watch the config file and re-parse on change.

---

## 2. System Provider

### Crate: `procfs` (v0.17+, 3.6M downloads)

The `procfs` crate is the definitive Rust interface to `/proc`. It provides typed structs for every `/proc` file, with serde support. **Use this instead of manual parsing.**

```toml
procfs = { version = "0.17", features = ["serde1"] }
nix = { version = "0.29", features = ["fs"] }
```

#### System info (replaces your manual `/proc` parsing)

```rust
use procfs::{Meminfo, CpuInfo, LoadAverage, Uptime, Current};

async fn system_info() -> serde_json::Value {
    let meminfo = Meminfo::current().unwrap();
    let cpuinfo = CpuInfo::current().unwrap();
    let loadavg = LoadAverage::current().unwrap();
    let uptime = Uptime::current().unwrap();
    let hostname = procfs::sys::kernel::hostname().unwrap();
    let osrelease = procfs::sys::kernel::osrelease().unwrap();

    serde_json::json!({
        "hostname": hostname,
        "kernel": osrelease,
        "uptime_seconds": uptime.uptime,
        "cpu_count": cpuinfo.num_cores(),
        "load_average": {
            "one": loadavg.one,
            "five": loadavg.five,
            "fifteen": loadavg.fifteen,
        },
        "memory": {
            "total_kb": meminfo.mem_total,
            "free_kb": meminfo.mem_free,
            "available_kb": meminfo.mem_available,
            "swap_total_kb": meminfo.swap_total,
            "swap_free_kb": meminfo.swap_free,
        }
    })
}
```

#### CPU usage percentage (fixes your hardcoded 0.0 problem)

CPU% requires two samples with a delay. The `procfs` crate gives you raw jiffies from `/proc/stat`:

```rust
use procfs::KernelStats;
use std::time::Duration;

async fn cpu_usage_percent() -> f64 {
    let stat1 = KernelStats::current().unwrap();
    tokio::time::sleep(Duration::from_millis(250)).await;
    let stat2 = KernelStats::current().unwrap();

    let cpu1 = &stat1.total;
    let cpu2 = &stat2.total;

    let idle1 = cpu1.idle + cpu1.iowait.unwrap_or(0);
    let idle2 = cpu2.idle + cpu2.iowait.unwrap_or(0);

    let total1 = cpu1.user + cpu1.nice + cpu1.system + cpu1.idle
        + cpu1.iowait.unwrap_or(0) + cpu1.irq.unwrap_or(0)
        + cpu1.softirq.unwrap_or(0) + cpu1.steal.unwrap_or(0);
    let total2 = cpu2.user + cpu2.nice + cpu2.system + cpu2.idle
        + cpu2.iowait.unwrap_or(0) + cpu2.irq.unwrap_or(0)
        + cpu2.softirq.unwrap_or(0) + cpu2.steal.unwrap_or(0);

    let total_delta = total2 - total1;
    let idle_delta = idle2 - idle1;

    if total_delta == 0 { return 0.0; }
    ((total_delta - idle_delta) as f64 / total_delta as f64) * 100.0
}
```

#### Disk usage (fixes your stubbed empty array)

Use `procfs` for mount info, then `nix::sys::statvfs` for capacity:

```rust
use procfs::process::MountInfo;
use nix::sys::statvfs::statvfs;

fn disk_usage() -> Vec<serde_json::Value> {
    // /proc/self/mountinfo has all mounts
    let mounts = MountInfo::current().unwrap();

    let skip_fs = ["tmpfs", "proc", "sysfs", "devtmpfs", "devpts",
                   "cgroup", "cgroup2", "pstore", "securityfs",
                   "fusectl", "debugfs", "hugetlbfs", "mqueue",
                   "configfs", "binfmt_misc", "autofs", "tracefs",
                   "overlay", "nsfs", "efivarfs"];

    mounts.iter()
        .filter(|m| !skip_fs.contains(&m.fs_type.as_str()))
        .filter_map(|m| {
            let stat = statvfs(m.mount_point.as_path()).ok()?;
            let block_size = stat.fragment_size() as u64;
            let total = stat.blocks() * block_size;
            let free = stat.blocks_available() * block_size;
            if total == 0 { return None; }

            Some(serde_json::json!({
                "mount": m.mount_point.display().to_string(),
                "device": m.mount_source.as_deref().unwrap_or("unknown"),
                "fs_type": m.fs_type,
                "total_bytes": total,
                "free_bytes": free,
                "used_bytes": total - free,
                "used_percent": ((total - free) as f64 / total as f64 * 100.0).round(),
            }))
        })
        .collect()
}
```

---

## 3. Service Provider

**Covered in the prior zbus/systemd D-Bus report.** Key points:

- **`zbus`** with tokio feature for systemd D-Bus (Manager, Unit, Service proxies)
- **`systemd-zbus`** crate (v5.3) provides pre-built proxy types
- **`systemd`** crate (v0.10) for journal FFI reading
- Connection is `Clone + Send + Sync`, create once at startup

---

## 4. Process Provider

### Crate: `procfs` (same as System Provider)

The `procfs` crate provides per-process data via `procfs::process::Process`:

```rust
use procfs::process::{all_processes, Process, Stat as ProcStat, Status as ProcStatus};

fn process_list() -> Vec<serde_json::Value> {
    all_processes().unwrap()
        .filter_map(|p| p.ok())
        .filter_map(|proc| {
            let stat = proc.stat().ok()?;
            let status = proc.status().ok()?;

            Some(serde_json::json!({
                "pid": stat.pid,
                "name": stat.comm,
                "state": format!("{}", stat.state),
                "ppid": stat.ppid,
                "uid": status.ruid,       // Real UID (fixes "unknown" user)
                "rss_bytes": stat.rss * procfs::page_size(),
                "vsize_bytes": stat.vsize,
                "threads": stat.num_threads,
                "start_time": stat.starttime,  // in clock ticks since boot
                "utime": stat.utime,       // user mode jiffies
                "stime": stat.stime,       // kernel mode jiffies
            }))
        })
        .collect()
}
```

#### Per-process CPU percentage

For individual process CPU%, you need two samples of `/proc/[pid]/stat` and the global clock:

```rust
use std::collections::HashMap;

async fn process_top_by_cpu(count: usize) -> Vec<serde_json::Value> {
    let ticks_per_sec = procfs::ticks_per_second();

    // Sample 1: record (utime + stime) for each process
    let snap1: HashMap<i32, u64> = all_processes().unwrap()
        .filter_map(|p| p.ok())
        .filter_map(|p| {
            let s = p.stat().ok()?;
            Some((s.pid, s.utime + s.stime))
        })
        .collect();

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Sample 2: compute delta
    let mut results: Vec<_> = all_processes().unwrap()
        .filter_map(|p| p.ok())
        .filter_map(|p| {
            let stat = p.stat().ok()?;
            let status = p.status().ok()?;
            let total2 = stat.utime + stat.stime;
            let total1 = snap1.get(&stat.pid)?;
            let delta = total2 - total1;
            let cpu_pct = (delta as f64 / ticks_per_sec as f64) * 100.0 / 0.5; // 500ms window

            Some(serde_json::json!({
                "pid": stat.pid,
                "name": stat.comm,
                "cpu_percent": (cpu_pct * 10.0).round() / 10.0,
                "rss_bytes": stat.rss * procfs::page_size(),
                "uid": status.ruid,
            }))
        })
        .collect();

    results.sort_by(|a, b| {
        b["cpu_percent"].as_f64().partial_cmp(&a["cpu_percent"].as_f64()).unwrap()
    });
    results.truncate(count);
    results
}
```

#### UID to username resolution

```rust
fn uid_to_username(uid: u32) -> String {
    // Read /etc/passwd once at startup and cache
    // Or use nix::unistd::User
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| uid.to_string())
}
```

---

## 5. Log Provider

### Crate: `systemd` (v0.10, journal feature)

**Covered in prior report.** Key addition for async integration:

The `systemd` crate's journal reader is sync and `!Send`. For use in async cortexd tools, wrap in `spawn_blocking`:

```rust
async fn journal_tail(unit: &str, lines: usize) -> Result<Vec<String>, anyhow::Error> {
    let unit = unit.to_string();
    tokio::task::spawn_blocking(move || {
        let mut j = systemd::journal::OpenOptions::default()
            .system(true)
            .open()?;
        j.match_add("_SYSTEMD_UNIT", &unit)?;
        j.seek(systemd::journal::JournalSeek::Tail)?;

        let mut entries = Vec::new();
        for _ in 0..lines {
            if j.previous()? == 0 { break; }
            if let Some(entry) = j.next_entry()? {
                if let Some(msg) = entry.get("MESSAGE") {
                    entries.push(msg.clone());
                }
            }
        }
        entries.reverse();
        Ok(entries)
    }).await?
}
```

**Build dependency:** `libsystemd-dev` (Ubuntu/Debian) or `systemd-devel` (RHEL/Fedora). This is a C library linking requirement. Document it in your install instructions.

---

## 6. Network Provider

**This is the area you flagged as most uncertain.** Here's the complete picture.

### Architecture: Two layers

1. **rtnetlink** — for interfaces, addresses, routes (equivalent to `ip link`, `ip addr`, `ip route`)
2. **netlink-packet-sock-diag** — for active connections (equivalent to `ss` / `/proc/net/tcp`)

### 6.1 Interfaces, Addresses, Routes: `rtnetlink`

```toml
rtnetlink = "0.14"
netlink-packet-route = "0.21"
```

The `rtnetlink` crate provides a high-level async API over netlink route protocol. It uses `netlink-proto` under the hood which spawns its own tokio task for the netlink socket.

```rust
use rtnetlink::new_connection;
use futures::TryStreamExt;

async fn list_interfaces() -> anyhow::Result<Vec<serde_json::Value>> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection); // must be spawned for requests to work

    let mut links = handle.link().get().execute();
    let mut results = Vec::new();

    while let Some(msg) = links.try_next().await? {
        // msg is a LinkMessage with nested attributes
        let name = msg.attributes.iter().find_map(|attr| {
            if let netlink_packet_route::link::LinkAttribute::IfName(n) = attr {
                Some(n.clone())
            } else { None }
        }).unwrap_or_default();

        let mac = msg.attributes.iter().find_map(|attr| {
            if let netlink_packet_route::link::LinkAttribute::Address(a) = attr {
                Some(a.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":"))
            } else { None }
        });

        let mtu = msg.attributes.iter().find_map(|attr| {
            if let netlink_packet_route::link::LinkAttribute::Mtu(m) = attr {
                Some(*m)
            } else { None }
        });

        let is_up = msg.header.flags.contains(
            netlink_packet_route::link::LinkFlags::Up
        );

        results.push(serde_json::json!({
            "index": msg.header.index,
            "name": name,
            "mac": mac,
            "mtu": mtu,
            "up": is_up,
        }));
    }
    Ok(results)
}

async fn list_addresses() -> anyhow::Result<Vec<serde_json::Value>> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    let mut addrs = handle.address().get().execute();
    let mut results = Vec::new();

    while let Some(msg) = addrs.try_next().await? {
        let addr = msg.attributes.iter().find_map(|attr| {
            if let netlink_packet_route::address::AddressAttribute::Address(a) = attr {
                Some(format!("{}", a))
            } else { None }
        });

        results.push(serde_json::json!({
            "index": msg.header.index,
            "family": if msg.header.family == 2 { "IPv4" } else { "IPv6" },
            "address": addr,
            "prefix_len": msg.header.prefix_len,
        }));
    }
    Ok(results)
}

async fn list_routes() -> anyhow::Result<Vec<serde_json::Value>> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    let mut routes = handle.route().get(
        netlink_packet_route::route::RouteMessage::default().into()
    ).execute();
    let mut results = Vec::new();

    while let Some(msg) = routes.try_next().await? {
        // Extract destination, gateway, output interface from attributes
        let dst = msg.attributes.iter().find_map(|attr| {
            if let netlink_packet_route::route::RouteAttribute::Destination(d) = attr {
                Some(format!("{}", d))
            } else { None }
        });

        let gateway = msg.attributes.iter().find_map(|attr| {
            if let netlink_packet_route::route::RouteAttribute::Gateway(g) = attr {
                Some(format!("{}", g))
            } else { None }
        });

        results.push(serde_json::json!({
            "destination": dst.unwrap_or("default".into()),
            "prefix_len": msg.header.destination_prefix_length,
            "gateway": gateway,
            "table": msg.header.table,
        }));
    }
    Ok(results)
}
```

**Important:** Each `new_connection()` creates a netlink socket. The returned `connection` future **must be spawned** as a tokio task — it drives the socket I/O. Create one connection per query batch, or maintain a long-lived handle if you need persistent netlink monitoring.

### 6.2 Active Connections: `netlink-packet-sock-diag`

For listing TCP/UDP connections (what `ss` does), use the sock-diag netlink protocol. This is lower-level than rtnetlink — there's no high-level wrapper crate yet.

```toml
netlink-packet-sock-diag = "0.4"
netlink-packet-core = "0.7"
netlink-sys = "0.8"
```

The sock-diag interface queries the kernel's socket table directly. For the MVP, `/proc/net/tcp` parsing via the `procfs` crate is simpler and perfectly adequate:

```rust
use procfs::net::{TcpState, tcp, tcp6};

fn active_connections() -> Vec<serde_json::Value> {
    let mut conns = Vec::new();

    // IPv4 TCP
    if let Ok(entries) = tcp() {
        for e in entries {
            conns.push(serde_json::json!({
                "protocol": "tcp",
                "local_addr": format!("{}:{}", e.local_address.ip(), e.local_address.port()),
                "remote_addr": format!("{}:{}", e.remote_address.ip(), e.remote_address.port()),
                "state": format!("{:?}", e.state),
                "inode": e.inode,
                "uid": e.uid,
            }));
        }
    }

    // IPv6 TCP
    if let Ok(entries) = tcp6() {
        for e in entries {
            conns.push(serde_json::json!({
                "protocol": "tcp6",
                "local_addr": format!("{}:{}", e.local_address.ip(), e.local_address.port()),
                "remote_addr": format!("{}:{}", e.remote_address.ip(), e.remote_address.port()),
                "state": format!("{:?}", e.state),
                "inode": e.inode,
                "uid": e.uid,
            }));
        }
    }

    conns
}
```

**Recommendation:** Use `procfs::net::tcp()` for the MVP. Migrate to netlink sock-diag later if you need kernel-filtered queries (e.g., "only ESTABLISHED connections on port 443") for performance at scale.

---

## 7. File Provider

### Crate: `notify` (v7+, CC0 license, used by rust-analyzer, deno, zed)

The `notify` crate is the standard for cross-platform filesystem watching. On Linux it uses inotify. For Linux-only, the raw `inotify` crate works too, but `notify` gives you debouncing and a cleaner API.

```toml
notify = "7"
notify-debouncer-mini = "0.5"  # optional, for debounced events
```

#### File watching with tokio integration

```rust
use notify::{RecommendedWatcher, RecursiveMode, Watcher, Event};
use tokio::sync::mpsc;

async fn watch_path(path: &str) -> anyhow::Result<mpsc::Receiver<Event>> {
    let (tx, rx) = mpsc::channel(100);

    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.blocking_send(event);
            }
        },
        notify::Config::default(),
    )?;

    watcher.watch(path.as_ref(), RecursiveMode::Recursive)?;

    // Watcher must be kept alive — store it in your state struct
    // If dropped, watching stops
    std::mem::forget(watcher); // HACK — properly store in cortexd struct

    Ok(rx)
}
```

#### File provider tools (observe-only for MVP)

For the file provider's observe-only tools, you likely don't need the watching capability. Simple `tokio::fs` operations suffice:

```rust
use tokio::fs;

async fn file_info(path: &str) -> serde_json::Value {
    let meta = fs::metadata(path).await.unwrap();
    serde_json::json!({
        "path": path,
        "size_bytes": meta.len(),
        "is_dir": meta.is_dir(),
        "modified": meta.modified().ok().map(|t|
            t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        ),
        "permissions": format!("{:o}", meta.permissions().mode()),
    })
}

async fn list_dir(path: &str) -> Vec<serde_json::Value> {
    let mut entries = Vec::new();
    let mut dir = fs::read_dir(path).await.unwrap();
    while let Some(entry) = dir.next_entry().await.unwrap() {
        let meta = entry.metadata().await.ok();
        entries.push(serde_json::json!({
            "name": entry.file_name().to_string_lossy(),
            "is_dir": meta.as_ref().map(|m| m.is_dir()).unwrap_or(false),
            "size_bytes": meta.as_ref().map(|m| m.len()).unwrap_or(0),
        }));
    }
    entries
}
```

File watching becomes relevant in Phase 2 for things like "watch /var/log/app.log for changes" or config reload. For Phase 1, file.info and file.list are sufficient.

---

## 8. Container Provider

### Docker: `bollard` (dominant, 13M+ downloads)

Bollard is the clear winner for Docker. Async, tokio-native, auto-generated from Docker's OpenAPI spec.

```toml
bollard = { version = "0.18", default-features = false, features = ["tokio"] }
```

```rust
use bollard::Docker;
use bollard::container::ListContainersOptions;
use bollard::container::InspectContainerOptions;
use std::collections::HashMap;

async fn docker_client() -> Docker {
    // Connects via /var/run/docker.sock
    Docker::connect_with_socket_defaults().unwrap()
}

async fn list_containers(docker: &Docker) -> Vec<serde_json::Value> {
    let options = ListContainersOptions::<String> {
        all: true,
        ..Default::default()
    };

    docker.list_containers(Some(options)).await.unwrap()
        .into_iter()
        .map(|c| serde_json::json!({
            "id": c.id.unwrap_or_default()[..12].to_string(),
            "names": c.names,
            "image": c.image,
            "state": c.state,
            "status": c.status,
            "created": c.created,
        }))
        .collect()
}

async fn container_stats(docker: &Docker, id: &str) -> serde_json::Value {
    use bollard::container::StatsOptions;
    use futures::StreamExt;

    let stats = docker.stats(id, Some(StatsOptions { stream: false, ..Default::default() }))
        .next().await.unwrap().unwrap();

    let cpu_delta = stats.cpu_stats.cpu_usage.total_usage
        - stats.precpu_stats.cpu_usage.total_usage;
    let system_delta = stats.cpu_stats.system_cpu_usage.unwrap_or(0)
        - stats.precpu_stats.system_cpu_usage.unwrap_or(0);
    let num_cpus = stats.cpu_stats.online_cpus.unwrap_or(1);
    let cpu_pct = if system_delta > 0 {
        (cpu_delta as f64 / system_delta as f64) * num_cpus as f64 * 100.0
    } else { 0.0 };

    serde_json::json!({
        "cpu_percent": (cpu_pct * 10.0).round() / 10.0,
        "memory_usage": stats.memory_stats.usage,
        "memory_limit": stats.memory_stats.limit,
        "network_rx_bytes": stats.networks.as_ref()
            .map(|n| n.values().map(|v| v.rx_bytes).sum::<u64>()),
        "network_tx_bytes": stats.networks.as_ref()
            .map(|n| n.values().map(|v| v.tx_bytes).sum::<u64>()),
    })
}
```

### Podman: `podman-api` (v0.10, mirrors Docker API)

Podman exposes a Docker-compatible REST API over a Unix socket. The `podman-api` crate wraps it:

```toml
podman-api = "0.10"
```

```rust
use podman_api::Podman;

async fn podman_list() -> Vec<serde_json::Value> {
    let podman = Podman::unix("/run/user/1000/podman/podman.sock");
    let containers = podman.containers().list(&Default::default()).await.unwrap();
    // Similar structure to Docker responses
    containers.into_iter().map(|c| serde_json::json!({
        "id": &c.id.as_deref().unwrap_or("")[..12],
        "names": c.names,
        "image": c.image,
        "state": c.state,
    })).collect()
}
```

**Implementation strategy:** Abstract over both runtimes. At init time, detect which socket exists (`/var/run/docker.sock` or `$XDG_RUNTIME_DIR/podman/podman.sock`) and instantiate the appropriate client. The tool responses should be identical regardless of runtime.

---

## 9. Package Provider

### Reality check: No native Rust API for apt/dpkg/dnf

There are no production-quality Rust crates that provide a native API to query installed packages from apt/dpkg or dnf/rpm package databases. The options:

1. **`debian-packaging`** crate — can parse `.deb` files and repo indices, but **cannot query the local dpkg database** (`/var/lib/dpkg/status`).
2. **`rpm`** crate — can parse `.rpm` files but **cannot query the local rpmdb**.
3. **`librpm`** crate — Rust FFI bindings to `librpm`, but requires the C library and is low-level.

### Recommended approach: Parse dpkg/rpm databases directly

The dpkg status file is a simple text format:

```rust
fn list_installed_packages() -> Vec<serde_json::Value> {
    let content = std::fs::read_to_string("/var/lib/dpkg/status").unwrap();
    let mut packages = Vec::new();
    let mut current: HashMap<String, String> = HashMap::new();

    for line in content.lines() {
        if line.is_empty() {
            if let (Some(name), Some(status)) = (current.get("Package"), current.get("Status")) {
                if status.contains("installed") {
                    packages.push(serde_json::json!({
                        "name": name,
                        "version": current.get("Version").unwrap_or(&"".into()),
                        "architecture": current.get("Architecture").unwrap_or(&"".into()),
                        "description": current.get("Description")
                            .map(|d| d.lines().next().unwrap_or("")),
                    }));
                }
            }
            current.clear();
        } else if let Some((key, value)) = line.split_once(": ") {
            current.insert(key.to_string(), value.to_string());
        }
    }
    packages
}
```

For RPM-based systems, query the rpmdb via `librpm` FFI or fall back to subprocess (`rpm -qa --queryformat '...'`). **This is an acceptable place to shell out** — package databases don't have a clean kernel API, and the package provider is a low-priority Phase 3 feature.

---

## 10. Desktop Provider

### D-Bus session bus for desktop interactions

The desktop provider would use zbus on the **session bus** (not system bus) to interact with desktop services:

```rust
let session = zbus::Connection::session().await?;
```

Possible interfaces:

- **`org.freedesktop.Notifications`** — send desktop notifications
- **`org.freedesktop.ScreenSaver`** — screen lock status
- **`org.freedesktop.portal.Desktop`** — XDG desktop portal

This is the lowest priority provider and may never be needed. The session bus also requires a running desktop session, making it irrelevant for headless servers (your primary target).

**Recommendation:** Defer entirely. If you ever build it, it's just more zbus proxies on the session bus instead of system bus.

---

## 11. Dependency Matrix

### MVP (Phase 1) — 4 providers, ~8 crates

```toml
[dependencies]
# Core
rmcp = { version = "0.16", features = ["server", "transport-io", "macros"] }
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
schemars = "0.8"
anyhow = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# System + Process providers
procfs = { version = "0.17", features = ["serde1"] }
nix = { version = "0.29", features = ["fs", "user"] }

# Service provider (D-Bus)
zbus = { version = "5", default-features = false, features = ["tokio"] }

# Log provider (journald FFI)
systemd = { version = "0.10", features = ["journal"] }
```

**Build dependencies:** `libsystemd-dev` (for `systemd` crate)

### Phase 2 — Add network, file, container

```toml
# Network provider
rtnetlink = "0.14"

# File provider
notify = "7"

# Container provider
bollard = { version = "0.18", default-features = false, features = ["tokio"] }
podman-api = { version = "0.10", optional = true }
```

### Phase 3 — Package, desktop, WASM extensions

```toml
# Package provider (if needed)
# No new crates — parse /var/lib/dpkg/status directly

# Desktop (if needed)
# No new crates — reuse zbus on session bus

# WASM extensions (future)
wasmtime = "24"
```

---

## 12. Architecture Decisions

### Decision: Replace hand-rolled MCP with rmcp

**Rationale:** rmcp handles protocol negotiation, tool schema generation, transport management, and capability advertisement. Your hand-rolled code duplicates this with less correctness. The `#[tool]` macro eliminates the Provider trait → Registry → JSON-RPC chain entirely.

**Migration:** Delete `transport/mcp.rs`, `core/provider.rs`, `core/registry.rs`. Move tool logic from `providers/*.rs` into `#[tool]` methods on a single `cortexd` struct (or split into multiple structs with `#[tool_router]`).

### Decision: Keep linux/ modules as pure data layer

Your `linux/procfs.rs` and `linux/systemd.rs` modules stay. They're the real value — the kernel interface code. They just get called from `#[tool]` methods instead of from `Provider::call()`.

### Decision: procfs crate over manual parsing

**Rationale:** The `procfs` crate (3.6M downloads) handles every edge case in `/proc` parsing — kernel version differences, field count changes, encoding quirks. Your manual parsing works for the common case but will break on edge cases in production.

### Decision: procfs for connections, rtnetlink for interfaces

**Rationale:** `procfs::net::tcp()` gives you active connections with minimal code. `rtnetlink` gives you interface/address/route information via the proper kernel API. Use both.

### Decision: Subprocess acceptable for packages only

**Rationale:** The "no shelling out" principle applies to kernel subsystems that have proper programmatic APIs (D-Bus, netlink, procfs, sysfs). Package managers don't expose such APIs. Parsing `/var/lib/dpkg/status` is the pragmatic approach, with optional `rpm -q` fallback for RHEL systems.

### Decision: Single cortexd struct vs. multiple routers

rmcp supports `#[tool_router]` on multiple impl blocks. You could split tools across files:

```rust
// system_tools.rs
#[tool_router]
impl cortexd {
    #[tool(description = "...")] async fn system_info(&self) -> ...
    #[tool(description = "...")] async fn system_cpu(&self) -> ...
}

// service_tools.rs
#[tool_router]
impl cortexd {
    #[tool(description = "...")] async fn service_list(&self) -> ...
    #[tool(description = "...")] async fn service_status(&self) -> ...
}
```

This preserves your provider-based organization as a code layout concern while using rmcp's flat tool namespace. **Verify this works with rmcp** — multiple `#[tool_router]` blocks on the same struct may require the macros to merge routers. If not, use a single large impl block.

---

_End of reference. This document + the prior zbus/systemd report cover the complete cortexd tech stack._
