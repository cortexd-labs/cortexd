# zbus and systemd D-Bus integration in Rust

**zbus 4.x/5.x provides a clean, macro-driven async API for systemd D-Bus interaction, and the `systemd` crate is the best option for journal reading.** The latest zbus version is **5.13.2** (the 4.x API is nearly identical—the main change from v3→v4 was renaming `#[dbus_proxy(property)]` to `#[zbus(property)]`). For systemd specifically, the **`systemd-zbus`** crate (v5.3.2, 250K+ downloads) provides pre-generated proxy types, though rolling your own is straightforward. Below are concrete, working patterns for every use case requested.

---

## Connecting to the system bus and configuring tokio

Establishing a connection is a single async call. **`Connection` is cheap to clone** (`Send + Sync`), so you create one and pass clones throughout your application:

```rust
use zbus::Connection;

// In Cargo.toml, disable default async-io and enable tokio:
// zbus = { version = "4", default-features = false, features = ["tokio"] }

#[tokio::main]
async fn main() -> zbus::Result<()> {
    // Connect to the system bus (systemd lives here, not session bus)
    let connection = Connection::system().await?;
    
    // Connection is Clone + Send + Sync — share freely
    let conn2 = connection.clone(); // cheap clone, no data duplication
    
    Ok(())
}
```

The **`tokio` feature flag** is critical. By default, zbus uses `async-io` and spawns background threads. Enabling `tokio` (and disabling defaults) makes zbus use tokio's event loop directly with **zero extra threads**:

```toml
[dependencies]
zbus = { version = "4", default-features = false, features = ["tokio"] }
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
```

For advanced control, you can disable the internal executor and tick it manually, but the `tokio` feature flag is the standard approach and works out of the box.

---

## ListUnits with a complete proxy trait definition

The `org.freedesktop.systemd1.Manager.ListUnits()` method returns D-Bus signature **`a(ssssssouso)`** — an array of 10-field structs. Here is the complete pattern: define a Rust struct deriving `zvariant::Type` plus serde traits, then declare a proxy trait with the `#[proxy]` macro.

### The UnitInfo struct and Manager proxy

```rust
use serde::{Deserialize, Serialize};
use zbus::zvariant::{OwnedObjectPath, Type};
use zbus::{proxy, Connection, Result};

/// Maps to D-Bus signature (ssssssouso) — the ListUnits return element
#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct UnitInfo {
    pub name: String,              // s — e.g. "sshd.service"
    pub description: String,       // s — human-readable
    pub load_state: String,        // s — "loaded", "error", "masked"
    pub active_state: String,      // s — "active", "inactive", "failed"
    pub sub_state: String,         // s — "running", "dead", "exited"
    pub following: String,         // s — unit being followed (or "")
    pub unit_path: OwnedObjectPath,// o — e.g. /org/freedesktop/systemd1/unit/sshd_2eservice
    pub job_id: u32,               // u — queued job ID (0 if none)
    pub job_type: String,          // s — job type (or "")
    pub job_path: OwnedObjectPath, // o — job object path (or "/")
}

#[proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
trait SystemdManager {
    fn list_units(&self) -> Result<Vec<UnitInfo>>;

    fn list_units_filtered(&self, states: &[&str]) -> Result<Vec<UnitInfo>>;

    fn list_units_by_patterns(
        &self,
        states: &[&str],
        patterns: &[&str],
    ) -> Result<Vec<UnitInfo>>;

    fn get_unit(&self, name: &str) -> Result<OwnedObjectPath>;

    fn load_unit(&self, name: &str) -> Result<OwnedObjectPath>;

    fn start_unit(&self, name: &str, mode: &str) -> Result<OwnedObjectPath>;

    fn stop_unit(&self, name: &str, mode: &str) -> Result<OwnedObjectPath>;

    fn restart_unit(&self, name: &str, mode: &str) -> Result<OwnedObjectPath>;

    fn subscribe(&self) -> Result<()>;

    fn reload(&self) -> Result<()>;

    #[zbus(property)]
    fn version(&self) -> Result<String>;

    #[zbus(property)]
    fn architecture(&self) -> Result<String>;

    #[zbus(property)]
    fn system_state(&self) -> Result<String>;

    // Signals
    #[zbus(signal)]
    fn unit_new(&self, id: &str, unit: OwnedObjectPath) -> Result<()>;

    #[zbus(signal)]
    fn unit_removed(&self, id: &str, unit: OwnedObjectPath) -> Result<()>;
}
```

The `#[proxy]` macro generates **two types**: `SystemdManagerProxy` (async) and `SystemdManagerProxyBlocking` (sync). Method names are auto-converted from Rust snake_case to D-Bus PascalCase (`list_units` → `ListUnits`).

### Complete ListUnits example

```rust
#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::system().await?;
    let manager = SystemdManagerProxy::new(&connection).await?;

    println!("systemd {}", manager.version().await?);
    println!("System state: {}", manager.system_state().await?);

    let units = manager.list_units().await?;
    let failed: Vec<_> = units.iter()
        .filter(|u| u.active_state == "failed")
        .collect();

    println!("{} units loaded, {} failed", units.len(), failed.len());
    for u in &failed {
        println!("  FAILED: {} — {}", u.name, u.description);
    }

    // Filter to only active service units
    let active = manager.list_units_filtered(&["active"]).await?;
    let services: Vec<_> = active.iter()
        .filter(|u| u.name.ends_with(".service"))
        .collect();
    println!("{} active services", services.len());

    Ok(())
}
```

An alternative to the struct is a **raw tuple** — `Vec<(String, String, String, String, String, String, OwnedObjectPath, u32, String, OwnedObjectPath)>` — but named structs are far more ergonomic.

---

## GetUnit and reading unit and service properties

The pattern is: call `GetUnit("name.service")` to obtain an object path, then construct **separate proxy instances** for the `Unit` and `Service` interfaces at that path. Each proxy reads its own interface's properties.

### Unit and Service proxy definitions

```rust
#[proxy(
    interface = "org.freedesktop.systemd1.Unit",
    default_service = "org.freedesktop.systemd1"
)]
trait SystemdUnit {
    #[zbus(property)]
    fn id(&self) -> Result<String>;

    #[zbus(property)]
    fn active_state(&self) -> Result<String>;

    #[zbus(property)]
    fn sub_state(&self) -> Result<String>;

    #[zbus(property)]
    fn load_state(&self) -> Result<String>;

    #[zbus(property)]
    fn description(&self) -> Result<String>;

    #[zbus(property)]
    fn active_enter_timestamp(&self) -> Result<u64>;    // microseconds since epoch

    #[zbus(property)]
    fn active_exit_timestamp(&self) -> Result<u64>;

    #[zbus(property)]
    fn state_change_timestamp(&self) -> Result<u64>;
}

#[proxy(
    interface = "org.freedesktop.systemd1.Service",
    default_service = "org.freedesktop.systemd1"
)]
trait SystemdService {
    #[zbus(property, name = "MainPID")]
    fn main_pid(&self) -> Result<u32>;

    #[zbus(property, name = "ExecMainPID")]
    fn exec_main_pid(&self) -> Result<u32>;

    #[zbus(property, name = "ExecMainStartTimestamp")]
    fn exec_main_start_timestamp(&self) -> Result<u64>;

    #[zbus(property)]
    fn memory_current(&self) -> Result<u64>;

    #[zbus(property)]
    fn memory_available(&self) -> Result<u64>;

    #[zbus(property, name = "CPUUsageNSec")]
    fn cpu_usage_nsec(&self) -> Result<u64>;

    #[zbus(property)]
    fn tasks_current(&self) -> Result<u64>;

    #[zbus(property, name = "NRestarts")]
    fn n_restarts(&self) -> Result<u32>;

    #[zbus(property)]
    fn status_errno(&self) -> Result<i32>;
}
```

Note the **`#[zbus(property, name = "MainPID")]`** attribute — use `name` when the D-Bus property name doesn't match Rust's snake_case convention (e.g., `MainPID`, `CPUUsageNSec`, `NRestarts`, `ExecMainStartTimestamp`).

### Reading properties at a unit's object path

```rust
async fn inspect_service(
    connection: &Connection,
    service_name: &str,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let manager = SystemdManagerProxy::new(connection).await?;

    // Get the unit's object path
    let unit_path = manager.get_unit(service_name).await?;

    // Create a Unit proxy at that path
    let unit = SystemdUnitProxy::builder(connection)
        .path(unit_path.clone())?
        .build()
        .await?;

    println!("Unit: {}", unit.id().await?);
    println!("  Description:  {}", unit.description().await?);
    println!("  ActiveState:  {}", unit.active_state().await?);
    println!("  SubState:     {}", unit.sub_state().await?);
    println!("  LoadState:    {}", unit.load_state().await?);

    // Create a Service proxy at the SAME path for service-specific props
    let svc = SystemdServiceProxy::builder(connection)
        .path(unit_path)?
        .build()
        .await?;

    println!("  MainPID:      {}", svc.main_pid().await?);
    println!("  Memory:       {} bytes", svc.memory_current().await?);
    println!("  CPU:          {} ns", svc.cpu_usage_nsec().await?);
    println!("  Restarts:     {}", svc.n_restarts().await?);

    // Timestamps are microseconds since Unix epoch
    let start_us = svc.exec_main_start_timestamp().await?;
    if start_us > 0 {
        let start = std::time::UNIX_EPOCH
            + std::time::Duration::from_micros(start_us);
        println!("  Started:      {:?}", start);
    }

    Ok(())
}
```

The critical insight: **two different proxy types can point at the same D-Bus object path**. The `Unit` interface and `Service` interface coexist on the same object — you just build each proxy with the same path. The `no default_path` in the Unit/Service proxy definitions means you must always provide the path via `builder().path(...)`.

---

## The pre-built systemd-zbus crate saves boilerplate

Rather than defining all proxy traits yourself, the **`systemd-zbus`** crate (v5.3.2, by flukejones) ships auto-generated proxies for every systemd D-Bus interface. It provides typed enums (`ActiveState`, `LoadState`, `SubState`), a `Unit` data struct for `ListUnits`, and proxy types like `ManagerProxy`, `UnitProxy`, `ServiceProxy`, `TimerProxy`, and more. The production monitoring tool **`monitord`** (by cooperlees, 37 stars, actively maintained) uses this crate with tokio:

```toml
[dependencies]
systemd-zbus = "5.3"
zbus = { version = "5", default-features = false, features = ["tokio"] }
tokio = { version = "1", features = ["full"] }
```

```rust
use systemd_zbus::{ManagerProxy, UnitProxy, ServiceProxy};
use zbus::Connection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let conn = Connection::system().await?;
    let mgr = ManagerProxy::new(&conn).await?;

    let units = mgr.list_units().await?;
    let path = mgr.get_unit("nginx.service").await?;

    let svc = ServiceProxy::builder(&conn)
        .path(path)?
        .build()
        .await?;
    println!("PID: {}, Memory: {} bytes", 
        svc.main_pid().await?, svc.memory_current().await?);
    Ok(())
}
```

A second option is **`zbus_systemd`** (by lucab, v0.25900.0), which is also auto-generated from systemd's introspection XML and uses feature gates per module (`features = ["systemd1"]`). Both crates track the latest zbus version.

---

## Journal reading: the systemd crate dominates

**There is no D-Bus interface for reading journal entries.** The only options are the sd-journal C API or parsing binary `.journal` files directly. The **`systemd` crate (v0.10.1, 3.6M downloads)** is the clear production choice — it wraps libsystemd's sd-journal API via FFI and provides full filtering, seeking, and tailing support.

```toml
[dependencies]
systemd = { version = "0.10", features = ["journal"] }
```

Build requirement: `libsystemd-dev` (Debian/Ubuntu) or `systemd-devel` (RHEL/Fedora).

### Reading last N entries for a specific unit

```rust
use systemd::journal;

fn read_last_n_entries(unit: &str, n: usize) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut j = journal::OpenOptions::default()
        .system(true)
        .current_user(true)
        .open()?;

    // Filter by unit
    j.match_add("_SYSTEMD_UNIT", unit)?;

    // Seek to end and walk backwards
    j.seek(journal::JournalSeek::Tail)?;
    let mut messages = Vec::new();
    for _ in 0..n {
        if j.previous()? == 0 { break; }
        if let Some(entry) = j.next_entry()? {
            if let Some(msg) = entry.get("MESSAGE") {
                messages.push(msg.clone());
            }
        }
    }
    messages.reverse();
    Ok(messages)
}
```

### Filtering by priority and keyword

```rust
fn search_errors(unit: &str, keyword: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut j = journal::OpenOptions::default().system(true).open()?;

    // AND group: unit filter
    j.match_add("_SYSTEMD_UNIT", unit)?;

    // AND group: priority <= warning (0-4)
    j.match_and()?;
    for p in 0..=4 {
        j.match_add("PRIORITY", &p.to_string())?;
        if p < 4 { j.match_or()?; }
    }

    j.seek(journal::JournalSeek::Head)?;
    while let Some(entry) = j.next_entry()? {
        if let Some(msg) = entry.get("MESSAGE") {
            if msg.contains(keyword) {
                let ts = entry.get("__REALTIME_TIMESTAMP")
                    .unwrap_or(&String::new()).clone();
                println!("[{}] {}", ts, msg);
            }
        }
    }
    Ok(())
}
```

### Tailing (watching for new entries)

```rust
use std::time::Duration;

fn tail_unit(unit: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut j = journal::OpenOptions::default().system(true).open()?;
    j.match_add("_SYSTEMD_UNIT", unit)?;
    j.seek(journal::JournalSeek::Tail)?;

    loop {
        while let Some(entry) = j.next_entry()? {
            if let Some(msg) = entry.get("MESSAGE") {
                println!("{}", msg);
            }
        }
        // Block until new entries arrive (1s timeout)
        j.wait(Some(Duration::from_secs(1)))?;
    }
}
```

For **async integration**, the `systemd` crate is sync-only and `!Send`, but exposes `j.fd()` which returns a pollable file descriptor. You can register this fd with tokio's `AsyncFd` to get async notifications, then read entries on the same thread. Alternatively, run journal reading in a dedicated `tokio::task::spawn_blocking` thread.

### Other crate options at a glance

- **`sd-journal`** (v0.1.0): Claims 100% sd-journal API coverage with good docs, but uses **AGPL-3.0** — problematic for most commercial use.
- **`journald-query`**: New high-level crate with `.unit()`, `.message_contains()` query builders and `JournalTail` for live tailing. MIT-licensed but very new.
- **`sdjournal`** (v0.1.6): Pure Rust parser of binary `.journal` files — no C dependency needed, but extremely new with ~140 downloads.
- **`libsystemd`** (v0.7.2): Despite the name, this crate is for **writing** to the journal and daemon notification only. It has **no journal reading API**.

---

## Integration patterns for async Rust applications

### Connection lifecycle: create once, share everywhere

`Connection` is `Clone + Send + Sync` and cloning is nearly free (it's an `Arc` internally). The standard pattern is to create one connection at startup and pass clones:

```rust
use std::sync::Arc;

struct AppState {
    dbus: Connection,
}

#[tokio::main]
async fn main() -> zbus::Result<()> {
    let connection = Connection::system().await?;
    let state = Arc::new(AppState { dbus: connection });

    // Pass state.dbus.clone() to any task that needs D-Bus access
    let state2 = state.clone();
    tokio::spawn(async move {
        let mgr = SystemdManagerProxy::new(&state2.dbus).await.unwrap();
        // ... use mgr
    });

    Ok(())
}
```

### Error handling patterns

All proxy methods return `zbus::Result<T>`. The error enum distinguishes D-Bus protocol errors from transport errors:

```rust
use zbus::Error;
use zbus::fdo;

async fn safe_get_unit(
    manager: &SystemdManagerProxy<'_>,
    name: &str,
) -> Option<OwnedObjectPath> {
    match manager.get_unit(name).await {
        Ok(path) => Some(path),
        Err(Error::MethodError(ref err_name, ref msg, _)) => {
            // D-Bus method returned an error
            // Common: org.freedesktop.systemd1.NoSuchUnit
            eprintln!("D-Bus error {}: {:?}", err_name, msg);
            None
        }
        Err(Error::FDO(ref fdo_err)) => {
            match fdo_err.as_ref() {
                fdo::Error::ServiceUnknown(msg) => {
                    eprintln!("systemd not reachable: {}", msg);
                    None
                }
                fdo::Error::AccessDenied(msg) => {
                    eprintln!("Permission denied: {}", msg);
                    None
                }
                _ => None,
            }
        }
        Err(Error::InputOutput(io_err)) => {
            eprintln!("I/O error (bus disconnected?): {}", io_err);
            None
        }
        Err(e) => {
            eprintln!("Unexpected error: {}", e);
            None
        }
    }
}
```

The most common systemd-specific errors are **`MethodError`** variants: `org.freedesktop.systemd1.NoSuchUnit` (unit not loaded/found) and `org.freedesktop.DBus.Error.AccessDenied` (insufficient privileges for system bus operations).

### Property caching control

zbus caches D-Bus properties by default and updates them via `PropertiesChanged` signals. For systemd properties that change frequently (like `MemoryCurrent`), you may want to disable caching:

```rust
let svc = SystemdServiceProxy::builder(&connection)
    .path(unit_path)?
    .cache_properties(zbus::CacheProperties::No) // always fetch fresh
    .build()
    .await?;
```

The three caching modes are `Yes` (default — cache and update via signals), `No` (always fetch from bus), and `Lazily` (cache on first access, then update via signals).

---

## Conclusion

The zbus 4.x/5.x proxy macro system maps cleanly onto systemd's D-Bus interfaces. The **key architectural pattern** is: one `Connection::system()` instance, a `ManagerProxy` for discovery and control methods, then per-unit `UnitProxy`/`ServiceProxy` instances built at the object paths returned by `GetUnit()`. The `systemd-zbus` crate eliminates the need to hand-write proxy definitions, and the real-world `monitord` project proves this stack works reliably in production with tokio.

For journal access, **the C FFI path via the `systemd` crate is the only production-ready option** — pure Rust parsers exist but are too immature. The journal API is inherently synchronous and `!Send`, so integrate it with tokio via `spawn_blocking` or `AsyncFd` on the journal's file descriptor. There is no D-Bus interface for journal reading; the sd-journal C API (or direct binary file parsing) is the only path.