# neurond: Post-Review Improvement Backlog

Derived from senior tech lead review (2026-02-23).
Each item has a priority, category, and full tech spec.

Priority scale: **P1** = security/correctness bug · **P2** = reliability/maintainability · **P3** = Rust idioms · **P4** = dependency cleanup

---

## P1 — Security & Correctness

---

### [ ] FIX: Non-canonical path validation in `file_write` and `file_mkdir`

**Category:** Security
**File:** `src/providers/file.rs`

**Problem:**
`file_read`, `file_chmod`, and `file_info` call `std::fs::canonicalize()` before checking against `ALLOWED_PREFIXES` — correct.
`file_write` does NOT canonicalize the parent directory before checking; it uses `canonical_parent.starts_with(prefix)` on the result of `canonicalize(parent)` which is OK, but then checks sensitive file names with `path.to_lowercase().contains(s.to_lowercase())` — this is a substring match, not an exact match, and lowercases the input meaning `/etc/SHADOW` would not be caught by the `contains("/etc/shadow")` check on a case-sensitive filesystem (Linux FS is case-sensitive, so `/etc/SHADOW` is a different file, but the logic is misleading and non-canonical).
`file_mkdir` checks `parent_str.starts_with(prefix)` on the raw unresolved string — no `canonicalize` at all. A path like `/tmp/../etc/cron.d/evil` would pass the `/tmp` prefix check.

**Fix:**
Extract a `validate_writable_path(path: &str) -> anyhow::Result<PathBuf>` function:
1. If the file exists: `canonicalize(path)` then check prefix + sensitive list (exact string equality, not substring).
2. If the file does not yet exist: `canonicalize(parent)`, check parent is in `ALLOWED_PREFIXES`, then reconstruct `parent_canonical.join(filename)` as the target. Check the final joined path against the sensitive list.
3. Replace the `to_lowercase().contains()` sensitive-file check with exact `==` comparison against the canonical path string in all write/mkdir paths.
4. Add test: `file_write("/tmp/../etc/shadow", "x")` must return `Err`.

---

### [ ] FIX: `process_signal` must guard PID ≤ 1

**Category:** Security
**File:** `src/providers/process.rs`

**Problem:**
`process_signal(pid, signum)` and `process_kill(pid, force)` accept any pid value. `SIGKILL` sent to PID 1 causes a kernel panic. `SIGTERM` to PID 1 is ignored by init/systemd, but SIGKILL is not.

**Fix:**
Add at the top of both functions:
```rust
if pid <= 1 {
    anyhow::bail!("Refusing to signal PID {} — init process is protected", pid);
}
```
Add tests:
- `process_kill(1, true)` → `Err` (force SIGKILL to init)
- `process_kill(0, false)` → `Err` (pid 0 is process group)
- `process_signal(1, 9)` → `Err`

---

### [ ] FIX: Subprocess commands must use absolute paths

**Category:** Security
**Files:** `src/linux/systemd.rs`, `src/providers/network.rs`, `src/providers/package.rs`, `src/providers/storage.rs`, `src/providers/schedule.rs`, `src/providers/hardware.rs`, `src/linux/desktop.rs`, `src/providers/time.rs`, `src/providers/identity.rs`

**Problem:**
All subprocess invocations use bare command names (`"journalctl"`, `"apt-get"`, `"iptables"`, `"smartctl"`, `"lspci"`, `"wmctrl"`, `"pactl"`, `"chronyc"`, `"crontab"`, `"passwd"`, `"renice"`, `"gsettings"`, `"wl-paste"`, `"xclip"`, `"gtk-launch"`). If `PATH` is modified or the daemon is launched from a minimal environment, these could resolve to attacker-controlled binaries.

**Fix:**
Define a module-level constant or lookup table for each required binary:
```rust
const JOURNALCTL: &str = "/usr/bin/journalctl";
const APT_GET:    &str = "/usr/bin/apt-get";
const IPTABLES:   &str = "/sbin/iptables";
const SMARTCTL:   &str = "/usr/sbin/smartctl";
// etc.
```
Use these constants everywhere instead of bare string literals.
For tools that may live in different paths across distros (e.g., `iptables` in `/usr/sbin` vs `/sbin`), check existence at startup and log a warning if not found.

---

### [ ] FIX: Sync I/O blocking the async executor

**Category:** Correctness
**Files:** `src/providers/process.rs`, `src/providers/file.rs`, `src/providers/identity.rs`

**Problem:**
The following functions perform blocking I/O directly on a tokio async executor thread, which can stall the entire runtime:

- `process_list()`: calls `procfs::process::all_processes()` which reads many `/proc/*/stat` files synchronously.
- `process_top()`: same — two calls to `all_processes()` with a `tokio::time::sleep` in between (the sleep is async-correct but the surrounding I/O is not).
- `process_tree()`: same.
- `process_inspect()`: mixes `tokio::fs` calls (async) with synchronous `proc.stat()`, `proc.status()`, `proc.environ()` (blocking procfs).
- `file_search()` → inner `search_dir()`: fully synchronous recursive `std::fs::read_dir` + `std::fs::read_to_string` inside an `async fn`, not wrapped in `spawn_blocking`.
- `identity_users()`, `identity_groups()`: synchronous `std::fs::read_to_string` on `/etc/passwd`, `/etc/group` — small files, low risk, but inconsistent.

**Fix:**
Wrap all blocking I/O sections in `tokio::task::spawn_blocking`:

```rust
// process_list example
pub async fn process_list() -> anyhow::Result<Value> {
    tokio::task::spawn_blocking(|| {
        let page_size = procfs::page_size();
        let procs: Vec<_> = all_processes()?
            // ... rest of sync logic
        Ok(serde_json::json!(procs))
    }).await?
}
```

For `process_inspect` specifically: either move all I/O into a single `spawn_blocking` closure, or use only `tokio::fs` equivalents throughout (not both).

For `file_search`: move the entire `search_dir` recursive walk into `spawn_blocking`.

---

### [ ] FIX: Audit log failure must not silently allow mutations

**Category:** Security
**File:** `src/engine/audit.rs`, `src/engine/server.rs`

**Problem:**
`AuditLogger::log()` returns `()`. If the audit log file cannot be written (disk full, wrong permissions), the operation proceeds normally — an attacker who fills the disk before sending a `process.kill` or `system.reboot` command would cause the action to execute without an audit record.

**Fix:**
Change `log()` signature to return `anyhow::Result<()>`. In `server.rs`, `complete_tool_call()` should propagate audit failures for mutation tools:

```rust
async fn complete_tool_call(
    &self,
    tool: &str,
    params: &serde_json::Value,
    start: std::time::Instant,
    success: bool,
) -> Result<(), McpError> {
    let duration = start.elapsed().as_millis() as u64;
    self.audit.log(tool, params, "allowed",
        if success { "success" } else { "error" }, duration)
        .await
        .map_err(|e| Self::internal_error(format!("Audit log failure: {}", e)))?;
    Ok(())
}
```

Define a list of mutation tools (or mark them via a flag) where audit failure is fatal. For read-only tools, a warn-and-continue policy is acceptable.

---

## P1 — Correctness

---

### [ ] FIX: `file_tail` reads entire file into memory

**Category:** Correctness / Performance
**File:** `src/providers/file.rs`

**Problem:**
`file_tail(path, 10)` reads the entire file via `tokio::fs::read_to_string` before taking the last N lines. A 500 MB log file causes 500 MB of heap allocation to return 10 lines.

**Fix:**
For files larger than a threshold (e.g., 4 MB), seek from the end and scan backwards:

```rust
pub async fn file_tail(path: &str, lines: usize) -> anyhow::Result<Value> {
    let canonical = validate_path(path)?;
    let meta = tokio::fs::metadata(&canonical).await?;
    const SMALL_FILE_THRESHOLD: u64 = 4 * 1024 * 1024;

    let result_lines = if meta.len() <= SMALL_FILE_THRESHOLD {
        // existing approach: read all then slice
        let content = tokio::fs::read_to_string(&canonical).await?;
        let all: Vec<&str> = content.lines().collect();
        let start = all.len().saturating_sub(lines);
        all[start..].iter().map(|s| s.to_string()).collect::<Vec<_>>()
    } else {
        // large file: seek from end, read in chunks, scan backwards for newlines
        tokio::task::spawn_blocking(move || tail_large_file(&canonical, lines)).await??
    };
    Ok(serde_json::json!({"path": path, "lines": result_lines}))
}

fn tail_large_file(path: &std::path::Path, n: usize) -> anyhow::Result<Vec<String>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    let size = f.seek(SeekFrom::End(0))?;
    let chunk = std::cmp::min(size, 65536);
    let mut buf = vec![0u8; chunk as usize];
    let mut lines_found: Vec<String> = Vec::new();
    let mut pos = size;
    while lines_found.len() < n && pos > 0 {
        let read_start = pos.saturating_sub(chunk);
        let read_len = pos - read_start;
        f.seek(SeekFrom::Start(read_start))?;
        buf.resize(read_len as usize, 0);
        f.read_exact(&mut buf)?;
        for line in buf.split(|&b| b == b'\n').rev() {
            if !line.is_empty() {
                lines_found.push(String::from_utf8_lossy(line).into_owned());
                if lines_found.len() >= n { break; }
            }
        }
        pos = read_start;
    }
    lines_found.reverse();
    Ok(lines_found)
}
```

---

### [ ] FIX: `journal_stream` leaks child process on task cancellation

**Category:** Correctness
**File:** `src/linux/systemd.rs`

**Problem:**
`journal_stream()` spawns a `journalctl -f` child process inside `spawn_blocking`. `child.kill()` is only reached at the bottom of the closure. If the `spawn_blocking` task is dropped or the future is cancelled before the deadline, the child process becomes an orphan and keeps running indefinitely.

**Fix:**
Wrap the child in a RAII kill-on-drop guard:

```rust
struct KillOnDrop(std::process::Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait(); // reap to avoid zombie
    }
}

// inside spawn_blocking:
let child = KillOnDrop(
    std::process::Command::new("/usr/bin/journalctl")
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .spawn()?
);
let stdout = child.0.stdout.as_ref().unwrap(); // borrow, not move
// ... read loop ...
// child dropped here → kill + wait called automatically
```

No explicit `child.kill()` needed at the end.

---

### [ ] FIX: `test_active_connections` is a tautology

**Category:** Correctness / Testing
**File:** `src/linux/network.rs`

**Problem:**
```rust
assert!(!arr.is_empty() || arr.is_empty()); // always true — tests nothing
```

**Fix:**
```rust
#[test]
fn test_active_connections() {
    let result = active_connections().unwrap();
    let arr = result.as_array().expect("Should return an array");
    // On any running Linux system there will be at least loopback connections
    // Verify structure when entries exist
    if let Some(first) = arr.first() {
        assert!(first.get("protocol").is_some(), "Entry must have protocol");
        assert!(first.get("local_addr").is_some(), "Entry must have local_addr");
        assert!(first.get("state").is_some(), "Entry must have state");
    }
}
```

---

### [ ] FIX: `test_file_read_respects_max_bytes` tests wrong behaviour

**Category:** Correctness / Testing
**File:** `src/providers/file.rs`

**Problem:**
`file_read()` returns `Err` when file exceeds `max_bytes` — it does not truncate. The test checks `content.len() <= 3` inside `if let Ok(val)`, meaning the entire assertion is silently skipped whenever `/etc/hostname` is larger than 3 bytes (it almost always is).

**Fix:**
Test the actual contract — that an error is returned when the file is too large:
```rust
#[tokio::test]
async fn test_file_read_rejects_oversized_file() {
    // /etc/hostname is typically 10-30 bytes; requesting max_bytes=1 must error
    let result = file_read("/etc/hostname", Some(1)).await;
    assert!(result.is_err(), "file_read must error when file exceeds max_bytes");
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("exceeds limit"), "Error should mention size limit");
}

#[tokio::test]
async fn test_file_read_succeeds_within_limit() {
    // Read with a generous limit — must succeed and return content
    let result = file_read("/etc/hostname", Some(1024)).await.unwrap();
    assert!(result.get("content").is_some());
    let content = result["content"].as_str().unwrap();
    assert!(!content.is_empty());
}
```

---

## P2 — Reliability & Maintainability

---

### [ ] REFACTOR: Split `server.rs` into focused modules

**Category:** Maintainability
**File:** `src/engine/server.rs` (currently 1573 lines)

**Problem:**
A single file contains: the `NeurondEngine` struct, all argument structs (~30), and all 100+ tool handler methods. It is difficult to review, navigate, and extend.

**Fix:**
Split into:
```
src/engine/
  mod.rs
  server.rs       ← NeurondEngine struct + new() + start/complete_tool_call + internal_error
  args.rs         ← all #[derive(Deserialize, JsonSchema)] arg structs
  tools/
    mod.rs        ← compose all sub-routers
    system.rs     ← system.* + process.* tool handlers
    service.rs    ← service.* + log.* tool handlers
    network.rs    ← network.* tool handlers
    file.rs       ← file.* tool handlers
    container.rs  ← container.* tool handlers
    packages.rs   ← package.* tool handlers
    identity.rs   ← identity.* tool handlers
    storage.rs    ← storage.* + schedule.* + security.* tool handlers
    desktop.rs    ← desktop.* + hardware.* + time.* tool handlers
```

Each `tools/X.rs` contains only the `#[tool]` methods relevant to that domain. The `tool_router` is composed in `tools/mod.rs` using rmcp's router composition API.

---

### [ ] REFACTOR: Replace `serde_json::json!()` responses with typed structs

**Category:** Maintainability / Type Safety
**Files:** All providers

**Problem:**
Every tool returns `serde_json::Value` built with `json!()` macros. Field name typos, missing fields, and type mismatches are invisible at compile time. Example: `"rss_bytes"` in `process_list` vs `"rss_bytes"` in `process_top` vs `"mem_mb"` — no guarantee of consistency.

**Fix:**
Define `#[derive(Serialize)]` response structs for each provider's output types:

```rust
// src/providers/types.rs  (or per-provider)
#[derive(Serialize)]
pub struct ProcessEntry {
    pub pid: i32,
    pub name: String,
    pub state: String,
    pub ppid: i32,
    pub uid: u32,
    pub user: String,
    pub rss_bytes: u64,
    pub vsize_bytes: u64,
    pub threads: i64,
}
```

Convert with:
```rust
Ok(serde_json::to_value(&ProcessEntry { .. })?)
```

Or if the function already returns `anyhow::Result<Value>`, keep the signature but fill it through the typed struct.

Prioritise providers used most frequently: `process`, `system`, `service`, `network`.

---

### [ ] FIX: Policy engine — deny-wins semantics + short-circuit

**Category:** Security / Correctness
**File:** `src/engine/policy.rs`

**Problem:**
Current `is_allowed()` iterates all rules and the last matching rule wins. This means rule order in `policy.toml` determines the result — a silent foot-gun. Adding a more specific deny after a broad allow doesn't work unless it's last.
Also, the loop does not short-circuit — it evaluates all rules even when a deny has already been found.

**Fix — option A (deny-wins, recommended):**
If any matching rule has `effect = "deny"`, return false immediately regardless of other rules. Only return true if at least one matching rule allows and zero matching rules deny:

```rust
pub fn is_allowed(&self, tool_name: &str) -> bool {
    let mut any_allow = false;
    for rule in &self.rules {
        for pattern in &rule.tools {
            if wildcard_match(pattern, tool_name) {
                match rule.effect {
                    Effect::Deny => return false,   // explicit deny always wins
                    Effect::Allow => any_allow = true,
                }
            }
        }
    }
    if any_allow { true } else { self.default_action == Effect::Allow }
}
```

Update policy tests to reflect deny-wins semantics. Update `policy.toml` documentation comment to explain the behaviour.

---

### [ ] FIX: Session D-Bus panic — make desktop tools fail gracefully

**Category:** Reliability
**Files:** `src/main.rs`, `src/engine/server.rs`, `src/providers/desktop.rs`, `src/linux/desktop.rs`

**Problem:**
`main.rs` panics if the session D-Bus is unavailable:
```rust
panic!("Session D-Bus required...");
```
This makes the daemon non-startable on headless/server deployments even when desktop tools are disabled via policy.

**Fix:**
Change `session_conn` to `Option<Arc<Connection>>`:
```rust
// main.rs
let session_conn: Option<Arc<Connection>> = match zbus::Connection::session().await {
    Ok(conn) => Some(Arc::new(conn)),
    Err(e) => {
        tracing::warn!("Session D-Bus unavailable ({}). Desktop tools will be non-functional.", e);
        None
    }
};
```

In `NeurondEngine`:
```rust
pub session_conn: Option<Arc<Connection>>,
```

In desktop tool handlers in `server.rs`, add a guard:
```rust
let conn = self.session_conn.as_ref().ok_or_else(|| McpError {
    code: ErrorCode::INTERNAL_ERROR,
    message: "Desktop tools unavailable: no session D-Bus connection".into(),
    data: None,
})?;
```

---

### [ ] IMPROVE: Extend wildcard matching to support full glob patterns

**Category:** Usability / Security
**File:** `src/engine/policy.rs`

**Problem:**
Only `foo.*` prefix wildcards are supported. Cannot express:
- `network.firewall.*` (two-level wildcard)
- `*.list` (match all list tools across providers)
- Negation

**Fix:**
Replace the hand-rolled `wildcard_match` with the `glob` crate (`glob = "0.3"`) pattern matching:

```rust
fn wildcard_match(pattern: &str, value: &str) -> bool {
    glob::Pattern::new(pattern)
        .map(|p| p.matches(value))
        .unwrap_or(false)
}
```

`glob` patterns supported: `*` (any segment), `**` (any depth), `?` (single char), `[abc]` (character class). This is a single small dependency (`glob = "0.3"`, no transitive deps).

Update tests to cover: `network.*`, `*.list`, `network.firewall.*`.
Update `policy.toml` comments with pattern syntax examples.

---

### [ ] FIX: `build_inode_pid_map()` is O(processes × fds) on every port scan

**Category:** Performance
**File:** `src/linux/network.rs`

**Problem:**
Every call to `listening_ports()` iterates all of `/proc`, reads every process's `/proc/{pid}/fd/` directory, and resolves every symlink. On a busy system with 1000 processes × 100 fds each, this is 100,000 readlink syscalls per call.

**Fix:**
Introduce a short-lived cache (TTL = 1 second) using a `std::sync::OnceLock` or `tokio::sync::Mutex<(Instant, HashMap)>`:

```rust
use std::sync::Mutex;
use std::time::{Duration, Instant};

static INODE_CACHE: Mutex<Option<(Instant, HashMap<u64, (i32, String)>)>> = Mutex::new(None);

fn build_inode_pid_map_cached() -> HashMap<u64, (i32, String)> {
    let mut guard = INODE_CACHE.lock().unwrap();
    if let Some((ts, ref map)) = *guard {
        if ts.elapsed() < Duration::from_secs(1) {
            return map.clone();
        }
    }
    let fresh = build_inode_pid_map();
    *guard = Some((Instant::now(), fresh.clone()));
    fresh
}
```

---

## P3 — Rust Idioms

---

### [ ] CLEANUP: Remove `async_trait` — use native async traits (Rust 1.75+)

**Category:** Rust Idioms / Dependency Reduction
**Files:** `src/providers/system.rs`, `Cargo.toml`

**Problem:**
`#[async_trait]` boxes every `async fn` return value (allocates a `Box<dyn Future>`), adding heap allocation overhead on every method call. Native async traits are stable since Rust 1.75 (edition 2021 project is already on a compatible edition).

**Fix:**
Remove the `async_trait` attribute from `SystemProvider` and its impl:

```rust
// Before:
#[async_trait]
pub trait SystemProvider: Send + Sync {
    async fn system_info(&self) -> anyhow::Result<Value>;
    ...
}

// After (no macro needed):
pub trait SystemProvider: Send + Sync {
    fn system_info(&self) -> impl Future<Output = anyhow::Result<Value>> + Send;
    ...
}
```

Or more simply, since the trait is object-safe only with boxing anyway (used as `Arc<dyn SystemProvider>`), use the `async-fn-in-trait` approach:
```rust
pub trait SystemProvider: Send + Sync {
    async fn system_info(&self) -> anyhow::Result<Value>;
    // Rust 1.75+: RPITIT, no boxing, no macro
}
```
Note: `Arc<dyn SystemProvider>` requires the trait to be object-safe. If `async fn` in traits causes dyn-incompatibility, keep `async_trait` only on the `dyn` boundary and use a thin wrapper. Otherwise remove the dep entirely.

Remove `async-trait` from `Cargo.toml`.

---

### [ ] CLEANUP: `Effect` should derive `Copy`

**Category:** Rust Idioms
**File:** `src/engine/policy.rs`

**Problem:**
`Effect` is a two-variant enum with no heap data. It derives `Clone` and is cloned in `is_allowed()` (`final_effect = rule.effect.clone()`). It should derive `Copy` so clones are implicit and free.

**Fix:**
```rust
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
pub enum Effect { Allow, #[default] Deny }
```

Remove all explicit `.clone()` calls on `Effect` values.

---

### [ ] CLEANUP: Replace `map_err(|e| anyhow::anyhow!(...))` with `.context()`

**Category:** Rust Idioms
**Files:** All (50+ occurrences across `src/linux/systemd.rs`, `src/providers/*.rs`)

**Problem:**
```rust
.map_err(|e| anyhow::anyhow!("manager proxy err: {}", e))?
```
is verbose. `anyhow` provides `.context()` and `.with_context()` for exactly this:
```rust
.context("systemd manager proxy")?
// or with dynamic info:
.with_context(|| format!("unit: {}", name))?
```
`.context()` also preserves the original error as a chain rather than flattening it into a string.

**Fix:**
Global search-and-replace pass. Pattern: any `.map_err(|e| anyhow::anyhow!("...: {}", e))` → `.context("...")` or `.with_context(|| ...)`. Preserve the description string; drop the `e` interpolation (it becomes a chained cause automatically).

---

### [ ] CLEANUP: `NeurondEngine` fields should not be `pub`

**Category:** Rust Idioms / Encapsulation
**File:** `src/engine/server.rs`

**Problem:**
`dbus_conn`, `session_conn`, `policy`, `audit`, `system_provider` are all `pub`. They are only accessed from within the engine's `impl` block and tests. There is no reason for external visibility.

**Fix:**
Change all fields to private (no modifier) or `pub(crate)` if accessed from sibling modules in `engine/`:

```rust
pub struct NeurondEngine {
    tool_router: ToolRouter<Self>,
    dbus_conn: Arc<Connection>,
    session_conn: Option<Arc<Connection>>,
    policy: Arc<Policy>,
    audit: Arc<AuditLogger>,
    system_provider: Arc<dyn SystemProvider>,
}
```

Add getter methods if the test suite accesses fields directly.

---

### [ ] CLEANUP: `process_nice` — replace `renice` subprocess with `nix::setpriority`

**Category:** Rust Idioms / Library usage
**File:** `src/providers/process.rs`

**Problem:**
`process_nice()` shells out to `renice` even though `nix` is already a dependency and provides direct syscall access.

**Fix:**
```rust
use nix::sys::resource::{setpriority, Which};
use nix::unistd::Pid;

pub async fn process_nice(pid: i32, priority: i32) -> anyhow::Result<Value> {
    if !(-20..=19).contains(&priority) {
        anyhow::bail!("Priority must be between -20 and 19, got {}", priority);
    }
    if pid <= 1 {
        anyhow::bail!("Refusing to renice PID {}", pid);
    }
    tokio::task::spawn_blocking(move || {
        setpriority(Which::Process(Pid::from_raw(pid)), priority)
            .map_err(|e| anyhow::anyhow!("setpriority({}, {}) failed: {}", pid, priority, e))
    }).await??;
    Ok(serde_json::json!({"pid": pid, "priority": priority, "status": "ok"}))
}
```

Remove the `renice` absolute path constant once this is done.

---

### [ ] CLEANUP: `String::from_utf8_lossy().to_string()` → `.into_owned()`

**Category:** Rust Idioms / Micro-performance
**Files:** `src/linux/systemd.rs`, `src/providers/package.rs`, `src/providers/network.rs`, many others

**Problem:**
`String::from_utf8_lossy(&bytes).to_string()` allocates a `Cow<str>` then calls `.to_string()` which clones it again if it was already an owned `String`. `.into_owned()` achieves the same result with a single allocation.

**Fix:**
```rust
// Before:
String::from_utf8_lossy(&output.stdout).to_string()

// After:
String::from_utf8_lossy(&output.stdout).into_owned()
```

Global replacement — no behavioural change.

---

### [ ] CLEANUP: `file_tail` double-reverse simplification

**Category:** Rust Idioms
**File:** `src/providers/file.rs`

**Problem:**
```rust
content.lines().rev().take(lines).collect::<Vec<_>>()
    .into_iter().rev().collect()
```
Two collects, two reverses. Verbose and allocates twice.

**Fix (for the small-file path after the large-file threshold fix above):**
```rust
let all: Vec<&str> = content.lines().collect();
let start = all.len().saturating_sub(lines);
all[start..].to_vec()
```
One collect, one slice, no reversal.

---

## P4 — Dependency Cleanup & Library Upgrades

---

### [ ] REPLACE: `time` crate in `audit.rs` → use `chrono` (already transitive)

**Category:** Dependency reduction
**File:** `src/engine/audit.rs`, `Cargo.toml`

**Problem:**
`time = { version = "0.3.47", features = ["formatting", "macros"] }` is used only for RFC3339 timestamp formatting in `audit.rs`. `chrono` is already pulled in as a transitive dependency by `bollard`.

**Fix:**
```rust
// Remove from Cargo.toml:
// time = { version = "0.3.47", features = ["formatting", "macros"] }

// audit.rs — replace:
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
// with:
use std::time::{SystemTime, UNIX_EPOCH};
```
For RFC3339 formatting without chrono as a direct dep, implement a minimal formatter:
```rust
fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Format as ISO-8601 UTC: YYYY-MM-DDTHH:MM:SSZ
    let s = secs;
    let sec = s % 60; let s = s / 60;
    let min = s % 60; let s = s / 60;
    let hour = s % 24; let days = s / 24;
    // ... day/month/year calculation
}
```
Or simply add `chrono` as a direct dep (it's lightweight and already present transitively):
```toml
chrono = { version = "0.4", features = ["serde"] }
```
```rust
let ts = chrono::Utc::now().to_rfc3339();
```
Then remove `time` from `Cargo.toml`.

---

### [ ] REPLACE: `journalctl` subprocesses → `systemd` / `rust-systemd` crate

**Category:** Library upgrade / Reliability
**Files:** `src/linux/systemd.rs`

**Problem:**
All journal operations (`journal_tail`, `journal_search`, `journal_stream`, `journal_units`, `journal_rotate`, `journal_vacuum`) spawn `journalctl` subprocesses. This:
- Requires `journalctl` to be on PATH (or absolute path)
- Parses JSON-line output which is fragile
- Each call spawns a new process (overhead)
- `journal_stream` has the child-leak issue

**Fix:**
Add the `systemd` crate:
```toml
systemd = { version = "0.10", features = ["journal"] }
```
The `systemd::journal::Journal` API provides:
- `Journal::open(JournalFiles::All, false, true)?` — open journal
- `j.seek_tail()?` + `j.previous_skip(n)` — tail N entries
- `j.match_add("_SYSTEMD_UNIT", unit)?` — filter by unit
- `j.next_entry()?` → `HashMap<String, String>` — structured fields directly

This eliminates all journalctl subprocesses, child-leak risk, JSON parsing, and PATH dependency for this entire domain.

Note: `rust-systemd` requires `libsystemd-dev` at build time. Add to README/build docs.

---

### [ ] REPLACE: `lsblk` subprocess → sysfs parsing for block devices

**Category:** Library upgrade / Reliability
**File:** `src/providers/storage.rs`

**Problem:**
`storage_block_list()` calls `lsblk -J` and parses its JSON output. This:
- Requires `lsblk` (part of `util-linux`, usually present but not guaranteed in containers)
- Output format can vary between versions

**Fix:**
Read directly from `/sys/block/`:
```rust
pub async fn storage_block_list() -> anyhow::Result<Value> {
    let mut entries = Vec::new();
    let mut dir = tokio::fs::read_dir("/sys/block").await?;
    while let Some(entry) = dir.next_entry().await? {
        let name = entry.file_name().to_string_lossy().into_owned();
        let base = entry.path();
        let size_bytes = tokio::fs::read_to_string(base.join("size")).await
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|sectors| sectors * 512); // sectors are 512 bytes
        let removable = tokio::fs::read_to_string(base.join("removable")).await
            .ok()
            .map(|s| s.trim() == "1")
            .unwrap_or(false);
        let model = tokio::fs::read_to_string(base.join("device/model")).await
            .ok()
            .map(|s| s.trim().to_string());
        entries.push(serde_json::json!({
            "name": name,
            "size_bytes": size_bytes,
            "removable": removable,
            "model": model,
        }));
    }
    Ok(serde_json::json!(entries))
}
```

---

### [ ] CONSIDER: Replace `iptables` subprocess with `nftables` support

**Category:** Future-proofing
**File:** `src/linux/network.rs`

**Problem:**
Modern Linux distros (Debian 11+, Ubuntu 20.04+, RHEL 9+) use `nftables` as the default firewall backend. `iptables` commands on these systems are shims that translate to nftables rules — which can cause inconsistencies and is deprecated.

**Options:**
1. **Short-term:** Check for `/usr/sbin/nft` first, fall back to `/sbin/iptables`. Use nft syntax when nft is available.
2. **Medium-term:** Add `nftables-rs = "0.4"` crate which provides a Rust API over the `libnftables` C library. Eliminates subprocess entirely.
3. **Long-term:** Deprecate `iptables` support entirely and document minimum kernel/distro requirements.

**Minimum fix for now:** Detect nftables vs iptables at runtime and log a warning when using the iptables shim.

---

## Testing Improvements

---

### [ ] ADD: Property tests for all input validators

**Category:** Testing
**Files:** `src/linux/systemd.rs`, `src/providers/package.rs`, `src/providers/identity.rs`, `src/providers/network.rs`, `src/providers/schedule.rs`, `src/providers/storage.rs`

**Problem:**
`validate_unit_name`, `validate_package_name`, `validate_username`, `validate_chain`, `validate_cron_schedule`, `validate_device_path` etc. are tested only with hand-picked examples. Property testing would find edge cases: null bytes, Unicode look-alikes, boundary lengths, mixed valid/invalid characters.

**Fix:**
Add `proptest` to dev-dependencies:
```toml
[dev-dependencies]
proptest = "1"
```

Example for unit name validation:
```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn validate_unit_name_never_panics(s in ".*") {
        // Must never panic, only Ok or Err
        let _ = validate_unit_name(&s);
    }

    #[test]
    fn validate_unit_name_valid_chars_always_ok(
        s in "[a-zA-Z0-9@._-]{1,64}"
    ) {
        prop_assert!(validate_unit_name(&s).is_ok());
    }

    #[test]
    fn validate_unit_name_with_semicolon_always_err(
        s in "[a-zA-Z0-9]{1,32};[a-zA-Z0-9]{1,32}"
    ) {
        prop_assert!(validate_unit_name(&s).is_err());
    }
}
```

Apply the same pattern to all validator functions.

---

### [ ] ADD: Root-guard helper for privileged tests

**Category:** Testing
**Files:** All test modules containing mount/install/lock/signal tests

**Problem:**
Tests for `storage_mount`, `package_install`, `identity_user_lock`, `process_kill` etc. silently fail or produce confusing errors when run without root. CI typically doesn't run as root.

**Fix:**
Add a shared test utility:
```rust
// src/test_utils.rs (behind #[cfg(test)])
pub fn skip_if_not_root() -> bool {
    if !nix::unistd::Uid::current().is_root() {
        eprintln!("Skipping: test requires root");
        return true;
    }
    false
}
```

Usage:
```rust
#[tokio::test]
async fn test_storage_mount_real() {
    if skip_if_not_root() { return; }
    // ... test body
}
```

Or gate behind a feature flag: `#[cfg(feature = "root-tests")]`.

---

### [ ] ADD: Integration tests against live MCP endpoint

**Category:** Testing
**Files:** `tests/integration.rs` (new file)

**Problem:**
All tests are unit tests. There is no test that:
- Starts the MCP server on a random port
- Sends a well-formed MCP `tools/call` request over HTTP
- Verifies the JSON response structure
- Tests that a denied tool returns a policy error

**Fix:**
```rust
// tests/integration.rs
#[tokio::test]
async fn test_mcp_system_info_via_http() {
    let port = find_free_port();
    let _server = spawn_test_server(port, allow_all_policy()).await;

    let client = reqwest::Client::new();
    let resp = client.post(format!("http://localhost:{}/api/v1/mcp", port))
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "system.info", "arguments": {}},
            "id": 1
        }))
        .send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["result"]["content"].is_array());
}

#[tokio::test]
async fn test_mcp_denied_tool_returns_policy_error() {
    let port = find_free_port();
    let _server = spawn_test_server(port, deny_all_policy()).await;

    let resp = call_tool(port, "system.info", json!({})).await;
    assert_eq!(resp["error"]["code"], -32600); // INVALID_REQUEST
    assert!(resp["error"]["message"].as_str().unwrap().contains("denied"));
}
```

Add `reqwest` to dev-dependencies.

---

### [ ] ADD: Policy engine edge case tests

**Category:** Testing
**File:** `src/engine/policy.rs`

**Problem:**
Current tests cover the basic allow/deny/wildcard cases. Missing:
- Empty rules list with `default_action = "allow"` — everything should be allowed
- Tool name not matching any rule — should fall through to default
- Multiple rules matching the same tool with mixed effects
- Empty tool name

**Fix:**
```rust
#[test]
fn test_default_allow_with_no_rules() {
    let policy = Policy { default_action: Effect::Allow, rules: vec![] };
    assert!(policy.is_allowed("anything"));
    assert!(policy.is_allowed("system.cpu"));
}

#[test]
fn test_default_deny_with_no_rules() {
    let policy = Policy::default(); // default = deny, no rules
    assert!(!policy.is_allowed("system.cpu"));
    assert!(!policy.is_allowed(""));
}

#[test]
fn test_no_matching_rule_falls_to_default() {
    let policy = Policy {
        default_action: Effect::Deny,
        rules: vec![PolicyRule {
            id: "allow-system".into(),
            description: None,
            effect: Effect::Allow,
            tools: vec!["system.*".into()],
        }],
    };
    assert!(!policy.is_allowed("network.interfaces")); // no match → deny
    assert!(policy.is_allowed("system.cpu"));          // matches → allow
}

#[test]
fn test_explicit_deny_overrides_allow() {
    let policy = Policy {
        default_action: Effect::Deny,
        rules: vec![
            PolicyRule { id: "a".into(), description: None, effect: Effect::Allow, tools: vec!["system.*".into()] },
            PolicyRule { id: "b".into(), description: None, effect: Effect::Deny,  tools: vec!["system.reboot".into()] },
        ],
    };
    assert!(policy.is_allowed("system.cpu"));       // allow by system.*
    assert!(!policy.is_allowed("system.reboot"));   // deny overrides allow
}
```

---

## Roadmap — Security Hardening

---

### [ ] FEAT: HTTP endpoint authentication (bearer token / mTLS)

**Category:** Security — P0 before any network exposure
**Files:** `src/main.rs`, `src/engine/server.rs`, `Cargo.toml`

**Problem:**
The server listens on `0.0.0.0:8080` with zero authentication. The policy engine controls which tools are callable, but not who is allowed to call them. Any process on the LAN that can reach port 8080 can invoke any allowed tool. Before mDNS announcement or multi-node deployment, this is effectively an unauthenticated privileged API.

**Fix — Phase 1: Static bearer token (minimal viable)**
Add an Axum middleware layer that checks an `Authorization: Bearer <token>` header on every request:

```rust
// src/engine/auth.rs
use axum::{middleware::Next, extract::{Request, State}, response::Response, http::StatusCode};

pub async fn bearer_auth(
    State(expected): State<Arc<String>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = req.headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match token {
        Some(t) if constant_time_eq(t.as_bytes(), expected.as_bytes()) => Ok(next.run(req).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}
```

Use `subtle::ConstantTimeEq` (add `subtle = "2"` to Cargo.toml) for timing-safe comparison.

Token is loaded from:
1. `NEUROND_AUTH_TOKEN` env var
2. `/etc/neurond/auth_token` file (0600, owned by neurond user)
3. If neither set: generate a random token at startup, print it to stderr once, and refuse to start silently

Wire into `main.rs`:
```rust
let app = Router::new()
    .nest_service("/api/v1/mcp", mcp_service)
    .layer(axum::middleware::from_fn_with_state(
        Arc::new(auth_token),
        bearer_auth,
    ));
```

**Fix — Phase 2: mTLS (for multi-node / cortexd integration)**
Add `rustls` + `tokio-rustls` to serve TLS, with optional client certificate verification:
```toml
[dependencies]
rustls = "0.23"
tokio-rustls = "0.26"
rcgen = "0.13"      # for dev: auto-generate self-signed cert at startup
```

At startup:
- Load server cert/key from `/etc/neurond/server.crt` + `/etc/neurond/server.key`
- Optionally load CA cert for client verification from `/etc/neurond/ca.crt`
- If no cert files exist and `NEUROND_DEV=1`: auto-generate ephemeral self-signed cert via `rcgen`, log fingerprint to stderr

**Tests:**
- Request without `Authorization` header returns `401`
- Request with wrong token returns `401`
- Request with correct token proceeds to policy check
- Timing attack: response time for wrong token is constant regardless of token length (test with criterion or manual timing)

---

### [ ] FEAT: Parameter-level policy rules

**Category:** Security / Policy Engine
**Files:** `src/engine/policy.rs`, `policy.toml`

**Problem:**
The current policy engine operates at tool-name granularity only. You can allow `file.read` or deny `file.read`, but you cannot express "allow `file.read` only for paths under `/var/log`" or "allow `process.signal` only for signal 15 (SIGTERM), not 9 (SIGKILL)". All parameter-level restrictions are currently hardcoded in the provider logic.

**Goal:**
Move parameter constraints out of provider code and into policy, making the policy the single source of truth for both tool-level and argument-level access control.

**Proposed policy syntax:**
```toml
[[rules]]
id = "file-read-logs-only"
effect = "allow"
tools = ["file.read", "file.tail", "file.search"]
conditions = [
  { param = "path", matches = "^/var/log/.*" },
]

[[rules]]
id = "allow-sigterm-only"
effect = "allow"
tools = ["process.signal"]
conditions = [
  { param = "signum", equals = 15 },
]

[[rules]]
id = "allow-package-info-no-install"
effect = "allow"
tools = ["package.*"]
conditions = [
  { param = "name", matches = "^[a-z0-9][a-z0-9+\\-.]{1,64}$" }
]
```

**Implementation:**
```rust
// src/engine/policy.rs
#[derive(Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum Condition {
    Matches { param: String, matches: String },       // regex on string param
    Equals   { param: String, equals: serde_json::Value }, // exact equality
    LessThan { param: String, less_than: i64 },
    GreaterThan { param: String, greater_than: i64 },
}

#[derive(Deserialize, Serialize, Clone)]
pub struct PolicyRule {
    pub id: String,
    pub description: Option<String>,
    pub effect: Effect,
    pub tools: Vec<String>,
    #[serde(default)]
    pub conditions: Vec<Condition>,   // NEW: all conditions must match
}
```

Policy evaluation changes:
```rust
pub fn is_allowed(&self, tool_name: &str, params: &serde_json::Value) -> bool {
    for rule in &self.rules {
        if rule.tools.iter().any(|p| wildcard_match(p, tool_name)) {
            if conditions_match(&rule.conditions, params) {
                match rule.effect {
                    Effect::Deny  => return false,
                    Effect::Allow => { /* continue, collect allows */ }
                }
            }
        }
    }
    // ...
}

fn conditions_match(conditions: &[Condition], params: &serde_json::Value) -> bool {
    conditions.iter().all(|c| match c {
        Condition::Matches { param, matches } => {
            let val = params.get(param).and_then(|v| v.as_str()).unwrap_or("");
            regex::Regex::new(matches).map(|r| r.is_match(val)).unwrap_or(false)
        },
        Condition::Equals { param, equals } => params.get(param) == Some(equals),
        // ...
    })
}
```

Add `regex = "1"` to Cargo.toml.

Update `start_tool_call` in `server.rs` to pass `params` to `policy.is_allowed(tool, params)`.

**Tests:**
- Rule with `matches` condition: only paths matching the regex are allowed
- Rule with `equals` condition: exact param match works
- Rule with no conditions: behaves identically to current behaviour
- Deny-wins: a deny condition match blocks even if an allow rule also matches

---

### [ ] FEAT: Health and readiness endpoints

**Category:** Reliability / Operations
**Files:** `src/main.rs`

**Problem:**
No `/health` or `/ready` endpoint. Required for:
- mDNS-discovered nodes to be verified alive before cortexd routes to them
- Container orchestrators (Docker health check, k8s liveness/readiness probes)
- Load balancer health checks
- Simple uptime monitoring

**Fix:**
Add two lightweight endpoints alongside the MCP service:

```rust
// src/engine/health.rs
use axum::{Json, http::StatusCode};
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub uptime_seconds: u64,
}

#[derive(Serialize)]
pub struct ReadyResponse {
    pub ready: bool,
    pub checks: ReadyChecks,
}

#[derive(Serialize)]
pub struct ReadyChecks {
    pub dbus_system: bool,
    pub dbus_session: bool,
    pub policy_loaded: bool,
    pub audit_writable: bool,
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: STARTUP_TIME.elapsed().as_secs(),
    })
}

pub async fn ready(State(state): State<Arc<AppState>>) -> (StatusCode, Json<ReadyResponse>) {
    let dbus_ok  = state.dbus_conn.inner().is_some();      // ping D-Bus
    let policy_ok = true;  // already loaded at startup
    let audit_ok  = std::fs::OpenOptions::new()
        .append(true).create(true)
        .open(&state.audit_path).is_ok();

    let all_ok = dbus_ok && policy_ok && audit_ok;
    let code = if all_ok { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (code, Json(ReadyResponse {
        ready: all_ok,
        checks: ReadyChecks {
            dbus_system: dbus_ok,
            dbus_session: state.session_conn.is_some(),
            policy_loaded: policy_ok,
            audit_writable: audit_ok,
        },
    }))
}
```

Wire into Router:
```rust
let app = Router::new()
    .route("/health", get(health))
    .route("/ready",  get(ready))
    .nest_service("/api/v1/mcp", mcp_service);
```

`/health` is always 200 if the process is up (no auth required — safe to expose to load balancers).
`/ready` returns 503 if any critical dependency is unavailable.

---

## Roadmap — MCP Proxy Provider

---

### [ ] FEAT: Upstream MCP proxy — stdio transport

**Category:** New Feature
**Files:** `src/providers/proxy.rs` (new), `src/engine/server.rs`, `Cargo.toml`

**Problem / Goal:**
`neurond` should act as a policy-enforcing multiplexer for other MCP servers. AI clients connect to one `neurond` endpoint and get access to all upstream MCPs (GitHub, Postgres, filesystem tools, etc.), with every proxied tool call going through neurond's policy engine and audit log. This is the primary value of the cortexd architecture: a single trust boundary over heterogeneous tool providers.

**Config format** (extend `policy.toml` or a new `upstream.toml`):
```toml
[[upstream]]
id = "github"
transport = "stdio"
command = ["npx", "-y", "@modelcontextprotocol/server-github"]
env = { GITHUB_TOKEN = "${GITHUB_TOKEN}" }   # env var substitution
prefix = "github"                             # tools become github.list_repos etc.
restart_on_failure = true
startup_timeout_secs = 10

[[upstream]]
id = "postgres"
transport = "http"
url = "http://localhost:9090/mcp"
prefix = "db"
auth = { type = "bearer", token_env = "PG_MCP_TOKEN" }
```

**Architecture:**
```
neurond
  └── ProxyManager (src/engine/proxy.rs)
       ├── UpstreamHandle { id, prefix, transport }
       │     ├── StdioUpstream  → spawns child process, speaks JSON-RPC over stdin/stdout
       │     └── HttpUpstream   → maintains HTTP+SSE connection to upstream MCP URL
       └── tool registry: merged list of (prefixed) upstream tools + built-in tools
```

**Stdio upstream implementation:**
```rust
// src/engine/proxy.rs
pub struct StdioUpstream {
    pub id: String,
    pub prefix: String,
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    stdout_lines: tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
    next_id: std::sync::atomic::AtomicU64,
}

impl StdioUpstream {
    pub async fn spawn(config: &UpstreamConfig) -> anyhow::Result<Self> {
        let mut cmd = tokio::process::Command::new(&config.command[0]);
        cmd.args(&config.command[1..])
           .stdin(Stdio::piped())
           .stdout(Stdio::piped())
           .stderr(Stdio::null());  // or pipe stderr to tracing::debug
        // Expand env vars
        for (k, v) in &config.env {
            cmd.env(k, expand_env_var(v));
        }
        let mut child = cmd.spawn()?;
        let stdin  = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let reader = tokio::io::BufReader::new(stdout).lines();
        Ok(Self { id: config.id.clone(), prefix: config.prefix.clone(),
                  child, stdin, stdout_lines: reader,
                  next_id: AtomicU64::new(1) })
    }

    /// Send a JSON-RPC request and wait for the matching response.
    pub async fn call(&mut self, method: &str, params: serde_json::Value)
        -> anyhow::Result<serde_json::Value>
    {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let req = serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": method, "params": params
        });
        self.stdin.write_all((req.to_string() + "\n").as_bytes()).await?;
        // Read lines until we get the matching id
        while let Some(line) = self.stdout_lines.next_line().await? {
            if let Ok(resp) = serde_json::from_str::<serde_json::Value>(&line) {
                if resp["id"] == id {
                    return if let Some(err) = resp.get("error") {
                        anyhow::bail!("upstream error: {}", err)
                    } else {
                        Ok(resp["result"].clone())
                    };
                }
            }
        }
        anyhow::bail!("upstream closed without response for id {}", id)
    }

    /// Fetch the upstream's tool list and prefix each tool name.
    pub async fn list_tools(&mut self) -> anyhow::Result<Vec<PrefixedTool>> {
        let result = self.call("tools/list", serde_json::json!({})).await?;
        let tools = result["tools"].as_array().cloned().unwrap_or_default();
        Ok(tools.into_iter().map(|t| PrefixedTool {
            prefixed_name: format!("{}.{}", self.prefix, t["name"].as_str().unwrap_or("")),
            original_name: t["name"].as_str().unwrap_or("").to_string(),
            upstream_id: self.id.clone(),
            schema: t,
        }).collect())
    }
}
```

**Integration with NeurondEngine:**
- On startup, `ProxyManager::start_all()` spawns/connects all upstreams and collects their tool lists.
- `NeurondEngine::list_tools()` returns built-in tools + all prefixed upstream tools.
- `NeurondEngine::call_tool()` checks if the tool name matches a proxy prefix → routes to `ProxyManager::call(upstream_id, original_name, params)`.
- Policy engine sees the prefixed name (`github.list_repos`) — can be allowed/denied like any built-in tool.
- Every proxy call goes through `start_tool_call` (policy) and `complete_tool_call` (audit) — same path as built-in tools.

**Lifecycle management:**
```rust
pub struct ProxyManager {
    upstreams: HashMap<String, UpstreamHandle>,
    config: Vec<UpstreamConfig>,
}

impl ProxyManager {
    pub async fn restart_failed(&mut self) {
        // Called periodically (e.g., every 5s) or on tool-call failure
        for (id, handle) in &mut self.upstreams {
            if handle.is_dead() && handle.config.restart_on_failure {
                tracing::warn!("Upstream {} died, restarting", id);
                match StdioUpstream::spawn(&handle.config).await {
                    Ok(new) => *handle = UpstreamHandle::Stdio(new),
                    Err(e)  => tracing::error!("Failed to restart {}: {}", id, e),
                }
            }
        }
    }
}
```

**Tests:**
- `test_stdio_upstream_call_roundtrip`: spawn a minimal echo MCP server (a small Rust binary in `tests/fixtures/`) and verify round-trip JSON-RPC
- `test_proxy_tool_prefixing`: tool `list_repos` from upstream `github` appears as `github.list_repos` in neurond's tool list
- `test_proxy_policy_enforced`: `github.list_repos` is denied by default; allowing it via policy makes it callable
- `test_proxy_upstream_failure_graceful`: killing the upstream child returns an `Err` from the tool call, not a panic
- `test_proxy_restart_on_failure`: after the upstream dies, it is restarted within 5 seconds

---

### [ ] FEAT: Upstream MCP proxy — HTTP+SSE transport

**Category:** New Feature (depends on stdio proxy task above)
**Files:** `src/engine/proxy.rs`

**Problem:**
Many MCP servers expose an HTTP+SSE endpoint rather than stdio. The proxy manager needs to support this transport.

**Implementation:**
```rust
pub struct HttpUpstream {
    pub id: String,
    pub prefix: String,
    client: reqwest::Client,
    base_url: String,
    auth: Option<BearerAuth>,
}

impl HttpUpstream {
    pub async fn call(&self, method: &str, params: serde_json::Value)
        -> anyhow::Result<serde_json::Value>
    {
        let req = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params
        });
        let mut rb = self.client.post(&self.base_url).json(&req);
        if let Some(ref auth) = self.auth {
            rb = rb.bearer_auth(&auth.token);
        }
        let resp = rb.send().await?.error_for_status()?;
        // For SSE: handle text/event-stream response (streaming results)
        // For plain POST: parse JSON response directly
        let body: serde_json::Value = resp.json().await?;
        if let Some(err) = body.get("error") {
            anyhow::bail!("upstream error: {}", err);
        }
        Ok(body["result"].clone())
    }
}
```

Add `reqwest = { version = "0.12", features = ["json", "stream"] }` to Cargo.toml (if not already present via another dep).

**SSE streaming support:**
For tools that return streaming results (long-running operations), use `reqwest`'s `bytes_stream()` + `futures::StreamExt` to parse SSE events and forward them through neurond's own SSE transport.

---

## Roadmap — Network Discovery

---

### [ ] FEAT: mDNS/DNS-SD self-announcement

**Category:** New Feature (requires auth task to be complete first)
**Files:** `src/engine/mdns.rs` (new), `src/main.rs`, `Cargo.toml`

**Problem / Goal:**
Each `neurond` node should announce itself on the local network so that `cortexd` (or any MCP-aware orchestrator) can discover it automatically — no manual configuration of IP addresses required. Same model as printers, AirPlay, and Chromecast devices.

**Protocol:**
- Service type: `_mcp._tcp.local.` (or `_neurond._tcp.local.` for neurond-specific discovery)
- Instance name: hostname (e.g., `myserver._mcp._tcp.local.`)
- TXT records carry metadata:
  - `v=1` — protocol version
  - `node=myserver.local` — FQDN
  - `port=8080` — HTTP port
  - `providers=system,process,service,log,network,file,container,package,identity,storage,schedule,security,time,hardware,desktop` — available providers
  - `auth=bearer` — authentication method (`bearer`, `mtls`, `none`)
  - `neurond=0.1.0` — neurond version

**Rust crate:**
```toml
[dependencies]
mdns-sd = "0.11"   # pure-Rust mDNS/DNS-SD, no Avahi dependency
```

`mdns-sd` uses `ServiceDaemon` which runs its own background thread. No `libavahi` needed.

**Implementation:**
```rust
// src/engine/mdns.rs
use mdns_sd::{ServiceDaemon, ServiceInfo};

pub struct MdnsAnnouncer {
    daemon: ServiceDaemon,
    service_fullname: String,
}

impl MdnsAnnouncer {
    pub fn start(port: u16, providers: &[&str], auth_method: &str)
        -> anyhow::Result<Self>
    {
        let hostname = gethostname::gethostname()
            .to_string_lossy()
            .into_owned();

        let daemon = ServiceDaemon::new()?;

        let instance_name = &hostname;
        let service_type  = "_mcp._tcp.local.";

        let mut properties = std::collections::HashMap::new();
        properties.insert("v".to_string(),         "1".to_string());
        properties.insert("node".to_string(),       format!("{}.local", hostname));
        properties.insert("neurond".to_string(),    env!("CARGO_PKG_VERSION").to_string());
        properties.insert("providers".to_string(),  providers.join(","));
        properties.insert("auth".to_string(),       auth_method.to_string());

        // Resolve local IP addresses to announce
        let addrs: Vec<std::net::Ipv4Addr> = local_ipaddress::get()
            .into_iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        let service = ServiceInfo::new(
            service_type,
            instance_name,
            &format!("{}.local.", hostname),
            addrs.as_slice(),
            port,
            Some(properties),
        )?;

        daemon.register(service.clone())?;
        tracing::info!("mDNS: announced {} on port {}", instance_name, port);

        Ok(Self {
            daemon,
            service_fullname: service.get_fullname().to_string(),
        })
    }
}

impl Drop for MdnsAnnouncer {
    fn drop(&mut self) {
        // Send mDNS goodbye packet so cortexd removes the node immediately
        let _ = self.daemon.unregister(&self.service_fullname);
    }
}
```

Add to `Cargo.toml`:
```toml
mdns-sd      = "0.11"
gethostname  = "0.4"
local-ip-address = "0.6"
```

Wire into `main.rs` after the server starts:
```rust
let providers = vec!["system", "process", "service", /* ... all 15 */];
let _mdns = MdnsAnnouncer::start(8080, &providers, "bearer")
    .unwrap_or_else(|e| {
        tracing::warn!("mDNS announcement failed ({}). Discovery will not work.", e);
        // Return a no-op announcer — not fatal
    });
// _mdns held for the lifetime of main, Drop sends goodbye on shutdown
```

**Security note — document clearly:**
mDNS is unauthenticated and LAN-broadcast only. It is a _discovery hint_, not a trust mechanism. `cortexd` must complete an authenticated handshake (bearer token or mTLS) with the discovered node before routing any tool calls to it. mDNS is safe precisely because authentication is enforced at the connection layer, not the discovery layer.

**Tests:**
- `test_mdns_service_registers`: `ServiceDaemon` starts without error and service is registered
- `test_mdns_goodbye_on_drop`: dropping `MdnsAnnouncer` sends an unregister call (mock ServiceDaemon)
- `test_mdns_properties_contain_providers`: TXT record includes all provider names
- `test_mdns_properties_contain_auth_method`: TXT record includes the correct auth string

---

### [ ] FEAT: cortexd integration — authenticated node registration

**Category:** New Feature (companion to mDNS task)
**Files:** `src/engine/registration.rs` (new), `src/main.rs`

**Problem:**
mDNS provides discovery on the LAN but no trust. For `cortexd` to safely route tool calls to a `neurond` node, there must be a secondary authenticated handshake. This prevents a rogue process from announcing itself on mDNS and intercepting tool calls.

**Proposed flow:**
```
neurond startup
  1. POST https://cortexd.host/nodes/register
     Body: { node_id, hostname, port, providers, pubkey_fingerprint }
     Auth: pre-shared registration token (from NEUROND_CORTEXD_TOKEN env var)
  2. cortexd responds: { node_token: "<per-node JWT or opaque token>" }
  3. neurond stores node_token; cortexd uses it to authenticate callbacks
  4. Periodic heartbeat: POST /nodes/heartbeat { node_id, uptime_seconds }
  5. On clean shutdown: POST /nodes/unregister { node_id }
```

**Implementation:**
```rust
// src/engine/registration.rs
pub struct CortexdClient {
    base_url: String,
    registration_token: String,
    node_token: Option<String>,
    http: reqwest::Client,
}

impl CortexdClient {
    pub async fn register(&mut self, node_info: &NodeInfo) -> anyhow::Result<()> {
        let resp = self.http
            .post(format!("{}/nodes/register", self.base_url))
            .bearer_auth(&self.registration_token)
            .json(node_info)
            .send().await?
            .error_for_status()?;
        let body: serde_json::Value = resp.json().await?;
        self.node_token = body["node_token"].as_str().map(|s| s.to_string());
        tracing::info!("Registered with cortexd at {}", self.base_url);
        Ok(())
    }

    pub async fn heartbeat(&self, node_id: &str, uptime_secs: u64) -> anyhow::Result<()> {
        self.http
            .post(format!("{}/nodes/heartbeat", self.base_url))
            .bearer_auth(self.node_token.as_deref().unwrap_or(""))
            .json(&serde_json::json!({"node_id": node_id, "uptime_seconds": uptime_secs}))
            .send().await?
            .error_for_status()?;
        Ok(())
    }
}
```

Configuration via env vars or `policy.toml` `[cortexd]` section:
```toml
[cortexd]
url = "https://cortexd.example.com"
registration_token_env = "NEUROND_CORTEXD_TOKEN"
heartbeat_interval_secs = 30
```

Registration is optional — if `NEUROND_CORTEXD_TOKEN` is not set, skip registration silently and only use mDNS announcement.

**Tests:**
- `test_registration_sends_correct_payload`: mock HTTP server verifies the registration JSON body
- `test_heartbeat_uses_node_token`: heartbeat Authorization header matches the token from registration response
- `test_registration_disabled_when_no_token`: no HTTP call made when env var not set

---

## Suggested Implementation Order

The tasks above have dependencies. Recommended sequence:

```
1. bearer-auth           (unblocks: all network exposure)
2. health/ready          (unblocks: cortexd health checks, mDNS viability)
3. stdio-proxy           (core proxy feature)
4. http-proxy            (extends proxy to HTTP upstreams)
5. param-level-policy    (makes proxy policy meaningful)
6. mdns-announcement     (requires auth to be safe)
7. cortexd-registration  (requires auth + health + mdns)
```

---

## Verification

After completing the above tasks:

```bash
cargo build 2>&1            # must compile clean
cargo clippy -- -D warnings  # zero warnings
cargo test 2>&1             # all tests pass or gracefully skip
cargo test --features root-tests 2>&1  # run privileged tests (requires sudo)
```

---

## Roadmap — Local Federation Proxy

**Source:** `specs/neurond-federation-spec.md`
**Priority:** High — core architectural feature
**Phase:** Phase 3 (after HTTP+SSE transport and mDNS/auth)

neurond becomes a **Local Federation Proxy**: a single MCP endpoint per machine that aggregates its own native Linux tools with any number of third-party MCP servers running on the same node (redis-mcp, postgres-mcp, custom tools, etc.). cortexd connects to one port per machine, period.

**Design Principles:**
1. **Single ingress** — one port, one TLS cert, one firewall rule per node
2. **Downstream isolation** — third-party MCP servers never bind to a network interface
3. **Lifecycle binding** — stdio children die when neurond dies; no orphans via `kill_on_drop(true)`
4. **Namespace everything** — zero tool name collisions across providers (`redis.get`, `pg.query`)
5. **Audit everything** — every proxied call hits the same JSONL log as native calls

**Module mapping (current project → federation spec):**
- `src/providers/` → spec's `native/` — keep current naming, no rename needed
- `src/engine/server.rs` → spec's `server.rs` — extend in-place
- Add new `src/federation/` module with 5 sub-files
- `policy.toml` → spec proposes `neurond.toml` as main config; see Config task below

---

### [ ] FEAT: Config schema — `neurond.toml` and `FederationConfig`

**Category:** New Feature (prerequisite for all federation tasks)
**Files:** `src/config.rs` (new), `Cargo.toml`, `neurond.toml.example` (new)

**Problem:**
The project currently uses only `policy.toml` for configuration. Federation requires a richer config file covering the server bind address, TLS settings, audit path, provider toggles, and `[[federation.servers]]` stanzas. The two files can coexist: `policy.toml` stays as the policy engine input; `neurond.toml` is the main operational config.

**Cargo.toml additions:**
```toml
[dependencies]
url          = "2"                                          # URL parsing + loopback validation
chrono       = { version = "0.4", features = ["serde"] }   # Audit timestamps
tokio-util   = { version = "0.7", features = ["rt"] }       # CancellationToken for graceful shutdown

# rmcp must include client + transport features for dual-role:
rmcp = { version = "0.16", features = [
    "server",
    "client",
    "transport-io",          # TokioChildProcess (stdio)
    "transport-sse-client",  # SseClientTransport (localhost HTTP)
    "macros",
] }
```

**`src/config.rs` — Full data structures:**
```rust
use std::collections::HashMap;
use std::path::PathBuf;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct NeurondConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub federation: FederationConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub tls: Option<TlsConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self { bind: default_bind(), port: default_port(), tls: None }
    }
}

fn default_bind() -> String { "0.0.0.0".to_string() }
fn default_port() -> u16 { 8080 }

#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub ca: Option<PathBuf>,   // Optional: mTLS client verification
}

#[derive(Debug, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_audit_path")]
    pub path: PathBuf,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self { enabled: true, path: default_audit_path() }
    }
}

fn default_audit_path() -> PathBuf { PathBuf::from("/var/log/neurond/audit.jsonl") }
fn default_true() -> bool { true }

#[derive(Debug, Default, Deserialize)]
pub struct FederationConfig {
    #[serde(default)]
    pub servers: Vec<DownstreamServer>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DownstreamServer {
    /// Namespace prefix, e.g. "redis" → all tools become "redis.<name>"
    /// Must match ^[a-z][a-z0-9_]{0,31}$
    /// Reserved: system, process, service, log, network, file, container,
    ///           package, identity, storage, schedule, security, time, hardware, desktop
    pub namespace: String,
    /// stdio or localhost
    #[serde(flatten)]
    pub transport: DownstreamTransport,
    /// Optional: only expose these specific tool names (empty = all)
    #[serde(default)]
    pub expose: Vec<String>,
    /// Health check interval, default "30s"
    #[serde(default = "default_healthcheck_interval")]
    pub healthcheck_interval: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "transport")]
pub enum DownstreamTransport {
    #[serde(rename = "stdio")]
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        /// Environment variables for the child process.
        /// Values support ${VAR_NAME} expansion at load time.
        #[serde(default)]
        env: HashMap<String, String>,
    },
    #[serde(rename = "localhost")]
    Localhost {
        /// Must resolve to 127.0.0.0/8 or ::1. Startup fails if not loopback.
        url: String,
    },
}

fn default_healthcheck_interval() -> String { "30s".to_string() }
```

**Namespace validation at startup:**
```rust
const RESERVED_NAMESPACES: &[&str] = &[
    "system", "process", "service", "log", "network", "file",
    "container", "package", "identity", "storage", "schedule",
    "security", "time", "hardware", "desktop",
];

pub fn validate_namespace(ns: &str) -> anyhow::Result<()> {
    let re = regex::Regex::new(r"^[a-z][a-z0-9_]{0,31}$").unwrap();
    if !re.is_match(ns) {
        anyhow::bail!("Invalid namespace '{}': must match ^[a-z][a-z0-9_]{{0,31}}$", ns);
    }
    if RESERVED_NAMESPACES.contains(&ns) {
        anyhow::bail!("Namespace '{}' is reserved by a native provider", ns);
    }
    Ok(())
}
```

**Config loading in `main.rs`:**
```rust
// Load neurond.toml if present, fall back to empty defaults
let config: NeurondConfig = if std::path::Path::new("neurond.toml").exists() {
    let raw = std::fs::read_to_string("neurond.toml")?;
    toml::from_str(&raw)?
} else {
    NeurondConfig::default()
};
```

**Example `neurond.toml.example`:**
```toml
[server]
bind = "0.0.0.0"
port = 8080

[audit]
enabled = true
path = "/var/log/neurond/audit.jsonl"

[[federation.servers]]
namespace = "redis"
transport = "stdio"
command   = "/usr/local/bin/redis-mcp"
args      = ["--readonly"]
env       = { REDIS_URL = "redis://127.0.0.1:6379" }
expose    = ["get", "set", "scan"]
healthcheck_interval = "30s"

[[federation.servers]]
namespace = "pg"
transport = "stdio"
command   = "npx"
args      = ["-y", "@modelcontextprotocol/server-postgres"]
env       = { DATABASE_URL = "${DATABASE_URL}" }   # expanded from environment

[[federation.servers]]
namespace = "files"
transport = "localhost"
url       = "http://127.0.0.1:3100"
```

**Tests:**
- Valid namespace `"redis"` → Ok
- Invalid namespace `"Redis"` (uppercase) → Err
- Reserved namespace `"system"` → Err
- Namespace collision between two `[[federation.servers]]` entries → startup Err
- Config with no `[federation]` section parses with empty `servers: vec![]`
- Config with `${DATABASE_URL}` in env value expands at load time

---

### [ ] FEAT: `src/federation/` module — core types and wiring

**Category:** New Feature (prerequisite for all other federation tasks)
**Files:** `src/federation/mod.rs`, `src/federation/connection.rs`, `src/main.rs`

**Problem:**
Need the fundamental data structures and module layout before any implementation tasks can proceed.

**Module structure to create:**
```
src/
  federation/
    mod.rs          # FederationManager, re-exports
    connection.rs   # DownstreamConnection + DownstreamState
    namespace.rs    # namespace_tools(), route_tool_call()
    lifecycle.rs    # spawn, connect, monitor, restart, healthcheck
    transport.rs    # stdio + localhost HTTP transport helpers
```

Add to `src/main.rs` (or wherever the module tree is declared):
```rust
mod federation;
```

**`src/federation/connection.rs` — core types:**
```rust
use rmcp::model::Tool;
use rmcp::service::RunningService;
use rmcp::RoleClient;
use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug)]
pub enum DownstreamState {
    Starting,
    Running { since: Instant },
    Restarting { attempt: u32, next_retry: Instant },
    Dead { reason: String },
}

pub struct DownstreamConnection {
    /// Config from neurond.toml
    pub config: crate::config::DownstreamServer,
    /// Current lifecycle state
    pub state: DownstreamState,
    /// Active rmcp client session (Some when Running)
    pub session: Option<RunningService<RoleClient, ()>>,
    /// Namespaced tool list (cached from last tools/list)
    pub tools: Vec<Tool>,
    /// "redis.get" -> "get" — used for routing
    pub name_map: HashMap<String, String>,
}
```

**`src/federation/mod.rs`:**
```rust
pub mod connection;
pub mod lifecycle;
pub mod namespace;
pub mod transport;

use connection::DownstreamConnection;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct FederationManager {
    /// All downstream connections, guarded by RwLock for concurrent read/write
    pub downstreams: Arc<RwLock<Vec<DownstreamConnection>>>,
    /// Handle to the upstream session for notifications (set after server starts)
    pub upstream_notify: tokio::sync::watch::Sender<()>,
}

impl FederationManager {
    pub fn new() -> (Self, tokio::sync::watch::Receiver<()>) {
        let (tx, rx) = tokio::sync::watch::channel(());
        (Self {
            downstreams: Arc::new(RwLock::new(Vec::new())),
            upstream_notify: tx,
        }, rx)
    }

    /// Aggregate all Running downstream tools for tools/list response
    pub async fn aggregate_tools(&self) -> Vec<rmcp::model::Tool> {
        let downstreams = self.downstreams.read().await;
        downstreams.iter()
            .filter(|ds| matches!(ds.state, connection::DownstreamState::Running { .. }))
            .flat_map(|ds| ds.tools.iter().cloned())
            .collect()
    }

    /// Send tools/list_changed notification to upstream
    pub fn notify_tools_changed(&self) {
        let _ = self.upstream_notify.send(());
    }
}
```

**Wire into `NeurondEngine` in `src/engine/server.rs`:**
```rust
pub struct NeurondEngine {
    // existing fields...
    pub federation: crate::federation::FederationManager,
}
```

---

### [ ] FEAT: stdio downstream spawning

**Category:** New Feature
**File:** `src/federation/lifecycle.rs`

**Problem:**
Implement spawning a stdio child process as an MCP client. This is the primary federation transport: the child process is a private pipe pair — zero network exposure.

**Implementation:**
```rust
use tokio::process::Command;
use rmcp::transport::TokioChildProcess;
use crate::config::{DownstreamServer, DownstreamTransport};
use crate::federation::connection::{DownstreamConnection, DownstreamState};
use crate::federation::namespace::namespace_tools;

pub async fn spawn_stdio_downstream(
    config: &DownstreamServer,
) -> anyhow::Result<DownstreamConnection> {
    let DownstreamTransport::Stdio { ref command, ref args, ref env } = config.transport
        else { anyhow::bail!("spawn_stdio_downstream called with non-stdio config") };

    let mut cmd = Command::new(command);
    cmd.args(args)
       .envs(env.iter())
       .stdin(std::process::Stdio::piped())
       .stdout(std::process::Stdio::piped())
       .stderr(std::process::Stdio::piped())
       // CRITICAL: kill child if neurond exits (no orphan processes)
       .kill_on_drop(true);

    let child = cmd.spawn()
        .map_err(|e| anyhow::anyhow!("Failed to spawn '{}': {}", command, e))?;

    // Wrap child in rmcp's stdio transport (handles framing)
    let transport = TokioChildProcess::new(child)
        .map_err(|e| anyhow::anyhow!("TokioChildProcess failed: {}", e))?;

    // Perform MCP initialize handshake
    let client_info = rmcp::model::ClientInfo {
        name: "neurond".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        ..Default::default()
    };
    let session = client_info.serve(transport).await
        .map_err(|e| anyhow::anyhow!("MCP handshake failed for '{}': {}", command, e))?;

    // Discover available tools
    let raw_tools = session.list_tools(None).await
        .map_err(|e| anyhow::anyhow!("tools/list failed for '{}': {}", config.namespace, e))?
        .tools;

    // Apply namespace prefix + expose filter
    let (tools, name_map) = namespace_tools(&config.namespace, &raw_tools, &config.expose);

    tracing::info!(
        namespace = %config.namespace,
        tool_count = tools.len(),
        "stdio downstream connected"
    );

    Ok(DownstreamConnection {
        config: config.clone(),
        state: DownstreamState::Running { since: std::time::Instant::now() },
        session: Some(session),
        tools,
        name_map,
    })
}
```

**Security: `kill_on_drop(true)` is mandatory** — without it, the child MCP server continues running after neurond exits, potentially accepting stale connections. Document this requirement in the module-level doc comment.

**Tests:**
- Spawn a minimal test MCP server (a small fixture binary or script in `tests/fixtures/`) and verify the connection returns `Running` state
- Verify tool list is correctly namespaced: `"get"` from namespace `"redis"` → `"redis.get"`
- `expose` filter: only listed tool names appear in the output
- Invalid command path → spawning returns `Err` (not panic)
- `kill_on_drop` behavior: drop the `DownstreamConnection` and verify the child process is gone

---

### [ ] FEAT: localhost HTTP downstream connection with loopback validation

**Category:** New Feature
**File:** `src/federation/transport.rs`

**Problem:**
Some MCP servers run as independent services (managed by systemd, shared with other consumers) and expose an HTTP endpoint. neurond must connect as an MCP client but must enforce that the URL resolves only to the loopback address — preventing proxying to remote hosts.

**Implementation:**
```rust
use rmcp::transport::SseClientTransport;
use crate::config::{DownstreamServer, DownstreamTransport};
use crate::federation::connection::{DownstreamConnection, DownstreamState};
use crate::federation::namespace::namespace_tools;

/// Security: ensure the downstream URL only resolves to a loopback address.
/// Prevents misconfiguration from exposing a remote host as a "local" MCP server.
pub fn verify_loopback(url_str: &str) -> anyhow::Result<()> {
    let url: url::Url = url_str.parse()
        .map_err(|e| anyhow::anyhow!("Invalid downstream URL '{}': {}", url_str, e))?;
    let host = url.host_str()
        .ok_or_else(|| anyhow::anyhow!("Downstream URL has no host: {}", url_str))?;

    // Resolve all addresses for the host
    use std::net::ToSocketAddrs;
    let port = url.port().unwrap_or(80);
    let addrs = format!("{}:{}", host, port).to_socket_addrs()
        .map_err(|e| anyhow::anyhow!("Cannot resolve '{}': {}", host, e))?;

    for addr in addrs {
        if !addr.ip().is_loopback() {
            anyhow::bail!(
                "Security: downstream URL '{}' resolves to non-loopback address {} — \
                 downstream MCP servers must bind to 127.0.0.1 or ::1 only",
                url_str,
                addr.ip()
            );
        }
    }
    Ok(())
}

pub async fn connect_localhost_downstream(
    config: &DownstreamServer,
) -> anyhow::Result<DownstreamConnection> {
    let DownstreamTransport::Localhost { ref url } = config.transport
        else { anyhow::bail!("connect_localhost_downstream called with non-localhost config") };

    // Enforce loopback-only before connecting
    verify_loopback(url)?;

    let transport = SseClientTransport::new(url).await
        .map_err(|e| anyhow::anyhow!("SSE connection to '{}' failed: {}", url, e))?;

    let client_info = rmcp::model::ClientInfo {
        name: "neurond".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        ..Default::default()
    };
    let session = client_info.serve(transport).await
        .map_err(|e| anyhow::anyhow!("MCP handshake failed for '{}': {}", config.namespace, e))?;

    let raw_tools = session.list_tools(None).await?.tools;
    let (tools, name_map) = namespace_tools(&config.namespace, &raw_tools, &config.expose);

    tracing::info!(
        namespace = %config.namespace,
        url = %url,
        tool_count = tools.len(),
        "localhost HTTP downstream connected"
    );

    Ok(DownstreamConnection {
        config: config.clone(),
        state: DownstreamState::Running { since: std::time::Instant::now() },
        session: Some(session),
        tools,
        name_map,
    })
}
```

**Tests:**
- `verify_loopback("http://127.0.0.1:3100")` → Ok
- `verify_loopback("http://localhost:3100")` → Ok (localhost resolves to 127.0.0.1)
- `verify_loopback("http://192.168.1.10:3100")` → Err (non-loopback)
- `verify_loopback("http://example.com:3100")` → Err (external host)
- `verify_loopback("not-a-url")` → Err (parse error)
- `verify_loopback("http://[::1]:3100")` → Ok (IPv6 loopback)

---

### [ ] FEAT: Namespace routing — tool rewriting and request routing

**Category:** New Feature
**File:** `src/federation/namespace.rs`

**Problem:**
When neurond discovers tools from a downstream, tool names like `"get"` must be rewritten to `"redis.get"` before being advertised upstream. When a client calls `"redis.get"`, neurond must route to the redis downstream and call `"get"` with the original (un-namespaced) name. This bidirectional mapping is the core of the federation routing layer.

**`src/federation/namespace.rs`:**
```rust
use rmcp::model::Tool;
use std::collections::HashMap;

/// Rewrite downstream tools with a namespace prefix.
///
/// Returns:
///   - namespaced tools: Tool list with prefixed names for presentation to upstream
///   - name_map: "redis.get" → "get" for reverse-lookup during routing
pub fn namespace_tools(
    namespace: &str,
    raw_tools: &[Tool],
    expose_filter: &[String],
) -> (Vec<Tool>, HashMap<String, String>) {
    let mut tools = Vec::new();
    let mut name_map = HashMap::new();

    for tool in raw_tools {
        let original_name = tool.name.as_str();

        // Apply expose filter: if set, only forward listed tools
        if !expose_filter.is_empty() && !expose_filter.iter().any(|e| e == original_name) {
            continue;
        }

        let namespaced = format!("{}.{}", namespace, original_name);

        let mut namespaced_tool = tool.clone();
        namespaced_tool.name = namespaced.clone().into();
        // Prefix description for clarity in tool listings
        namespaced_tool.description = Some(format!(
            "[{}] {}",
            namespace,
            tool.description.as_deref().unwrap_or(""),
        ).into());

        name_map.insert(namespaced, original_name.to_string());
        tools.push(namespaced_tool);
    }

    (tools, name_map)
}
```

**Request routing in `src/engine/server.rs` — extend `call_tool` handler:**
```rust
/// Route a tool call to either a native provider or a federated downstream.
async fn route_tool_call(
    &self,
    tool_name: &str,
    arguments: serde_json::Value,
) -> Result<rmcp::model::CallToolResult, rmcp::McpError> {
    // 1. Try native tools first (no namespace prefix in native tool names)
    if !tool_name.contains('.') || self.is_native_tool(tool_name) {
        return self.call_native_tool(tool_name, arguments).await;
    }

    // 2. Look up the downstream that owns this namespaced tool
    let downstreams = self.federation.downstreams.read().await;
    for downstream in downstreams.iter() {
        if let Some(original_name) = downstream.name_map.get(tool_name) {
            // Audit the proxied call
            self.audit_proxy_call(tool_name, &downstream.config.namespace, original_name).await;

            let session = downstream.session.as_ref()
                .ok_or_else(|| rmcp::McpError::internal_error(
                    format!("Downstream '{}' is not currently running", downstream.config.namespace),
                    None,
                ))?;

            // Forward to downstream with the original (un-prefixed) name
            return session.call_tool(original_name, arguments).await
                .map_err(|e| rmcp::McpError::internal_error(e.to_string(), None));
        }
    }

    Err(rmcp::McpError::invalid_params(
        format!("Tool '{}' not found in native providers or any federated downstream", tool_name),
        None,
    ))
}
```

**`tools/list` aggregation in `NeurondEngine`:**
```rust
fn list_all_tools(&self) -> Vec<rmcp::model::Tool> {
    let mut all = self.native_tool_list.clone();
    // aggregate_tools() filters out Restarting/Dead downstreams
    // so clients never see tools they can't call
    all.extend(
        futures::executor::block_on(self.federation.aggregate_tools())
    );
    all
}
```

**Tests:**
- `namespace_tools("redis", tools, &[])` — all tools get `"redis."` prefix
- `namespace_tools("redis", tools, &["get".into()])` — only `"get"` is included as `"redis.get"`
- Empty `raw_tools` → empty output
- `name_map` reverse lookup: `"redis.get"` → `"get"`
- Tool description includes `"[redis]"` prefix

---

### [ ] FEAT: Lifecycle management — startup, restart policy, graceful shutdown

**Category:** New Feature
**File:** `src/federation/lifecycle.rs`

**Problem:**
Downstream MCP servers can crash, be updated, or time out. neurond must:
1. Connect all downstreams at startup (or schedule retry if startup fails)
2. Monitor each downstream and detect disconnection
3. Restart with exponential backoff (max 5 attempts, max 60s delay)
4. Mark as Dead if max retries exceeded and remove its tools from the advertised list
5. Shut down all downstreams cleanly on SIGTERM/SIGINT

**Startup sequence (in `main.rs`):**
```
1. Parse neurond.toml
2. Validate all namespaces (reserved check, collision check, format check)
3. Initialize native providers (D-Bus, procfs)
4. Start audit logger
5. For each [[federation.servers]]:
   a. Attempt connect/spawn (stdio or localhost)
   b. On success: add to FederationManager.downstreams as Running
   c. On failure: add as Restarting{attempt:0} and schedule retry
   d. Spawn a monitor task per downstream
6. Bind upstream HTTP+SSE listener
7. Accept MCP client connections
```

**Restart policy (exponential backoff):**
```rust
pub const MAX_RESTART_ATTEMPTS: u32 = 5;
pub const BASE_BACKOFF_SECS: u64 = 1;
pub const MAX_BACKOFF_SECS: u64 = 60;

/// Compute backoff delay for attempt N (1-indexed).
/// Sequence: 1s, 2s, 4s, 8s, 16s, 32s, 60s (capped)
pub fn backoff_duration(attempt: u32) -> std::time::Duration {
    let secs = std::cmp::min(
        BASE_BACKOFF_SECS * 2u64.pow(attempt.saturating_sub(1)),
        MAX_BACKOFF_SECS,
    );
    std::time::Duration::from_secs(secs)
}

/// Spawned per downstream. Monitors for disconnect, attempts restart.
pub async fn monitor_downstream(
    federation: Arc<crate::federation::FederationManager>,
    index: usize,
    cancel: tokio_util::sync::CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("Monitor task for downstream[{}] shutting down", index);
                return;
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
        }

        let is_dead = {
            let ds = federation.downstreams.read().await;
            ds.get(index).map(|d| {
                matches!(d.state, DownstreamState::Running { .. })
                && d.session.as_ref().map(|s| s.is_closed()).unwrap_or(true)
            }).unwrap_or(false)
        };

        if is_dead {
            let attempt = {
                let mut ds_list = federation.downstreams.write().await;
                let ds = &mut ds_list[index];
                let attempt = match &ds.state {
                    DownstreamState::Restarting { attempt, .. } => *attempt + 1,
                    _ => 1,
                };
                if attempt > MAX_RESTART_ATTEMPTS {
                    tracing::error!(
                        namespace = %ds.config.namespace,
                        "Max restart attempts exceeded — marking downstream as Dead"
                    );
                    ds.state = DownstreamState::Dead {
                        reason: format!("Failed after {} restart attempts", attempt),
                    };
                    ds.tools.clear();
                    ds.name_map.clear();
                    drop(ds_list);
                    // Notify upstream client that tool list has shrunk
                    federation.notify_tools_changed();
                    return;
                }
                let delay = backoff_duration(attempt);
                tracing::warn!(
                    namespace = %ds.config.namespace,
                    attempt,
                    delay_secs = delay.as_secs(),
                    "Downstream disconnected, scheduling restart"
                );
                ds.state = DownstreamState::Restarting {
                    attempt,
                    next_retry: std::time::Instant::now() + delay,
                };
                drop(ds_list);
                federation.notify_tools_changed();
                delay
            };

            tokio::time::sleep(attempt).await;

            // Attempt reconnection
            reconnect_downstream(&federation, index).await;
        }
    }
}

async fn reconnect_downstream(federation: &crate::federation::FederationManager, index: usize) {
    let config = {
        let ds = federation.downstreams.read().await;
        ds[index].config.clone()
    };

    let result = match &config.transport {
        crate::config::DownstreamTransport::Stdio { .. } =>
            super::lifecycle::spawn_stdio_downstream(&config).await,
        crate::config::DownstreamTransport::Localhost { .. } =>
            super::transport::connect_localhost_downstream(&config).await,
    };

    let mut ds_list = federation.downstreams.write().await;
    match result {
        Ok(new_conn) => {
            tracing::info!(namespace = %config.namespace, "Downstream reconnected");
            ds_list[index] = new_conn;
            drop(ds_list);
            federation.notify_tools_changed();
        }
        Err(e) => {
            tracing::warn!(namespace = %config.namespace, error = %e, "Reconnect attempt failed");
            // State already set to Restarting; monitor loop will retry
        }
    }
}
```

**Graceful shutdown:**
```rust
use tokio_util::sync::CancellationToken;

pub async fn shutdown_all_downstreams(federation: &crate::federation::FederationManager) {
    let mut ds_list = federation.downstreams.write().await;
    for ds in ds_list.iter_mut() {
        if let Some(session) = ds.session.take() {
            // Send MCP shutdown notification to downstream
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                session.cancel(),
            ).await;
        }
        // stdio children: kill_on_drop will handle them, but explicit is better
        // (child is consumed by TokioChildProcess transport; no separate handle needed)
    }
}
```

Wire `CancellationToken` into `main.rs` SIGTERM handler:
```rust
let cancel = CancellationToken::new();
let cancel_clone = cancel.clone();
tokio::spawn(async move {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
    tokio::select! {
        _ = sigterm.recv() => {},
        _ = tokio::signal::ctrl_c() => {},
    }
    cancel_clone.cancel();
});
```

**Tests:**
- `backoff_duration(1)` = 1s, `backoff_duration(2)` = 2s, `backoff_duration(5)` = 16s, `backoff_duration(6)` = 32s, `backoff_duration(10)` = 60s (capped)
- Downstream dies → `notify_tools_changed()` called → tools removed from aggregate list
- After max retries, state transitions to `Dead` and monitor task exits
- `shutdown_all_downstreams` completes within 3 seconds even if downstreams are unresponsive (timeout enforced)

---

### [ ] FEAT: Downstream health checking and `neurond.status` meta-tool

**Category:** New Feature
**Files:** `src/federation/lifecycle.rs`, `src/engine/server.rs`

**Problem:**
Two forms of health checking are needed:
1. **Periodic downstream health check** — neurond calls `tools/list` on each Running downstream every N seconds; if it times out, treat as disconnected and trigger restart logic
2. **`neurond.status` meta-tool** — cortexd (or any MCP client) can call this to get the health of neurond itself plus all downstream states

**Downstream health check (per-downstream loop, runs alongside monitor):**
```rust
pub async fn healthcheck_loop(
    federation: Arc<crate::federation::FederationManager>,
    index: usize,
    interval_secs: u64,
    cancel: tokio_util::sync::CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(std::time::Duration::from_secs(interval_secs)) => {}
        }

        let alive = {
            let ds = federation.downstreams.read().await;
            if let Some(session) = ds.get(index).and_then(|d| d.session.as_ref()) {
                matches!(
                    tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        session.list_tools(None),
                    ).await,
                    Ok(Ok(_))
                )
            } else {
                false
            }
        };

        if !alive {
            tracing::warn!(
                "Healthcheck failed for downstream[{}], triggering restart logic",
                index
            );
            // Mark as disconnected — monitor loop will handle the restart
            let mut ds_list = federation.downstreams.write().await;
            if let Some(ds) = ds_list.get_mut(index) {
                if matches!(ds.state, DownstreamState::Running { .. }) {
                    ds.session = None; // signal to monitor that it should restart
                }
            }
        }
    }
}
```

**`neurond.status` meta-tool in `src/engine/server.rs`:**
```rust
#[tool(description = "Get neurond status: version, uptime, native providers, and federated downstream states")]
async fn neurond_status(&self) -> Result<CallToolResult, McpError> {
    let downstreams = self.federation.downstreams.read().await;

    let status = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": self.start_time.elapsed().as_secs(),
        "native_providers": [
            "system", "process", "service", "log", "network", "file",
            "container", "package", "identity", "storage", "schedule",
            "security", "time", "hardware", "desktop"
        ],
        "federation": downstreams.iter().map(|ds| serde_json::json!({
            "namespace": ds.config.namespace,
            "state": match &ds.state {
                DownstreamState::Starting => "starting",
                DownstreamState::Running { .. } => "running",
                DownstreamState::Restarting { attempt, .. } =>
                    &format!("restarting (attempt {})", attempt),
                DownstreamState::Dead { reason } =>
                    &format!("dead: {}", reason),
            },
            "tool_count": ds.tools.len(),
            "transport": match &ds.config.transport {
                DownstreamTransport::Stdio { command, .. } => format!("stdio:{}", command),
                DownstreamTransport::Localhost { url } => format!("localhost:{}", url),
            },
        })).collect::<Vec<_>>(),
    });

    Ok(CallToolResult::success(vec![Content::json(status)?]))
}
```

**Tests:**
- `neurond_status` returns the meta-tool result without error (no downstreams → empty federation array)
- With a running downstream: state shows `"running"`, tool_count > 0
- With a dead downstream: state shows `"dead: ..."`, tool_count = 0

---

### [ ] FEAT: Audit logging — extend `AuditEntry` for federation

**Category:** New Feature
**File:** `src/engine/audit.rs`

**Problem:**
The current `AuditEntry` struct does not capture:
- Which MCP client is making the call (client identity from mTLS or session metadata)
- Whether the call was proxied to a downstream (routed_to, original_tool)
- Downstream lifecycle events (state changes)

These are needed for a complete audit trail in multi-provider deployments.

**Extended `AuditEntry`:**
```rust
use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct AuditEntry {
    /// ISO 8601 timestamp
    pub timestamp: DateTime<Utc>,
    /// MCP client identity — from mTLS CN when available, otherwise "unknown"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    /// "tool_call" | "tool_result" | "tools_list" | "downstream_state_change"
    pub event: String,
    /// Full namespaced tool name as seen by the client (e.g. "redis.get")
    pub tool: String,
    /// Decision: "allow" | "deny" | "error"
    pub decision: String,
    /// Parameters passed to the tool (if allowed by policy)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
    /// If proxied: which namespace handled it
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routed_to: Option<String>,
    /// If proxied: the original un-namespaced tool name (e.g. "get")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_tool: Option<String>,
    /// Call duration in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// true = success, false = error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,
    /// Error message if failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
```

**Example log lines:**
```jsonl
{"timestamp":"2026-03-15T14:22:01Z","client":"cortexd-prod","event":"tool_call","tool":"system.info","decision":"allow","duration_ms":2,"success":true}
{"timestamp":"2026-03-15T14:22:01Z","client":"cortexd-prod","event":"tool_call","tool":"redis.get","decision":"allow","routed_to":"redis","original_tool":"get","duration_ms":4,"success":true}
{"timestamp":"2026-03-15T14:22:05Z","event":"downstream_state_change","tool":"","decision":"allow","routed_to":"pg","error":"Process exited with code 1"}
{"timestamp":"2026-03-15T14:22:06Z","event":"downstream_state_change","tool":"","decision":"allow","routed_to":"pg","error":"Restarting (attempt 1, backoff 1s)"}
```

**Changes:**
- Add `chrono = { version = "0.4", features = ["serde"] }` (already in Cargo.toml additions above)
- Replace `SystemTime` timestamps with `chrono::Utc::now()`
- Add `client` field (populated from mTLS CN or HTTP header, `None` until auth is implemented)
- Add `routed_to` + `original_tool` in the proxied call path
- Add `"downstream_state_change"` event type emitted by the lifecycle monitor

---

### [ ] FEAT: `notifications/tools/list_changed` — notify upstream on downstream state change

**Category:** New Feature
**File:** `src/engine/server.rs`, `src/federation/mod.rs`

**Problem:**
When a downstream crashes or its tool list changes, the MCP upstream client (cortexd or Claude Desktop) must be notified that `tools/list` has changed. Without this, the client continues attempting to call tools that no longer exist.

MCP supports this via the `notifications/tools/list_changed` notification.

**Implementation:**
```rust
// In FederationManager::notify_tools_changed():
// Sends on the watch channel, which the server loop listens to

// In server.rs main loop — listen for tool list changes and send MCP notification:
let mut tools_changed = federation_notify_rx;
tokio::spawn(async move {
    loop {
        tools_changed.changed().await.ok();
        // Notify the upstream MCP client
        if let Some(ref upstream) = upstream_session {
            tracing::info!("Tool list changed — sending notifications/tools/list_changed");
            let _ = upstream.notify_tools_list_changed().await;
        }
    }
});
```

The `tokio::sync::watch::channel(())` approach (already wired in the module task) means:
- Multiple state changes during a backoff delay are coalesced into one notification
- The listener always gets the latest state without queuing

**Tests:**
- Killing a downstream triggers `notify_tools_changed()` within 10 seconds
- The aggregated tool list no longer includes the dead downstream's tools after notification
- A new connection after restart triggers another notification with the restored tools

---

### [ ] FEAT: `neurond-lite` — federation-only build without Linux providers

**Category:** New Feature / Build variant
**Files:** `Cargo.toml`, `src/main.rs`, `src/providers/mod.rs`, all provider files

**Problem:**
The user has specified that federation should "probably be also offered in a neurond-lite version that will ship without the linux controls." This means:
- A smaller binary with no Linux system provider code compiled in
- Safe to run on non-Linux platforms (macOS, WSL2 dev environments)
- Useful as a pure MCP proxy/aggregator without any system management risk
- Smaller attack surface — no `process.kill`, `service.restart`, `package.install`, etc.

**Cargo.toml — add feature flags:**
```toml
[features]
default = ["linux-providers"]

# All 15 native Linux provider modules.
# When disabled, neurond acts as a pure federation proxy only.
linux-providers = [
    "dep:procfs",
    "dep:nix",
    "dep:bollard",
    "dep:x509-parser",
]

# Explicit alias for building the lite variant:
# cargo build --no-default-features
```

**`src/providers/mod.rs`:**
```rust
#[cfg(feature = "linux-providers")]
pub mod system;
#[cfg(feature = "linux-providers")]
pub mod process;
#[cfg(feature = "linux-providers")]
pub mod service;
#[cfg(feature = "linux-providers")]
pub mod log;
#[cfg(feature = "linux-providers")]
pub mod network;
#[cfg(feature = "linux-providers")]
pub mod file;
#[cfg(feature = "linux-providers")]
pub mod container;
#[cfg(feature = "linux-providers")]
pub mod package;
#[cfg(feature = "linux-providers")]
pub mod identity;
#[cfg(feature = "linux-providers")]
pub mod storage;
#[cfg(feature = "linux-providers")]
pub mod schedule;
#[cfg(feature = "linux-providers")]
pub mod security;
#[cfg(feature = "linux-providers")]
pub mod time;
#[cfg(feature = "linux-providers")]
pub mod hardware;
#[cfg(feature = "linux-providers")]
pub mod desktop;
```

**`src/main.rs` — conditional D-Bus initialization:**
```rust
#[cfg(feature = "linux-providers")]
let dbus_system_conn = Arc::new(zbus::Connection::system().await?);
#[cfg(feature = "linux-providers")]
let dbus_session_conn = zbus::Connection::session().await.ok().map(Arc::new);

#[cfg(not(feature = "linux-providers"))]
let dbus_system_conn = unreachable_placeholder();  // not compiled
```

**`src/engine/server.rs` — conditional tool registration:**
```rust
#[cfg(feature = "linux-providers")]
{
    // Register all 100 native tools
    all_tools.extend(self.native_system_tools());
    // ... etc
}

// neurond.status is always registered regardless of feature flags
```

**Build targets:**
```bash
# Full neurond with all 100 Linux tools + federation
cargo build --release

# neurond-lite: federation proxy only, no Linux provider code
cargo build --release --no-default-features

# Verify lite build compiles
cargo check --no-default-features

# Run lite tests (no Linux-specific tests)
cargo test --no-default-features
```

**Package naming in Cargo.toml:**
```toml
[[bin]]
name = "neurond"
required-features = []   # always buildable

# Optional: a distinct binary name for the lite variant
# Users can alias this with a Makefile target
```

**Tests:**
- `cargo check --no-default-features` compiles without errors on Linux
- `cargo test --no-default-features` runs without panics (no Linux syscalls attempted)
- Lite binary at startup: `tools/list` returns only `neurond.status` and any federated tools, no `system.*` etc.
- Full binary at startup: all 100+ tools present

---

### [ ] CONSIDER: Dynamic federation config reload (Open Question #1)

**Category:** Future Feature
**File:** `src/federation/lifecycle.rs`

**Problem:**
Currently, `[[federation.servers]]` is read once at startup. Adding or removing a downstream server requires restarting neurond, which also restarts all stdio child processes.

**Options:**
1. **SIGHUP reload** — catch SIGHUP, re-read `neurond.toml`, diff against current downstreams, start new ones, shut down removed ones, leave unchanged ones running. No disruption to existing connections.
2. **File watcher** — use the `notify = "6"` crate to watch `neurond.toml` for changes, debounce, and trigger reload automatically. Convenient for operators but adds a background thread.
3. **No dynamic reload (current)** — simplest, use systemd to restart the service (`systemctl reload neurond` via `ExecReload=/bin/kill -HUP $MAINPID`).

**Recommendation:** Implement SIGHUP-based reload in Phase 4.

**Rough implementation sketch for SIGHUP approach:**
```rust
let mut sighup = tokio::signal::unix::signal(SignalKind::hangup())?;
tokio::spawn(async move {
    loop {
        sighup.recv().await;
        tracing::info!("SIGHUP received, reloading federation config...");
        match reload_federation_config(&federation, &config_path).await {
            Ok(()) => tracing::info!("Federation config reloaded"),
            Err(e) => tracing::error!("Config reload failed: {}", e),
        }
    }
});
```

---

### [ ] CONSIDER: Config secrets — env var expansion in federation env values (Open Question #5)

**Category:** Security / Config
**File:** `src/config.rs`

**Problem:**
`env` values in `[[federation.servers]]` may contain database passwords:
```toml
[[federation.servers]]
env = { DATABASE_URL = "postgresql://user:password@localhost/db" }
```
Storing passwords in plain TOML is bad practice. The config file would need to be root-owned with 0600 permissions, which is restrictive.

**Solution: `${VAR_NAME}` expansion at config load time:**
```rust
/// Expand ${VAR_NAME} references in a string using the process environment.
/// Fails fast if the referenced variable is not set.
pub fn expand_env_var(value: &str) -> anyhow::Result<String> {
    let mut result = value.to_string();
    // Find all ${...} patterns
    while let Some(start) = result.find("${") {
        let end = result[start..].find('}')
            .ok_or_else(|| anyhow::anyhow!("Unclosed ${{}} in config value: {}", value))?
            + start;
        let var_name = &result[start + 2..end];
        let var_value = std::env::var(var_name)
            .map_err(|_| anyhow::anyhow!(
                "Config references ${{{}}}, but that environment variable is not set",
                var_name
            ))?;
        result.replace_range(start..=end, &var_value);
    }
    Ok(result)
}
```

Apply during config loading:
```rust
// After parsing DownstreamTransport::Stdio, expand env values
if let DownstreamTransport::Stdio { ref mut env, .. } = server.transport {
    for val in env.values_mut() {
        *val = expand_env_var(val)?;
    }
}
```

**Tests:**
- `expand_env_var("postgresql://${DB_USER}:${DB_PASS}@localhost/db")` with vars set → expanded string
- Missing env var → `Err` with helpful message naming the variable
- No `${...}` in value → returned unchanged
- Nested `${...}` → expand left-to-right (or reject with error)

---

### [ ] CONSIDER: Streaming tool results proxy (Open Question #3)

**Category:** Architecture / Future Feature
**Files:** `src/federation/namespace.rs`, `src/engine/server.rs`

**Problem:**
The current routing layer assumes tool calls return a single `CallToolResult`. Some MCP tools return streaming results (e.g., `log.stream` in neurond itself). When proxying such a tool from a downstream, the proxy must forward the stream incrementally rather than buffering the entire response.

**Current status:** `rmcp` handles streaming at the transport level. The routing layer (`route_tool_call`) calls `session.call_tool()` and returns a single result — this will buffer the entire stream.

**Required investigation:**
1. Does `rmcp`'s `session.call_tool()` already handle streaming responses transparently?
2. If not, does rmcp expose a streaming call API?
3. How does this interact with neurond's own HTTP+SSE upstream transport?

**This is directly relevant to the existing `log.stream` tool** — if a downstream exposes a streaming log tool, we need stream forwarding to work correctly.

**Action:** Before implementing federation Phase 3, investigate rmcp's streaming capabilities and document the approach. Create a follow-up task if a custom streaming proxy layer is needed.

---

## Federation Implementation Order

```
Phase 3 — Local Federation (this spec)

1.  config-schema           # FederationConfig types, namespace validation, neurond.toml
2.  federation-module       # Module structure, core types (DownstreamConnection, FederationManager)
3.  stdio-spawning          # TokioChildProcess, MCP handshake, kill_on_drop
4.  localhost-http          # SseClientTransport, verify_loopback()
5.  namespace-routing       # namespace_tools(), route_tool_call(), aggregate_tools()
6.  lifecycle-management    # monitor task, exponential backoff, shutdown
7.  healthcheck             # healthcheck_loop, neurond.status meta-tool
8.  audit-extension         # Extended AuditEntry with client/routed_to/original_tool
9.  tools-list-changed      # notifications/tools/list_changed via watch channel
10. neurond-lite            # linux-providers feature flag, --no-default-features build
11. env-expansion           # ${VAR_NAME} expansion in federation env config values
12. streaming-investigation # Assess rmcp streaming capabilities for log.stream proxy
13. dynamic-reload          # SIGHUP-based config reload (Phase 4)
```

**Cargo.toml diff summary for federation:**
```toml
# New dependencies:
url          = "2"
tokio-util   = { version = "0.7", features = ["rt"] }

# Updated: rmcp needs additional features
rmcp = { version = "0.16", features = [
    "server",
    "client",           # NEW: dual-role
    "transport-io",     # NEW: TokioChildProcess for stdio
    "transport-sse-client",  # NEW: SseClientTransport for localhost HTTP
    "macros",
] }

# chrono is already needed for audit; add serde feature if not present:
chrono = { version = "0.4", features = ["serde"] }
```

---

## Final Verification

```bash
# Full build
cargo build 2>&1
cargo clippy -- -D warnings
cargo test 2>&1
cargo test --features root-tests 2>&1

# Federation lite build
cargo build --no-default-features 2>&1
cargo clippy --no-default-features -- -D warnings
cargo test --no-default-features 2>&1
```
