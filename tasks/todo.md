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
