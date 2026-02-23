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

## Verification

After completing the above tasks:

```bash
cargo build 2>&1            # must compile clean
cargo clippy -- -D warnings  # zero warnings
cargo test 2>&1             # all tests pass or gracefully skip
cargo test --features root-tests 2>&1  # run privileged tests (requires sudo)
```
