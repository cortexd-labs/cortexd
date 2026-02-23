use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::process::Command;
use zbus::zvariant::{OwnedObjectPath, Type};
use zbus::{proxy, Connection};

/// Maximum length for grep patterns to prevent ReDoS in journalctl.
const MAX_GREP_LENGTH: usize = 256;

/// Systemd enable/disable change triple: (type, symlink_path, destination).
type UnitChange = (String, String, String);

/// Validate a systemd unit name against a safe pattern.
/// Rejects names that could be used for argument injection.
fn validate_unit_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        anyhow::bail!("Unit name cannot be empty");
    }
    if name.len() > 256 {
        anyhow::bail!("Unit name too long (max 256 chars)");
    }
    // Allow alphanumeric, @, -, _, . (standard systemd unit name characters)
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || "@.-_".contains(c)) {
        anyhow::bail!("Unit name contains invalid characters: {}", name);
    }
    Ok(())
}

/// Validate and sanitize a grep keyword for journalctl.
fn validate_grep_keyword(keyword: &str) -> anyhow::Result<()> {
    if keyword.is_empty() {
        anyhow::bail!("Search keyword cannot be empty");
    }
    if keyword.len() > MAX_GREP_LENGTH {
        anyhow::bail!("Search keyword too long (max {} chars)", MAX_GREP_LENGTH);
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct UnitInfo {
    pub name: String,
    pub description: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub following: String,
    pub unit_path: OwnedObjectPath,
    pub job_id: u32,
    pub job_type: String,
    pub job_path: OwnedObjectPath,
}

#[proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
trait SystemdManager {
    fn list_units(&self) -> zbus::Result<Vec<UnitInfo>>;
    fn get_unit(&self, name: &str) -> zbus::Result<OwnedObjectPath>;
    fn start_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    fn stop_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    fn restart_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    /// Enable unit files; returns (carries_install_info, changes).
    fn enable_unit_files(
        &self,
        files: &[&str],
        runtime: bool,
        force: bool,
    ) -> zbus::Result<(bool, Vec<UnitChange>)>;
    /// Disable unit files; returns change list.
    fn disable_unit_files(
        &self,
        files: &[&str],
        runtime: bool,
    ) -> zbus::Result<Vec<UnitChange>>;
    /// Reload the daemon configuration (equivalent to daemon-reload).
    fn reload(&self) -> zbus::Result<()>;
}

#[proxy(
    interface = "org.freedesktop.systemd1.Unit",
    default_service = "org.freedesktop.systemd1"
)]
trait SystemdUnit {
    #[zbus(property)]
    fn description(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn active_state(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn sub_state(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn load_state(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn requires(&self) -> zbus::Result<Vec<String>>;
    #[zbus(property)]
    fn wants(&self) -> zbus::Result<Vec<String>>;
    #[zbus(property)]
    fn after(&self) -> zbus::Result<Vec<String>>;
    #[zbus(property)]
    fn before(&self) -> zbus::Result<Vec<String>>;
}

#[proxy(
    interface = "org.freedesktop.systemd1.Service",
    default_service = "org.freedesktop.systemd1"
)]
trait SystemdService {
    #[zbus(property, name = "MainPID")]
    fn main_pid(&self) -> zbus::Result<u32>;
    #[zbus(property)]
    fn memory_current(&self) -> zbus::Result<u64>;
    #[zbus(property, name = "CPUUsageNSec")]
    fn cpu_usage_nsec(&self) -> zbus::Result<u64>;
    #[zbus(property)]
    fn tasks_current(&self) -> zbus::Result<u64>;
}

/// Execute a command and return stdout as a String.
/// Used for journalctl subprocess calls (journal has no D-Bus API).
fn execute_command_stdout(cmd_name: &str, args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new(cmd_name)
        .args(args)
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to execute {}: {}", cmd_name, e))?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Command {} failed with status: {}",
            cmd_name, output.status
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub async fn list_units(connection: &Connection) -> anyhow::Result<Value> {
    let manager = SystemdManagerProxy::new(connection)
        .await
        .map_err(|e| anyhow::anyhow!("manager proxy err: {}", e))?;

    let units = manager
        .list_units()
        .await
        .map_err(|e| anyhow::anyhow!("list_units failed: {}", e))?;

    let mut mapped = Vec::new();
    for u in units {
        if u.name.ends_with(".service") {
            mapped.push(serde_json::json!({
                "name": u.name,
                "load_state": u.load_state,
                "state": u.active_state,
                "sub_state": u.sub_state,
                "description": u.description
            }));
        }
    }

    Ok(serde_json::json!(mapped))
}

pub async fn get_unit_status(name: &str, connection: &Connection) -> anyhow::Result<Value> {
    let manager = SystemdManagerProxy::new(connection)
        .await
        .map_err(|e| anyhow::anyhow!("manager proxy err: {}", e))?;

    let unit_path = manager
        .get_unit(name)
        .await
        .map_err(|e| anyhow::anyhow!("unit not found: {}", e))?;

    let unit = SystemdUnitProxy::builder(connection)
        .path(unit_path.clone())
        .map_err(|e| anyhow::anyhow!(e.to_string()))?
        .build()
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let mut props = serde_json::Map::new();
    props.insert("Id".to_string(), serde_json::json!(name));

    if let Ok(desc) = unit.description().await {
        props.insert("Description".to_string(), serde_json::json!(desc));
    }
    if let Ok(active) = unit.active_state().await {
        props.insert("ActiveState".to_string(), serde_json::json!(active));
    }
    if let Ok(sub) = unit.sub_state().await {
        props.insert("SubState".to_string(), serde_json::json!(sub));
    }
    if let Ok(load) = unit.load_state().await {
        props.insert("LoadState".to_string(), serde_json::json!(load));
    }

    // Read service-specific properties if it is a .service unit
    if name.ends_with(".service") {
        let svc = SystemdServiceProxy::builder(connection)
            .path(unit_path)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?
            .build()
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        if let Ok(pid) = svc.main_pid().await {
            props.insert("MainPID".to_string(), serde_json::json!(pid));
        }
        if let Ok(mem) = svc.memory_current().await {
            props.insert("MemoryCurrent".to_string(), serde_json::json!(mem));
        }
        if let Ok(cpu) = svc.cpu_usage_nsec().await {
            props.insert("CPUUsageNSec".to_string(), serde_json::json!(cpu));
        }
        if let Ok(tasks) = svc.tasks_current().await {
            props.insert("TasksCurrent".to_string(), serde_json::json!(tasks));
        }
    }

    Ok(serde_json::Value::Object(props))
}

pub async fn journal_tail(unit: Option<&str>, lines: usize) -> anyhow::Result<Value> {
    let unit_owned = unit.map(|u| u.to_string());
    if let Some(ref u) = unit_owned {
        validate_unit_name(u)?;
    }
    let unit_display = unit_owned.clone();

    let stdout = tokio::task::spawn_blocking(move || {
        let lines_str = lines.to_string();
        let mut args = vec!["-o".to_string(), "json".to_string(), "-n".to_string(), lines_str, "--no-pager".to_string()];

        if let Some(ref u) = unit_owned {
            args.push("-u".to_string());
            args.push(u.clone());
        }

        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        execute_command_stdout("journalctl", &args_ref)
    }).await??;

    let mut entries = Vec::new();
    for line in stdout.lines() {
        if let Ok(json) = serde_json::from_str::<Value>(line) {
            entries.push(json);
        }
    }

    Ok(serde_json::json!({
        "unit": unit_display,
        "entries": entries
    }))
}

pub async fn journal_search(keyword: &str, since: Option<&str>, priority: Option<&str>) -> anyhow::Result<Value> {
    let keyword_owned = keyword.to_string();
    validate_grep_keyword(&keyword_owned)?;
    let since_owned = since.map(|s| s.to_string());
    let priority_owned = priority.map(|p| p.to_string());
    let keyword_display = keyword_owned.clone();

    let stdout = tokio::task::spawn_blocking(move || {
        let mut args = vec!["-o".to_string(), "json".to_string(), "--no-pager".to_string(), "--grep".to_string(), keyword_owned];

        if let Some(ref s) = since_owned {
            args.push(format!("--since={}", s));
        }

        if let Some(ref p) = priority_owned {
            args.push("-p".to_string());
            args.push(p.clone());
        }

        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        execute_command_stdout("journalctl", &args_ref)
    }).await??;

    let mut entries = Vec::new();
    for line in stdout.lines() {
        if let Ok(json) = serde_json::from_str::<Value>(line) {
            entries.push(json);
        }
    }

    Ok(serde_json::json!({
        "keyword": keyword_display,
        "entries": entries
    }))
}

pub async fn get_unit_dependencies(name: &str, connection: &Connection) -> anyhow::Result<Value> {
    validate_unit_name(name)?;
    let manager = SystemdManagerProxy::new(connection)
        .await
        .map_err(|e| anyhow::anyhow!("manager proxy: {}", e))?;
    let unit_path = manager.get_unit(name).await
        .map_err(|e| anyhow::anyhow!("unit not found: {}", e))?;
    let unit = SystemdUnitProxy::builder(connection)
        .path(unit_path)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?
        .build().await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    Ok(serde_json::json!({
        "name": name,
        "requires": unit.requires().await.unwrap_or_default(),
        "wants":    unit.wants().await.unwrap_or_default(),
        "after":    unit.after().await.unwrap_or_default(),
        "before":   unit.before().await.unwrap_or_default(),
    }))
}

pub async fn unit_start(name: &str, connection: &Connection) -> anyhow::Result<Value> {
    validate_unit_name(name)?;
    let manager = SystemdManagerProxy::new(connection).await
        .map_err(|e| anyhow::anyhow!("manager proxy: {}", e))?;
    manager.start_unit(name, "replace").await
        .map_err(|e| anyhow::anyhow!("StartUnit failed: {}", e))?;
    Ok(serde_json::json!({"name": name, "action": "start", "status": "ok"}))
}

pub async fn unit_stop(name: &str, connection: &Connection) -> anyhow::Result<Value> {
    validate_unit_name(name)?;
    let manager = SystemdManagerProxy::new(connection).await
        .map_err(|e| anyhow::anyhow!("manager proxy: {}", e))?;
    manager.stop_unit(name, "replace").await
        .map_err(|e| anyhow::anyhow!("StopUnit failed: {}", e))?;
    Ok(serde_json::json!({"name": name, "action": "stop", "status": "ok"}))
}

pub async fn unit_restart(name: &str, connection: &Connection) -> anyhow::Result<Value> {
    validate_unit_name(name)?;
    let manager = SystemdManagerProxy::new(connection).await
        .map_err(|e| anyhow::anyhow!("manager proxy: {}", e))?;
    manager.restart_unit(name, "replace").await
        .map_err(|e| anyhow::anyhow!("RestartUnit failed: {}", e))?;
    Ok(serde_json::json!({"name": name, "action": "restart", "status": "ok"}))
}

/// Enable a unit file permanently using D-Bus EnableUnitFiles — no subprocess.
pub async fn unit_enable(name: &str, connection: &Connection) -> anyhow::Result<Value> {
    validate_unit_name(name)?;
    let manager = SystemdManagerProxy::new(connection).await
        .map_err(|e| anyhow::anyhow!("manager proxy: {}", e))?;
    manager.enable_unit_files(&[name], false, false).await
        .map_err(|e| anyhow::anyhow!("EnableUnitFiles({}) failed: {}", name, e))?;
    // Reload daemon so it picks up the new symlinks
    let _ = manager.reload().await;
    Ok(serde_json::json!({"name": name, "action": "enable", "status": "ok"}))
}

/// Disable a unit file permanently using D-Bus DisableUnitFiles — no subprocess.
pub async fn unit_disable(name: &str, connection: &Connection) -> anyhow::Result<Value> {
    validate_unit_name(name)?;
    let manager = SystemdManagerProxy::new(connection).await
        .map_err(|e| anyhow::anyhow!("manager proxy: {}", e))?;
    manager.disable_unit_files(&[name], false).await
        .map_err(|e| anyhow::anyhow!("DisableUnitFiles({}) failed: {}", name, e))?;
    let _ = manager.reload().await;
    Ok(serde_json::json!({"name": name, "action": "disable", "status": "ok"}))
}

pub async fn journal_units() -> anyhow::Result<Value> {
    let stdout = tokio::task::spawn_blocking(|| {
        execute_command_stdout("journalctl", &["-F", "_SYSTEMD_UNIT", "--no-pager"])
    }).await??;
    let mut units: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    units.sort_unstable();
    units.dedup();
    Ok(serde_json::json!(units))
}

pub async fn journal_stream(unit: Option<&str>, timeout_secs: u64, max_lines: usize) -> anyhow::Result<Value> {
    let unit_owned = unit.map(|u| u.to_string());
    if let Some(ref u) = unit_owned {
        validate_unit_name(u)?;
    }
    let timeout = std::cmp::min(timeout_secs, 30);
    let unit_display = unit_owned.clone();

    let entries = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<Value>> {
        let mut args = vec!["-f", "--lines=0", "-o", "json", "--no-pager"];
        let unit_arg;
        if let Some(ref u) = unit_owned {
            unit_arg = format!("-u={}", u);
            args.push(&unit_arg);
        }
        let mut child = std::process::Command::new("journalctl")
            .args(&args)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("journalctl spawn failed: {}", e))?;

        let stdout = child.stdout.take().unwrap();
        let reader = std::io::BufReader::new(stdout);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout);
        let mut entries = Vec::new();

        use std::io::BufRead;
        for line in reader.lines() {
            if std::time::Instant::now() >= deadline || entries.len() >= max_lines {
                break;
            }
            if let Ok(l) = line {
                if let Ok(json) = serde_json::from_str::<Value>(&l) {
                    entries.push(json);
                }
            }
        }
        let _ = child.kill();
        Ok(entries)
    }).await??;

    Ok(serde_json::json!({"unit": unit_display, "entries": entries}))
}

pub async fn journal_rotate() -> anyhow::Result<Value> {
    let output = tokio::task::spawn_blocking(|| {
        Command::new("journalctl").args(["--rotate"]).output()
    }).await?
    .map_err(|e| anyhow::anyhow!("journalctl --rotate failed: {}", e))?;
    if output.status.success() {
        Ok(serde_json::json!({"status": "rotated"}))
    } else {
        anyhow::bail!("journalctl --rotate failed: {}", String::from_utf8_lossy(&output.stderr))
    }
}

pub async fn journal_vacuum(size_mb: Option<u64>, days: Option<u64>) -> anyhow::Result<Value> {
    if size_mb.is_none() && days.is_none() {
        anyhow::bail!("Provide either size_mb or days");
    }
    let arg = if let Some(mb) = size_mb {
        format!("--vacuum-size={}M", mb)
    } else {
        format!("--vacuum-time={}d", days.unwrap())
    };
    let output = tokio::task::spawn_blocking(move || {
        Command::new("journalctl").arg(&arg).output()
    }).await?
    .map_err(|e| anyhow::anyhow!("journalctl vacuum failed: {}", e))?;
    if output.status.success() {
        Ok(serde_json::json!({"status": "vacuumed"}))
    } else {
        anyhow::bail!("journalctl vacuum failed: {}", String::from_utf8_lossy(&output.stderr))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    // ── Validation unit tests (pure, no I/O) ────────────────────────────────

    #[test]
    fn test_validate_unit_name_valid() {
        assert!(validate_unit_name("systemd-journald.service").is_ok());
        assert!(validate_unit_name("nginx.service").is_ok());
        assert!(validate_unit_name("user@1000.service").is_ok());
        assert!(validate_unit_name("multi-user.target").is_ok());
    }

    #[test]
    fn test_validate_unit_name_empty() {
        assert!(validate_unit_name("").is_err());
    }

    #[test]
    fn test_validate_unit_name_injection() {
        assert!(validate_unit_name("nginx; rm -rf /").is_err());
        assert!(validate_unit_name("$(evil)").is_err());
        assert!(validate_unit_name("unit`id`").is_err());
        assert!(validate_unit_name("unit name with spaces").is_err());
    }

    #[test]
    fn test_validate_unit_name_too_long() {
        let long = "a".repeat(257);
        assert!(validate_unit_name(&long).is_err());
    }

    #[test]
    fn test_validate_grep_keyword_empty() {
        assert!(validate_grep_keyword("").is_err());
    }

    #[test]
    fn test_validate_grep_keyword_too_long() {
        let long = "a".repeat(MAX_GREP_LENGTH + 1);
        assert!(validate_grep_keyword(&long).is_err());
    }

    #[test]
    fn test_validate_grep_keyword_valid() {
        assert!(validate_grep_keyword("ERROR").is_ok());
        assert!(validate_grep_keyword("Failed to start").is_ok());
    }

    #[test]
    fn test_journal_vacuum_requires_params() {
        // Sync validation — we can test without spinning up tokio
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(journal_vacuum(None, None));
        assert!(result.is_err(), "Must provide size_mb or days");
    }

    // ── D-Bus integration tests ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_list_units_executes() {
        let connection = Connection::system().await.expect("D-Bus connection");
        let res = list_units(&connection).await;
        assert!(res.is_ok(), "list_units should execute");
        let array = res.unwrap();
        assert!(array.is_array());
    }

    #[tokio::test]
    async fn test_get_unit_status_journald() {
        let conn = Connection::system().await.expect("D-Bus connection");
        let result = get_unit_status("systemd-journald.service", &conn).await;
        if let Ok(val) = result {
            assert!(val.get("ActiveState").is_some(), "Status should contain ActiveState");
            assert_eq!(val["Id"], "systemd-journald.service");
        }
    }

    #[tokio::test]
    async fn test_unit_start_invalid_name_rejected() {
        let conn = Connection::system().await.expect("D-Bus connection");
        let result = unit_start("nginx; rm -rf /", &conn).await;
        assert!(result.is_err(), "Injection in unit name must be rejected before D-Bus call");
    }

    #[tokio::test]
    async fn test_unit_stop_invalid_name_rejected() {
        let conn = Connection::system().await.expect("D-Bus connection");
        let result = unit_stop("$(evil).service", &conn).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unit_restart_invalid_name_rejected() {
        let conn = Connection::system().await.expect("D-Bus connection");
        let result = unit_restart("bad name", &conn).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unit_enable_invalid_name_rejected() {
        let conn = Connection::system().await.expect("D-Bus connection");
        let result = unit_enable("bad;name", &conn).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unit_disable_invalid_name_rejected() {
        let conn = Connection::system().await.expect("D-Bus connection");
        let result = unit_disable("bad name", &conn).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_journal_tail_invalid_unit_rejected() {
        let result = journal_tail(Some("bad;unit"), 10).await;
        assert!(result.is_err(), "Injection in unit name must be rejected");
    }

    #[tokio::test]
    async fn test_journal_tail_global() {
        let result = journal_tail(None, 3).await;
        if let Ok(val) = result {
            let entries = val["entries"].as_array().expect("Should have entries array");
            assert!(entries.len() <= 3, "Should respect line limit");
        }
    }

    #[tokio::test]
    async fn test_journal_search_empty_keyword() {
        let result = journal_search("", None, None).await;
        assert!(result.is_err(), "Empty keyword must be rejected");
    }

    #[tokio::test]
    async fn test_journal_search_valid_keyword() {
        let result = journal_search("kernel", None, None).await;
        if let Ok(val) = result {
            assert!(val.get("keyword").is_some());
            assert!(val.get("entries").is_some());
        }
    }

    #[tokio::test]
    async fn test_journal_stream_timeout_capped() {
        // Pass a large timeout; the function caps it at 30 seconds.
        // With max_lines=0 it should return immediately with an empty array.
        let result = journal_stream(None, 9999, 0).await;
        if let Ok(val) = result {
            let entries = val["entries"].as_array().expect("Should have entries array");
            assert!(entries.is_empty(), "max_lines=0 should yield zero entries");
        }
    }

    #[tokio::test]
    async fn test_journal_stream_invalid_unit_rejected() {
        let result = journal_stream(Some("bad;unit"), 1, 5).await;
        assert!(result.is_err(), "Injection in unit name must be rejected");
    }

    #[tokio::test]
    async fn test_get_unit_dependencies_invalid_name() {
        let conn = Connection::system().await.expect("D-Bus connection");
        let result = get_unit_dependencies("bad;name", &conn).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_unit_dependencies_journald() {
        let conn = Connection::system().await.expect("D-Bus connection");
        let result = get_unit_dependencies("systemd-journald.service", &conn).await;
        if let Ok(val) = result {
            assert!(val.get("requires").is_some());
            assert!(val.get("wants").is_some());
            assert!(val.get("after").is_some());
            assert!(val.get("before").is_some());
        }
    }

    #[tokio::test]
    async fn test_journal_units_returns_array() {
        let result = journal_units().await;
        if let Ok(val) = result {
            assert!(val.is_array());
        }
    }
}
