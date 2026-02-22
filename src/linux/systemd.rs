use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::process::Command;
use zbus::zvariant::{OwnedObjectPath, Type};
use zbus::{proxy, Connection};

/// Maximum length for grep patterns to prevent ReDoS in journalctl.
const MAX_GREP_LENGTH: usize = 256;

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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_list_units_executes() {
        let connection = Connection::system().await.expect("D-Bus connection");
        let res = list_units(&connection).await;
        assert!(res.is_ok(), "list_units should execute");

        let array = res.unwrap();
        assert!(array.is_array());
    }
}
