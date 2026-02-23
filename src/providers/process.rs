use procfs::process::all_processes;
use nix::unistd::User;
use nix::unistd::Uid;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::collections::HashMap;
use serde_json::Value;

pub async fn process_list() -> anyhow::Result<Value> {
    let page_size = procfs::page_size();

    let procs: Vec<_> = all_processes()?
        .filter_map(|p| p.ok())
        .filter_map(|proc| {
            let stat = proc.stat().ok()?;
            let status = proc.status().ok()?;

            let username = User::from_uid(Uid::from_raw(status.ruid))
                .ok()
                .flatten()
                .map(|u| u.name)
                .unwrap_or_else(|| status.ruid.to_string());

            Some(serde_json::json!({
                "pid": stat.pid,
                "name": stat.comm,
                "state": format!("{}", stat.state),
                "ppid": stat.ppid,
                "uid": status.ruid,
                "user": username,
                "rss_bytes": stat.rss * page_size,
                "vsize_bytes": stat.vsize,
                "threads": stat.num_threads,
            }))
        })
        .collect();
        
    Ok(serde_json::json!(procs))
}

pub async fn process_top(sort_by: &str, limit: usize) -> anyhow::Result<Value> {
    let ticks_per_sec = procfs::ticks_per_second();
    let page_size = procfs::page_size();

    let snap1: HashMap<i32, u64> = all_processes()?
        .filter_map(|p| p.ok())
        .filter_map(|p| {
            let s = p.stat().ok()?;
            Some((s.pid, s.utime + s.stime))
        })
        .collect();

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let mut results: Vec<_> = all_processes()?
        .filter_map(|p| p.ok())
        .filter_map(|p| {
            let stat = p.stat().ok()?;
            let status = p.status().ok()?;
            let total2 = stat.utime + stat.stime;
            let total1 = snap1.get(&stat.pid)?;
            let delta = total2 - total1;
            let cpu_pct = (delta as f64 / ticks_per_sec as f64) * 100.0 / 0.5;

            let username = User::from_uid(Uid::from_raw(status.ruid))
                .ok()
                .flatten()
                .map(|u| u.name)
                .unwrap_or_else(|| status.ruid.to_string());

            Some(serde_json::json!({
                "pid": stat.pid,
                "name": stat.comm,
                "user": username,
                "state": format!("{}", stat.state),
                "cpu_percent": (cpu_pct * 10.0).round() / 10.0,
                "mem_mb": (stat.rss as f64 * page_size as f64) / 1024.0 / 1024.0,
            }))
        })
        .collect();

    if sort_by == "memory" {
        results.sort_by(|a, b| {
            b["mem_mb"].as_f64()
                .partial_cmp(&a["mem_mb"].as_f64())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    } else {
        results.sort_by(|a, b| {
            b["cpu_percent"].as_f64()
                .partial_cmp(&a["cpu_percent"].as_f64())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }
    
    results.truncate(limit);
    Ok(serde_json::json!(results))
}

/// Build a process tree: returns {pid, name, children: [...]} rooted at PID 1.
pub async fn process_tree() -> anyhow::Result<Value> {
    let page_size = procfs::page_size();
    let mut nodes: HashMap<i32, serde_json::Value> = HashMap::new();
    let mut children: HashMap<i32, Vec<i32>> = HashMap::new();

    for p in all_processes()?.filter_map(|p| p.ok()) {
        if let (Ok(stat), Ok(status)) = (p.stat(), p.status()) {
            let username = User::from_uid(Uid::from_raw(status.ruid))
                .ok()
                .flatten()
                .map(|u| u.name)
                .unwrap_or_else(|| status.ruid.to_string());
            nodes.insert(stat.pid, serde_json::json!({
                "pid": stat.pid,
                "name": stat.comm,
                "user": username,
                "state": format!("{}", stat.state),
                "rss_bytes": stat.rss * page_size,
                "children": [],
            }));
            children.entry(stat.ppid).or_default().push(stat.pid);
        }
    }

    // Attach children to parents
    fn build(pid: i32, nodes: &mut HashMap<i32, serde_json::Value>, children: &HashMap<i32, Vec<i32>>) -> serde_json::Value {
        let child_pids = children.get(&pid).cloned().unwrap_or_default();
        let child_nodes: Vec<serde_json::Value> = child_pids.iter()
            .map(|&c| build(c, nodes, children))
            .collect();
        let mut node = nodes.remove(&pid).unwrap_or_else(|| serde_json::json!({"pid": pid}));
        node["children"] = serde_json::json!(child_nodes);
        node
    }

    let root = build(1, &mut nodes, &children);
    Ok(root)
}

/// Detailed inspection of a single process by PID.
pub async fn process_inspect(pid: i32) -> anyhow::Result<Value> {
    let proc = procfs::process::Process::new(pid)
        .map_err(|e| anyhow::anyhow!("PID {} not found: {}", pid, e))?;

    let stat = proc.stat()?;
    let status = proc.status()?;

    let cgroup_raw = tokio::fs::read_to_string(format!("/proc/{}/cgroup", pid))
        .await
        .unwrap_or_default();
    let cgroups: Vec<&str> = cgroup_raw.lines().collect();

    let thread_count = tokio::fs::read_dir(format!("/proc/{}/task", pid))
        .await
        .ok()
        .map(|_| stat.num_threads);

    // Environ: read and truncate for safety (max 50 vars)
    let environ: Vec<String> = proc.environ()
        .unwrap_or_default()
        .into_iter()
        .take(50)
        .map(|(k, v)| format!("{}={}", k.to_string_lossy(), v.to_string_lossy()))
        .collect();

    let username = User::from_uid(Uid::from_raw(status.ruid))
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| status.ruid.to_string());

    Ok(serde_json::json!({
        "pid": stat.pid,
        "name": stat.comm,
        "state": format!("{}", stat.state),
        "ppid": stat.ppid,
        "user": username,
        "uid": status.ruid,
        "gid": status.rgid,
        "threads": thread_count,
        "vsize_bytes": stat.vsize,
        "rss_bytes": stat.rss * procfs::page_size(),
        "cgroups": cgroups,
        "environ": environ,
    }))
}

/// List open file descriptors for a process.
pub async fn process_open_files(pid: i32) -> anyhow::Result<Value> {
    let fd_dir = format!("/proc/{}/fd", pid);
    let mut entries = tokio::fs::read_dir(&fd_dir).await
        .map_err(|e| anyhow::anyhow!("Cannot read fds for PID {}: {}", pid, e))?;

    let mut fds = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let fd_num = entry.file_name().to_string_lossy().to_string();
        let target = tokio::fs::read_link(entry.path()).await
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "<unreadable>".to_string());
        fds.push(serde_json::json!({"fd": fd_num, "path": target}));
    }
    Ok(serde_json::json!(fds))
}

/// Send SIGTERM or SIGKILL to a process.
pub async fn process_kill(pid: i32, force: bool) -> anyhow::Result<Value> {
    let signal = if force { Signal::SIGKILL } else { Signal::SIGTERM };
    kill(Pid::from_raw(pid), signal)
        .map_err(|e| anyhow::anyhow!("kill({}, {:?}) failed: {}", pid, signal, e))?;
    Ok(serde_json::json!({"pid": pid, "signal": format!("{:?}", signal), "status": "sent"}))
}

/// Send an arbitrary signal number to a process.
pub async fn process_signal(pid: i32, signum: i32) -> anyhow::Result<Value> {
    let signal = Signal::try_from(signum)
        .map_err(|_| anyhow::anyhow!("Invalid signal number: {}", signum))?;
    kill(Pid::from_raw(pid), signal)
        .map_err(|e| anyhow::anyhow!("kill({}, {:?}) failed: {}", pid, signal, e))?;
    Ok(serde_json::json!({"pid": pid, "signal": format!("{:?}", signal), "status": "sent"}))
}

/// Change process scheduling priority (nice value).
pub async fn process_nice(pid: i32, priority: i32) -> anyhow::Result<Value> {
    if !(-20..=19).contains(&priority) {
        anyhow::bail!("Priority must be between -20 and 19");
    }
    let output = tokio::process::Command::new("renice")
        .args(["-n", &priority.to_string(), "-p", &pid.to_string()])
        .output()
        .await?;
    if output.status.success() {
        Ok(serde_json::json!({"pid": pid, "priority": priority, "status": "ok"}))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("renice failed: {}", stderr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_process_list_format() {
        let list = process_list().await.unwrap();
        let arr = list.as_array().expect("Process list should return an array");
        assert!(!arr.is_empty(), "System should have at least one process");
        
        // Check the init process usually pid 1 or something valid
        let first = &arr[0];
        assert!(first.get("pid").is_some(), "Process needs a PID");
        assert!(first.get("name").is_some(), "Process needs a name");
        assert!(first.get("user").is_some(), "Process needs a user");
        assert!(first.get("rss_bytes").is_some(), "Process needs RSS bytes");
    }

    #[tokio::test]
    async fn test_process_top_memory_sort() {
        let top = process_top("memory", 5).await.unwrap();
        let arr = top.as_array().expect("Top should return an array");
        assert!(arr.len() <= 5, "Should respect the limit");
        
        if arr.len() >= 2 {
            let p1 = arr[0]["mem_mb"].as_f64().unwrap();
            let p2 = arr[1]["mem_mb"].as_f64().unwrap();
            assert!(p1 >= p2, "Memory sort should be descending");
        }
    }

    #[tokio::test]
    async fn test_process_top_cpu_sort() {
        let top = process_top("cpu", 2).await.unwrap();
        let arr = top.as_array().expect("Top should return an array");
        assert!(arr.len() <= 2, "Should respect the limit");

        if arr.len() >= 2 {
            let p1 = arr[0]["cpu_percent"].as_f64().unwrap();
            let p2 = arr[1]["cpu_percent"].as_f64().unwrap();
            assert!(p1 >= p2, "CPU sort should be descending");
        }
    }

    #[tokio::test]
    async fn test_process_tree() {
        let result = process_tree().await.unwrap();
        assert!(result.get("pid").is_some());
        assert!(result.get("children").is_some());
    }

    #[tokio::test]
    async fn test_process_inspect_self() {
        let pid = std::process::id() as i32;
        let result = process_inspect(pid).await.unwrap();
        assert!(result.get("name").is_some());
        assert!(result.get("state").is_some());
    }

    #[tokio::test]
    async fn test_process_open_files_self() {
        let pid = std::process::id() as i32;
        let result = process_open_files(pid).await.unwrap();
        assert!(result.is_array());
    }

    #[tokio::test]
    async fn test_process_signal_invalid() {
        let result = process_signal(1, 999).await;
        assert!(result.is_err(), "Invalid signal number should return error");
    }

    #[tokio::test]
    async fn test_process_nice_invalid_priority() {
        let result = process_nice(1, 100).await;
        assert!(result.is_err(), "Priority 100 is out of range");
    }
}
