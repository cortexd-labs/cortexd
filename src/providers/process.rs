use procfs::process::all_processes;
use nix::unistd::User;
use nix::unistd::Uid;
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
}
