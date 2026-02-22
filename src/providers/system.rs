use procfs::{Meminfo, CpuInfo, LoadAverage, Uptime, KernelStats, Current, CurrentSI};
use std::time::Duration;
use procfs::process::Process;
use nix::sys::statvfs::statvfs;
use serde_json::Value;

pub async fn system_info() -> anyhow::Result<Value> {
    let meminfo = Meminfo::current()?;
    let cpuinfo = CpuInfo::current()?;
    let loadavg = LoadAverage::current()?;
    let uptime = Uptime::current()?;
    let uname = nix::sys::utsname::uname()?;
    let hostname = uname.nodename().to_string_lossy().into_owned();
    let osrelease = uname.release().to_string_lossy().into_owned();

    Ok(serde_json::json!({
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
    }))
}

pub async fn system_cpu() -> anyhow::Result<Value> {
    let cpuinfo = CpuInfo::current()?;
    let stat1 = KernelStats::current()?;
    tokio::time::sleep(Duration::from_millis(250)).await;
    let stat2 = KernelStats::current()?;

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

    let cpu_pct = if total_delta == 0 { 0.0 } else {
        ((total_delta - idle_delta) as f64 / total_delta as f64) * 100.0
    };

    Ok(serde_json::json!({
        "cores": cpuinfo.num_cores(),
        "total_usage_percent": (cpu_pct * 10.0).round() / 10.0,
    }))
}

pub async fn system_memory() -> anyhow::Result<Value> {
    let meminfo = Meminfo::current()?;
    Ok(serde_json::json!({
        "total_mb": meminfo.mem_total / 1024,
        "free_mb": meminfo.mem_free / 1024,
        "available_mb": meminfo.mem_available.unwrap_or(0) / 1024,
    }))
}

pub async fn system_disk() -> anyhow::Result<Value> {
    let process = Process::myself()?;
    let mounts = process.mountinfo()?;

    let skip_fs = ["tmpfs", "proc", "sysfs", "devtmpfs", "devpts",
                   "cgroup", "cgroup2", "pstore", "securityfs",
                   "fusectl", "debugfs", "hugetlbfs", "mqueue",
                   "configfs", "binfmt_misc", "autofs", "tracefs",
                   "overlay", "nsfs", "efivarfs"];

    let mut results = Vec::new();
    for m in mounts.iter().filter(|m| !skip_fs.contains(&m.fs_type.as_str())) {
        if let Ok(stat) = statvfs(m.mount_point.as_path()) {
            let block_size = stat.fragment_size();
            let total = stat.blocks() * block_size;
            let free = stat.blocks_available() * block_size;
            if total > 0 {
                results.push(serde_json::json!({
                    "mount": m.mount_point.display().to_string(),
                    "device": m.mount_source.as_deref().unwrap_or("unknown"),
                    "fs_type": m.fs_type,
                    "total_bytes": total,
                    "free_bytes": free,
                    "used_bytes": total - free,
                    "used_percent": ((total - free) as f64 / total as f64 * 100.0).round(),
                }));
            }
        }
    }
    Ok(serde_json::json!(results))
}

pub async fn system_uptime() -> anyhow::Result<Value> {
    let uptime = Uptime::current()?;
    Ok(serde_json::json!({
        "uptime_seconds": uptime.uptime,
        "idle_seconds": uptime.idle,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_system_info() {
        let result = system_info().await.unwrap();
        assert!(result.get("hostname").is_some(), "Should contain hostname");
        assert!(result.get("kernel").is_some(), "Should contain kernel version");
        assert!(result.get("uptime_seconds").is_some(), "Should contain uptime");
    }

    #[tokio::test]
    async fn test_system_cpu() {
        let result = system_cpu().await.unwrap();
        assert!(result.get("total_usage_percent").is_some(), "Should contain CPU usage");
    }

    #[tokio::test]
    async fn test_system_memory() {
        let result = system_memory().await.unwrap();
        assert!(result.get("total_mb").is_some(), "Should contain total memory");
        assert!(result.get("free_mb").is_some(), "Should contain free memory");
        
        let total = result["total_mb"].as_u64().unwrap();
        assert!(total > 0, "Total memory should be > 0");
    }

    #[tokio::test]
    async fn test_system_disk() {
        let result = system_disk().await.unwrap();
        let arr = result.as_array().expect("system_disk should return an array");
        assert!(!arr.is_empty(), "Should find at least one mount");
        
        let first = &arr[0];
        assert!(first.get("mount").is_some(), "Mount object should contain mount path");
        assert!(first.get("total_bytes").is_some(), "Mount object should contain total bytes");
    }

    #[tokio::test]
    async fn test_system_uptime() {
        let result = system_uptime().await.unwrap();
        assert!(result.get("uptime_seconds").is_some(), "Should contain uptime in seconds");
    }
}
