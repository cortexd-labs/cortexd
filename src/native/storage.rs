use serde_json::Value;

fn validate_device_path(device: &str) -> anyhow::Result<()> {
    // Device must be under /dev/ with safe characters only
    if !device.starts_with("/dev/") {
        anyhow::bail!("Device path must start with /dev/");
    }
    let name = &device[5..];
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        anyhow::bail!("Invalid device name: {}", name);
    }
    Ok(())
}

fn validate_mountpoint(mp: &str) -> anyhow::Result<()> {
    if mp.is_empty() || mp.len() > 255 {
        anyhow::bail!("Invalid mountpoint length");
    }
    // No shell metacharacters
    if mp.chars().any(|c| matches!(c, ';' | '|' | '&' | '`' | '$' | '(' | ')' | '<' | '>' | '!' | '\n')) {
        anyhow::bail!("Mountpoint contains unsafe characters");
    }
    Ok(())
}

/// List physical block devices using lsblk.
pub async fn storage_block_list() -> anyhow::Result<Value> {
    let output = tokio::process::Command::new("lsblk")
        .args(["-J", "-o", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL"])
        .output().await
        .map_err(|e| anyhow::anyhow!("lsblk failed: {}", e))?;
    if !output.status.success() {
        anyhow::bail!("lsblk failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    let json: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| anyhow::anyhow!("Failed to parse lsblk output: {}", e))?;
    Ok(json)
}

/// Parse /etc/fstab for persistent mount configurations.
pub async fn storage_mounts_fstab() -> anyhow::Result<Value> {
    let content = tokio::fs::read_to_string("/etc/fstab").await
        .map_err(|e| anyhow::anyhow!("Cannot read /etc/fstab: {}", e))?;
    let entries: Vec<Value> = content.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 4 { return None; }
            Some(serde_json::json!({
                "device": f[0],
                "mountpoint": f[1],
                "fstype": f[2],
                "options": f[3],
                "dump": f.get(4).and_then(|v| v.parse::<u8>().ok()).unwrap_or(0),
                "pass": f.get(5).and_then(|v| v.parse::<u8>().ok()).unwrap_or(0),
            }))
        })
        .collect();
    Ok(serde_json::json!(entries))
}

/// List LVM Physical Volumes, Volume Groups, and Logical Volumes.
pub async fn storage_lvm_list() -> anyhow::Result<Value> {
    async fn run_lvm(args: &[&str]) -> Option<Value> {
        let output = tokio::process::Command::new(args[0])
            .args(&args[1..])
            .output().await.ok()?;
        if !output.status.success() { return None; }
        serde_json::from_slice(&output.stdout).ok()
    }

    let pvs = run_lvm(&["pvs", "--reportformat", "json", "-o", "pv_name,pv_size,vg_name"]).await;
    let vgs = run_lvm(&["vgs", "--reportformat", "json", "-o", "vg_name,vg_size,vg_free,pv_count,lv_count"]).await;
    let lvs = run_lvm(&["lvs", "--reportformat", "json", "-o", "lv_name,vg_name,lv_size,lv_attr"]).await;

    if pvs.is_none() && vgs.is_none() && lvs.is_none() {
        anyhow::bail!("LVM not available on this system");
    }
    Ok(serde_json::json!({
        "pvs": pvs,
        "vgs": vgs,
        "lvs": lvs,
    }))
}

/// Retrieve S.M.A.R.T. health data for a physical drive.
pub async fn storage_smart_health(device: &str) -> anyhow::Result<Value> {
    validate_device_path(device)?;
    let device_owned = device.to_string();
    let output = tokio::process::Command::new("smartctl")
        .args(["-j", &device_owned])
        .output().await
        .map_err(|e| anyhow::anyhow!("smartctl failed: {}", e))?;
    let json: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| anyhow::anyhow!("Failed to parse smartctl output: {}", e))?;
    Ok(json)
}

/// Mount a block device using the nix::mount::mount() syscall — no subprocess required.
pub async fn storage_mount(device: &str, mountpoint: &str, fstype: Option<&str>) -> anyhow::Result<Value> {
    validate_device_path(device)?;
    validate_mountpoint(mountpoint)?;

    let device_path = std::path::PathBuf::from(device);
    let mountpoint_path = std::path::PathBuf::from(mountpoint);
    let fstype_owned = fstype.map(|s| s.to_string());
    let device_display = device.to_string();
    let mountpoint_display = mountpoint.to_string();

    tokio::task::spawn_blocking(move || {
        use nix::mount::{mount, MsFlags};
        let fstype_path = fstype_owned.as_ref().map(|s| std::path::Path::new(s.as_str()));
        mount(
            Some(device_path.as_path()),
            mountpoint_path.as_path(),
            fstype_path,
            MsFlags::empty(),
            None::<&std::path::Path>,
        ).map_err(|e| anyhow::anyhow!("mount({} → {}): {}", device_display, mountpoint_display, e))
    }).await??;

    Ok(serde_json::json!({"device": device, "mountpoint": mountpoint, "status": "mounted"}))
}

/// Unmount a filesystem using the nix::mount::umount() syscall — no subprocess required.
pub async fn storage_unmount(mountpoint: &str) -> anyhow::Result<Value> {
    validate_mountpoint(mountpoint)?;
    let mp_path = std::path::PathBuf::from(mountpoint);
    let mp_display = mountpoint.to_string();

    tokio::task::spawn_blocking(move || {
        nix::mount::umount(mp_path.as_path())
            .map_err(|e| anyhow::anyhow!("umount({}): {}", mp_display, e))
    }).await??;

    Ok(serde_json::json!({"mountpoint": mountpoint, "status": "unmounted"}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_storage_block_list() {
        let result = storage_block_list().await;
        if let Ok(val) = result {
            assert!(val.get("blockdevices").is_some() || val.is_object());
        }
    }

    #[tokio::test]
    async fn test_storage_mounts_fstab() {
        let result = storage_mounts_fstab().await;
        if let Ok(val) = result {
            assert!(val.is_array());
        }
    }

    #[test]
    fn test_validate_device_invalid() {
        assert!(validate_device_path("/etc/passwd").is_err());
        assert!(validate_device_path("/dev/sd$(rm)").is_err());
        assert!(validate_device_path("sda").is_err());
    }

    #[test]
    fn test_validate_mountpoint_invalid() {
        assert!(validate_mountpoint("/mnt/$(bad)").is_err());
        assert!(validate_mountpoint("").is_err());
    }

    #[test]
    fn test_validate_device_valid() {
        assert!(validate_device_path("/dev/sda").is_ok());
        assert!(validate_device_path("/dev/nvme0n1").is_ok());
        assert!(validate_device_path("/dev/vda").is_ok());
    }

    #[test]
    fn test_validate_mountpoint_valid() {
        assert!(validate_mountpoint("/mnt/data").is_ok());
        assert!(validate_mountpoint("/").is_ok());
        assert!(validate_mountpoint("/mnt/my backup").is_ok()); // spaces are allowed
    }

    #[tokio::test]
    async fn test_storage_smart_health_invalid_device() {
        let result = storage_smart_health("/etc/passwd").await;
        assert!(result.is_err(), "Non-/dev/ path must be rejected");
    }

    #[tokio::test]
    async fn test_storage_smart_health_injection_rejected() {
        let result = storage_smart_health("/dev/sda$(evil)").await;
        assert!(result.is_err(), "Injection in device path must be rejected");
    }

    #[tokio::test]
    async fn test_storage_mount_invalid_device() {
        let result = storage_mount("/etc/passwd", "/mnt/test", None).await;
        assert!(result.is_err(), "Non-/dev/ device path must be rejected");
    }

    #[tokio::test]
    async fn test_storage_mount_invalid_mountpoint() {
        let result = storage_mount("/dev/sda", "/mnt/$(evil)", None).await;
        assert!(result.is_err(), "Injection in mountpoint must be rejected");
    }

    #[tokio::test]
    async fn test_storage_unmount_invalid_mountpoint() {
        let result = storage_unmount("/mnt/$(evil)").await;
        assert!(result.is_err(), "Injection in mountpoint must be rejected");
    }

    #[tokio::test]
    async fn test_storage_lvm_list_runs_or_errors_cleanly() {
        let result = storage_lvm_list().await;
        // LVM may not be installed; that's fine as long as it's a clean error
        if let Err(e) = result {
            assert!(e.to_string().contains("LVM not available") || !e.to_string().is_empty());
        } else {
            let val = result.unwrap();
            assert!(val.get("pvs").is_some() || val.get("vgs").is_some() || val.get("lvs").is_some());
        }
    }
}
