use serde_json::Value;

/// Read CPU temperatures, fan speeds from sysfs thermal zones and hwmon.
pub async fn hardware_sensors() -> anyhow::Result<Value> {
    let mut sensors = Vec::new();

    // Thermal zones: /sys/class/thermal/thermal_zone*/
    if let Ok(mut dir) = tokio::fs::read_dir("/sys/class/thermal").await {
        while let Ok(Some(entry)) = dir.next_entry().await {
            let base = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with("thermal_zone") { continue; }

            let temp_raw = tokio::fs::read_to_string(base.join("temp")).await
                .ok()
                .and_then(|s| s.trim().parse::<i64>().ok());
            let zone_type = tokio::fs::read_to_string(base.join("type")).await
                .unwrap_or_default()
                .trim()
                .to_string();

            if let Some(millideg) = temp_raw {
                sensors.push(serde_json::json!({
                    "zone": name,
                    "type": zone_type,
                    "temp_celsius": millideg as f64 / 1000.0,
                    "source": "thermal_zone",
                }));
            }
        }
    }

    // hwmon: /sys/class/hwmon/hwmon*/temp*_input
    if let Ok(mut dir) = tokio::fs::read_dir("/sys/class/hwmon").await {
        while let Ok(Some(entry)) = dir.next_entry().await {
            let base = entry.path();
            let hwmon_name = tokio::fs::read_to_string(base.join("name")).await
                .unwrap_or_default()
                .trim()
                .to_string();
            let Ok(mut files) = tokio::fs::read_dir(&base).await else { continue };
            while let Ok(Some(f)) = files.next_entry().await {
                let fname = f.file_name().to_string_lossy().to_string();
                if fname.starts_with("temp") && fname.ends_with("_input") {
                    let temp_raw = tokio::fs::read_to_string(f.path()).await
                        .ok()
                        .and_then(|s| s.trim().parse::<i64>().ok());
                    if let Some(millideg) = temp_raw {
                        sensors.push(serde_json::json!({
                            "zone": format!("{}/{}", entry.file_name().to_string_lossy(), fname),
                            "type": hwmon_name.clone(),
                            "temp_celsius": millideg as f64 / 1000.0,
                            "source": "hwmon",
                        }));
                    }
                }
            }
        }
    }

    Ok(serde_json::json!(sensors))
}

/// List PCI devices using lspci.
pub async fn hardware_pci() -> anyhow::Result<Value> {
    let output = tokio::process::Command::new("lspci")
        .args(["-mm"])  // Machine-readable format
        .output().await
        .map_err(|e| anyhow::anyhow!("lspci failed: {}", e))?;
    if !output.status.success() {
        anyhow::bail!("lspci failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let devices: Vec<Value> = stdout.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            // Format: Slot "Class" "Vendor" "Device" "SVendor" "SDevice" "Rev"
            let fields: Vec<&str> = l.splitn(7, '"')
                .filter(|s| !s.trim_matches(|c| c == '"' || c == ' ').is_empty())
                .collect();
            serde_json::json!({
                "slot": l.split_whitespace().next().unwrap_or(""),
                "raw": l,
                "fields": fields,
            })
        })
        .collect();
    Ok(serde_json::json!(devices))
}

/// List USB devices by reading /sys/bus/usb/devices/.
pub async fn hardware_usb() -> anyhow::Result<Value> {
    let mut devices = Vec::new();

    if let Ok(mut dir) = tokio::fs::read_dir("/sys/bus/usb/devices").await {
        while let Ok(Some(entry)) = dir.next_entry().await {
            let base = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            // Skip interfaces (e.g., 1-1:1.0), only process device nodes
            if name.contains(':') { continue; }

            let id_vendor = tokio::fs::read_to_string(base.join("idVendor")).await
                .ok().map(|s| s.trim().to_string());
            let id_product = tokio::fs::read_to_string(base.join("idProduct")).await
                .ok().map(|s| s.trim().to_string());

            // Only include real USB devices (have idVendor)
            if id_vendor.is_none() { continue; }

            let product = tokio::fs::read_to_string(base.join("product")).await
                .ok().map(|s| s.trim().to_string());
            let manufacturer = tokio::fs::read_to_string(base.join("manufacturer")).await
                .ok().map(|s| s.trim().to_string());
            let busnum = tokio::fs::read_to_string(base.join("busnum")).await
                .ok().and_then(|s| s.trim().parse::<u32>().ok());
            let devnum = tokio::fs::read_to_string(base.join("devnum")).await
                .ok().and_then(|s| s.trim().parse::<u32>().ok());

            devices.push(serde_json::json!({
                "bus": busnum,
                "device": devnum,
                "id_vendor": id_vendor,
                "id_product": id_product,
                "product": product,
                "manufacturer": manufacturer,
            }));
        }
    }

    Ok(serde_json::json!(devices))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hardware_sensors() {
        let result = hardware_sensors().await.unwrap();
        assert!(result.is_array());
    }

    #[tokio::test]
    async fn test_hardware_usb() {
        let result = hardware_usb().await.unwrap();
        assert!(result.is_array());
    }

    #[tokio::test]
    async fn test_hardware_pci() {
        // lspci may not be installed everywhere
        let result = hardware_pci().await;
        if let Ok(val) = result {
            assert!(val.is_array());
        }
    }
}
