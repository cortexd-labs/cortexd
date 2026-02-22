use serde_json::Value;
use std::collections::HashMap;

pub async fn package_list() -> anyhow::Result<Value> {
    tokio::task::spawn_blocking(|| {
        list_installed_packages_dpkg()
    }).await?
}

/// Parse /var/lib/dpkg/status to list installed packages.
/// This is the standard dpkg database on Debian/Ubuntu systems.
fn list_installed_packages_dpkg() -> anyhow::Result<Value> {
    let content = std::fs::read_to_string("/var/lib/dpkg/status")
        .map_err(|e| anyhow::anyhow!("Failed to read dpkg status: {}. This system may not use dpkg.", e))?;

    let mut packages = Vec::new();
    let mut current: HashMap<String, String> = HashMap::new();

    for line in content.lines() {
        if line.is_empty() {
            if let (Some(name), Some(status)) = (current.get("Package"), current.get("Status")) {
                if status.contains("installed") {
                    packages.push(serde_json::json!({
                        "name": name,
                        "version": current.get("Version").cloned().unwrap_or_default(),
                        "architecture": current.get("Architecture").cloned().unwrap_or_default(),
                        "description": current.get("Description")
                            .map(|d| d.lines().next().unwrap_or("").to_string())
                            .unwrap_or_default(),
                    }));
                }
            }
            current.clear();
        } else if let Some((key, value)) = line.split_once(": ") {
            current.insert(key.to_string(), value.to_string());
        }
    }

    // Handle last entry if file doesn't end with empty line
    if let (Some(name), Some(status)) = (current.get("Package"), current.get("Status")) {
        if status.contains("installed") {
            packages.push(serde_json::json!({
                "name": name,
                "version": current.get("Version").cloned().unwrap_or_default(),
                "architecture": current.get("Architecture").cloned().unwrap_or_default(),
                "description": current.get("Description")
                    .map(|d| d.lines().next().unwrap_or("").to_string())
                    .unwrap_or_default(),
            }));
        }
    }

    Ok(serde_json::json!(packages))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_package_list() {
        let result = package_list().await;
        // On Debian/Ubuntu systems this should succeed; elsewhere it may fail
        if let Ok(val) = result {
            let arr = val.as_array().expect("Should return an array");
            assert!(!arr.is_empty(), "Should have at least some packages");
            let first = &arr[0];
            assert!(first.get("name").is_some(), "Package should have a name");
            assert!(first.get("version").is_some(), "Package should have a version");
        }
    }
}
