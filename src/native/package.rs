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

fn validate_package_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() || name.len() > 100 {
        anyhow::bail!("Invalid package name length");
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '+') {
        anyhow::bail!("Package name contains invalid characters: {}", name);
    }
    Ok(())
}

pub async fn package_updates() -> anyhow::Result<Value> {
    let output = tokio::process::Command::new("apt")
        .args(["list", "--upgradable"])
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output().await
        .map_err(|e| anyhow::anyhow!("apt list failed: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let packages: Vec<Value> = stdout.lines()
        .filter(|l| l.contains('/'))
        .filter_map(|l| {
            // Format: name/repo version arch [upgradable from: old_version]
            let mut parts = l.split_whitespace();
            let name_repo = parts.next()?;
            let name = name_repo.split('/').next()?;
            let version = parts.next()?;
            Some(serde_json::json!({"name": name, "version": version}))
        })
        .collect();
    Ok(serde_json::json!(packages))
}

pub async fn package_search(query: &str) -> anyhow::Result<Value> {
    if query.is_empty() || query.len() > 100 {
        anyhow::bail!("Query must be 1-100 characters");
    }
    // Validate: alphanumeric, spaces, hyphens only
    if !query.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == ' ' || c == '_') {
        anyhow::bail!("Query contains invalid characters");
    }
    let query_owned = query.to_string();
    let output = tokio::process::Command::new("apt-cache")
        .args(["search", &query_owned])
        .output().await
        .map_err(|e| anyhow::anyhow!("apt-cache search failed: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let packages: Vec<Value> = stdout.lines()
        .filter_map(|l| {
            let (name, desc) = l.split_once(" - ")?;
            Some(serde_json::json!({"name": name.trim(), "description": desc.trim()}))
        })
        .collect();
    Ok(serde_json::json!(packages))
}

/// Look up detailed package metadata by scanning /var/lib/dpkg/status directly — no subprocess.
pub async fn package_info(name: &str) -> anyhow::Result<Value> {
    validate_package_name(name)?;
    let name_owned = name.to_string();
    tokio::task::spawn_blocking(move || dpkg_package_info(&name_owned)).await?
}

fn dpkg_package_info(name: &str) -> anyhow::Result<Value> {
    let content = std::fs::read_to_string("/var/lib/dpkg/status")
        .map_err(|e| anyhow::anyhow!("Cannot read dpkg status: {}", e))?;

    let mut current: HashMap<String, String> = HashMap::new();
    let mut in_target = false;

    for line in content.lines() {
        if line.is_empty() {
            if in_target {
                break; // end of the target package stanza
            }
            current.clear();
            continue;
        }
        if let Some((k, v)) = line.split_once(": ") {
            if k == "Package" {
                in_target = v.trim() == name;
            }
            if in_target {
                current.entry(k.to_string()).or_insert_with(|| v.to_string());
            }
        }
    }

    if current.is_empty() {
        anyhow::bail!("Package not found: {}", name);
    }
    Ok(serde_json::to_value(current).unwrap_or_default())
}

pub async fn package_install(name: &str) -> anyhow::Result<Value> {
    validate_package_name(name)?;
    let name_owned = name.to_string();
    let output = tokio::process::Command::new("apt-get")
        .args(["install", "-y", &name_owned])
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output().await
        .map_err(|e| anyhow::anyhow!("apt-get install failed: {}", e))?;
    if output.status.success() {
        Ok(serde_json::json!({"name": name, "action": "install", "status": "ok"}))
    } else {
        anyhow::bail!("apt-get install failed: {}", String::from_utf8_lossy(&output.stderr))
    }
}

pub async fn package_update(name: Option<&str>) -> anyhow::Result<Value> {
    if let Some(n) = name { validate_package_name(n)?; }
    let mut args = vec!["install".to_string(), "--only-upgrade".to_string(), "-y".to_string()];
    if let Some(n) = name {
        args.push(n.to_string());
    } else {
        // Update all upgradable packages
        args = vec!["upgrade".to_string(), "-y".to_string()];
    }
    let output = tokio::process::Command::new("apt-get")
        .args(&args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output().await
        .map_err(|e| anyhow::anyhow!("apt-get upgrade failed: {}", e))?;
    if output.status.success() {
        Ok(serde_json::json!({"name": name, "action": "update", "status": "ok"}))
    } else {
        anyhow::bail!("apt-get upgrade failed: {}", String::from_utf8_lossy(&output.stderr))
    }
}

pub async fn package_remove(name: &str) -> anyhow::Result<Value> {
    validate_package_name(name)?;
    let name_owned = name.to_string();
    let output = tokio::process::Command::new("apt-get")
        .args(["remove", "-y", &name_owned])
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output().await
        .map_err(|e| anyhow::anyhow!("apt-get remove failed: {}", e))?;
    if output.status.success() {
        Ok(serde_json::json!({"name": name, "action": "remove", "status": "ok"}))
    } else {
        anyhow::bail!("apt-get remove failed: {}", String::from_utf8_lossy(&output.stderr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_package_list() {
        let result = package_list().await;
        if let Ok(val) = result {
            let arr = val.as_array().expect("Should return an array");
            assert!(!arr.is_empty(), "Should have at least some packages");
            let first = &arr[0];
            assert!(first.get("name").is_some(), "Package should have a name");
            assert!(first.get("version").is_some(), "Package should have a version");
        }
    }

    #[tokio::test]
    async fn test_package_name_invalid() {
        let result = package_install("bad;name && rm -rf /").await;
        assert!(result.is_err(), "Shell injection in package name should fail");
    }

    #[tokio::test]
    async fn test_package_search_invalid_query() {
        let result = package_search("bad;query").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_package_name_valid() {
        assert!(validate_package_name("bash").is_ok());
        assert!(validate_package_name("libssl-dev").is_ok());
        assert!(validate_package_name("g++").is_ok());
        assert!(validate_package_name("python3.11").is_ok());
    }

    #[test]
    fn test_validate_package_name_empty() {
        assert!(validate_package_name("").is_err());
    }

    #[test]
    fn test_validate_package_name_injection() {
        assert!(validate_package_name("bash; rm -rf /").is_err());
        assert!(validate_package_name("$(evil)").is_err());
        assert!(validate_package_name("bash`id`").is_err());
        assert!(validate_package_name("bash && evil").is_err());
    }

    #[test]
    fn test_validate_package_name_too_long() {
        let long = "a".repeat(101);
        assert!(validate_package_name(&long).is_err());
    }

    #[tokio::test]
    async fn test_package_remove_invalid_name() {
        let result = package_remove("bad name!").await;
        assert!(result.is_err(), "Invalid package name must be rejected");
    }

    #[tokio::test]
    async fn test_package_install_empty_name() {
        let result = package_install("").await;
        assert!(result.is_err(), "Empty package name must be rejected");
    }

    #[tokio::test]
    async fn test_package_info_valid_system_package() {
        // bash is installed on virtually every Debian/Ubuntu system
        let result = package_info("bash").await;
        if let Ok(val) = result {
            // dpkg -s returns a map of fields
            assert!(val.is_object(), "package_info should return an object");
        }
    }

    #[tokio::test]
    async fn test_package_search_valid_query() {
        let result = package_search("bash").await;
        if let Ok(val) = result {
            assert!(val.is_array());
        }
    }

    #[tokio::test]
    async fn test_package_updates_returns_array() {
        let result = package_updates().await;
        if let Ok(val) = result {
            assert!(val.is_array());
        }
    }
}
