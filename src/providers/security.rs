use serde_json::Value;

/// Check the enforcement state of SELinux or AppArmor.
pub async fn security_mac_status() -> anyhow::Result<Value> {
    // SELinux: /sys/fs/selinux/enforce (0=permissive, 1=enforcing)
    let selinux = tokio::fs::read_to_string("/sys/fs/selinux/enforce").await.ok()
        .map(|s| s.trim().to_string());

    // AppArmor: /sys/kernel/security/apparmor/profiles lists loaded profiles
    let apparmor_profiles = tokio::fs::read_to_string("/sys/kernel/security/apparmor/profiles").await
        .ok()
        .map(|s| s.lines().count());

    let (mac_system, enforcing) = if let Some(ref s) = selinux {
        ("selinux", s == "1")
    } else if apparmor_profiles.is_some() {
        ("apparmor", true) // AppArmor loaded = enforcing unless profiles say permissive
    } else {
        ("none", false)
    };

    Ok(serde_json::json!({
        "mac_system": mac_system,
        "enforcing": enforcing,
        "selinux_enforce_value": selinux,
        "apparmor_profiles_count": apparmor_profiles,
    }))
}

/// Scan a path (file or directory) for x509 certificates and return expiry info.
pub async fn security_certs_check(path: &str) -> anyhow::Result<Value> {
    use x509_parser::prelude::*;

    let p = std::path::Path::new(path);
    if !p.exists() {
        anyhow::bail!("Path does not exist: {}", path);
    }
    let mut cert_paths: Vec<std::path::PathBuf> = Vec::new();

    if p.is_dir() {
        let mut dir = tokio::fs::read_dir(p).await
            .map_err(|e| anyhow::anyhow!("Cannot read directory {}: {}", path, e))?;
        while let Ok(Some(entry)) = dir.next_entry().await {
            let ep = entry.path();
            if let Some(ext) = ep.extension() {
                if matches!(ext.to_str(), Some("pem") | Some("crt") | Some("cer")) {
                    cert_paths.push(ep);
                }
            }
        }
    } else {
        cert_paths.push(p.to_path_buf());
    }

    let mut certs = Vec::new();
    for cert_path in &cert_paths {
        let Ok(content) = tokio::fs::read(cert_path).await else { continue };
        // Try PEM first
        let pem_items: Vec<_> = Pem::iter_from_buffer(&content).collect();
        let parsed = if pem_items.is_empty() {
            // Try DER
            X509Certificate::from_der(&content).ok().map(|(_, c)| vec![c.tbs_certificate.validity.clone()])
        } else {
            Some(pem_items.into_iter().filter_map(|item| {
                let item = item.ok()?;
                let (_, cert) = X509Certificate::from_der(&item.contents).ok()?;
                Some(cert.tbs_certificate.validity.clone())
            }).collect::<Vec<_>>())
        };

        if let Some(validities) = parsed {
            for validity in validities {
                let not_after = validity.not_after.timestamp();
                let not_before = validity.not_before.timestamp();
                certs.push(serde_json::json!({
                    "path": cert_path.display().to_string(),
                    "not_before": not_before,
                    "not_after": not_after,
                    "expired": not_after < std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64,
                }));
            }
        }
    }

    // Sort by expiry ascending (soonest to expire first)
    certs.sort_by_key(|c| c["not_after"].as_i64().unwrap_or(i64::MAX));
    Ok(serde_json::json!(certs))
}

/// List active auditd rules.
pub async fn security_auditd_rules() -> anyhow::Result<Value> {
    let output = tokio::process::Command::new("auditctl")
        .args(["-l"])
        .output().await
        .map_err(|e| anyhow::anyhow!("auditctl -l failed: {}", e))?;
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let rules: Vec<&str> = stdout.lines()
            .filter(|l| !l.trim().is_empty())
            .collect();
        Ok(serde_json::json!(rules))
    } else {
        anyhow::bail!("auditctl failed: {}", String::from_utf8_lossy(&output.stderr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_security_mac_status() {
        let result = security_mac_status().await.unwrap();
        assert!(result.get("mac_system").is_some());
        assert!(result.get("enforcing").is_some());
    }

    #[tokio::test]
    async fn test_security_certs_check_dir() {
        // /etc/ssl/certs exists on most Debian/Ubuntu systems
        let result = security_certs_check("/etc/ssl/certs").await;
        if let Ok(val) = result {
            assert!(val.is_array());
        }
    }

    #[tokio::test]
    async fn test_security_mac_status_has_all_fields() {
        let result = security_mac_status().await.unwrap();
        assert!(result.get("mac_system").is_some(), "Should have mac_system field");
        assert!(result.get("enforcing").is_some(), "Should have enforcing field");
        assert!(result.get("selinux_enforce_value").is_some(), "Should have selinux_enforce_value field");
        assert!(result.get("apparmor_profiles_count").is_some(), "Should have apparmor_profiles_count field");
        // mac_system must be one of: selinux, apparmor, none
        let mac = result["mac_system"].as_str().unwrap();
        assert!(["selinux", "apparmor", "none"].contains(&mac), "mac_system must be a known value");
    }

    #[tokio::test]
    async fn test_security_certs_check_nonexistent_path() {
        let result = security_certs_check("/nonexistent/path/to/certs").await;
        // Should error cleanly, not panic
        assert!(result.is_err(), "Nonexistent path should return an error");
    }

    #[tokio::test]
    async fn test_security_certs_check_single_cert_file() {
        // Try a well-known cert file if it exists
        let result = security_certs_check("/etc/ssl/certs/ca-certificates.crt").await;
        if let Ok(val) = result {
            assert!(val.is_array(), "Cert check should return an array");
            // If certs were parsed, each should have not_after
            if let Some(first) = val.as_array().and_then(|a| a.first()) {
                assert!(first.get("not_after").is_some(), "Each cert should have not_after");
                assert!(first.get("expired").is_some(), "Each cert should have expired flag");
            }
        }
    }

    #[tokio::test]
    async fn test_security_auditd_rules_runs_or_errors_cleanly() {
        let result = security_auditd_rules().await;
        // auditd may not be installed; must not panic
        if let Ok(val) = result {
            assert!(val.is_array(), "auditd rules should return an array");
        }
        // Err is acceptable when auditd/auditctl is not installed
    }
}
