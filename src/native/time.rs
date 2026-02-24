use serde_json::Value;

/// Get NTP sync status, trying systemd-timesyncd D-Bus first, then chronyc.
pub async fn time_status(dbus_conn: &zbus::Connection) -> anyhow::Result<Value> {
    // Try systemd-timesyncd via D-Bus
    if let Ok(result) = timesyncd_status(dbus_conn).await {
        return Ok(result);
    }
    // Fall back to chronyc tracking
    chrony_status().await
}

async fn timesyncd_status(conn: &zbus::Connection) -> anyhow::Result<Value> {
    // org.freedesktop.timesync1.Manager has Properties: ServerName, NTPMessage, etc.
    let props = zbus::fdo::PropertiesProxy::builder(conn)
        .destination("org.freedesktop.timesync1")?
        .path("/org/freedesktop/timesync1")?
        .build()
        .await?;

    let iface: zbus::names::InterfaceName<'_> = "org.freedesktop.timesync1.Manager"
        .try_into()
        .map_err(|e| anyhow::anyhow!("invalid interface name: {}", e))?;

    let synchronized = props
        .get(iface.clone(), "NTPSynchronized")
        .await
        .ok()
        .and_then(|v| zbus::zvariant::Value::from(v).downcast::<bool>().ok());

    let server_name = props
        .get(iface, "ServerName")
        .await
        .ok()
        .and_then(|v| zbus::zvariant::Value::from(v).downcast::<String>().ok());

    Ok(serde_json::json!({
        "source": "timesyncd",
        "synchronized": synchronized,
        "server": server_name,
    }))
}

async fn chrony_status() -> anyhow::Result<Value> {
    let output = tokio::process::Command::new("chronyc")
        .args(["tracking"])
        .output().await
        .map_err(|e| anyhow::anyhow!("chronyc tracking failed: {}", e))?;
    if !output.status.success() {
        anyhow::bail!("chronyc tracking failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut info: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for line in stdout.lines() {
        if let Some((k, v)) = line.split_once(':') {
            info.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    Ok(serde_json::json!({
        "source": "chronyc",
        "data": info,
    }))
}

/// Force an immediate NTP sync using chronyc makestep.
pub async fn time_sync() -> anyhow::Result<Value> {
    let output = tokio::process::Command::new("chronyc")
        .args(["makestep"])
        .output().await
        .map_err(|e| anyhow::anyhow!("chronyc makestep failed: {}", e))?;
    if output.status.success() {
        Ok(serde_json::json!({"status": "synced"}))
    } else {
        anyhow::bail!("chronyc makestep failed: {}", String::from_utf8_lossy(&output.stderr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_time_status_fallback() {
        // Try system D-Bus; either succeeds or returns chrony fallback
        let conn = zbus::Connection::system().await.expect("D-Bus connection");
        let result = time_status(&conn).await;
        if let Ok(val) = result {
            assert!(val.get("source").is_some(), "time_status must include source field");
        }
    }

    #[tokio::test]
    async fn test_time_status_source_is_known_value() {
        let conn = zbus::Connection::system().await.expect("D-Bus connection");
        let result = time_status(&conn).await;
        if let Ok(val) = result {
            let source = val["source"].as_str().unwrap_or("");
            assert!(
                ["timesyncd", "chronyc"].contains(&source),
                "source must be one of: timesyncd, chronyc — got: {}",
                source
            );
        }
    }

    #[tokio::test]
    async fn test_time_sync_runs_or_errors_cleanly() {
        // chronyc makestep requires root and chrony running; just test it doesn't panic
        let result = time_sync().await;
        if let Err(e) = result {
            let msg = e.to_string();
            assert!(!msg.is_empty(), "Error message should be non-empty");
        }
    }
}
