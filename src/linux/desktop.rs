use serde_json::Value;
use zbus::Connection;

fn validate_app_name(app: &str) -> anyhow::Result<()> {
    if app.is_empty() || app.len() > 128 {
        anyhow::bail!("App name must be 1-128 characters");
    }
    if !app.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
        anyhow::bail!("App name contains invalid characters: {}", app);
    }
    Ok(())
}

fn validate_window_id(id: &str) -> anyhow::Result<()> {
    // Window IDs are hex numbers like 0x01e00003
    if id.is_empty() || id.len() > 20 {
        anyhow::bail!("Invalid window ID");
    }
    if !id.chars().all(|c| c.is_ascii_hexdigit() || c == 'x' || c == 'X') {
        anyhow::bail!("Window ID must be a hex number: {}", id);
    }
    Ok(())
}

/// List open windows using wmctrl.
pub async fn list_windows() -> anyhow::Result<Value> {
    let output = tokio::process::Command::new("wmctrl")
        .args(["-lG"])
        .output().await
        .map_err(|e| anyhow::anyhow!("wmctrl not available: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let windows: Vec<Value> = stdout.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let parts: Vec<&str> = l.splitn(8, ' ').collect();
            serde_json::json!({
                "id": parts.first().copied().unwrap_or(""),
                "desktop": parts.get(1).copied().unwrap_or(""),
                "x": parts.get(2).and_then(|v| v.parse::<i32>().ok()),
                "y": parts.get(3).and_then(|v| v.parse::<i32>().ok()),
                "width": parts.get(4).and_then(|v| v.parse::<i32>().ok()),
                "height": parts.get(5).and_then(|v| v.parse::<i32>().ok()),
                "title": parts.get(7).copied().unwrap_or(""),
            })
        })
        .collect();
    Ok(serde_json::json!(windows))
}

/// List running application classes using wmctrl.
pub async fn list_apps() -> anyhow::Result<Value> {
    let output = tokio::process::Command::new("wmctrl")
        .args(["-lx"])
        .output().await
        .map_err(|e| anyhow::anyhow!("wmctrl not available: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut apps: Vec<String> = stdout.lines()
        .filter_map(|l| {
            let parts: Vec<&str> = l.splitn(5, ' ').filter(|s| !s.is_empty()).collect();
            parts.get(2).map(|s| s.split('.').next().unwrap_or(*s).to_string())
        })
        .collect();
    apps.sort();
    apps.dedup();
    Ok(serde_json::json!(apps))
}

/// Get clipboard content (tries wl-paste for Wayland, xclip for X11).
pub async fn get_clipboard() -> anyhow::Result<Value> {
    // Try Wayland first
    if let Ok(output) = tokio::process::Command::new("wl-paste")
        .args(["--no-newline"])
        .output().await {
        if output.status.success() {
            return Ok(serde_json::json!({"content": String::from_utf8_lossy(&output.stdout)}));
        }
    }
    // Fall back to X11
    let output = tokio::process::Command::new("xclip")
        .args(["-selection", "clipboard", "-o"])
        .output().await
        .map_err(|e| anyhow::anyhow!("No clipboard tool available (wl-paste/xclip): {}", e))?;
    if output.status.success() {
        Ok(serde_json::json!({"content": String::from_utf8_lossy(&output.stdout)}))
    } else {
        anyhow::bail!("Clipboard read failed")
    }
}

/// Get MPRIS media playback status via D-Bus session bus.
pub async fn media_status(conn: &Connection) -> anyhow::Result<Value> {
    // Enumerate MPRIS players on the session bus
    let dbus_proxy = zbus::fdo::DBusProxy::new(conn).await?;
    let names = dbus_proxy.list_names().await?;
    let mpris_names: Vec<String> = names.into_iter()
        .filter(|n| n.starts_with("org.mpris.MediaPlayer2."))
        .map(|n| n.to_string())
        .collect();

    if mpris_names.is_empty() {
        return Ok(serde_json::json!({"status": "no player running"}));
    }

    let player_name = &mpris_names[0];
    let props = zbus::fdo::PropertiesProxy::builder(conn)
        .destination(player_name.as_str())?
        .path("/org/mpris/MediaPlayer2")?
        .build().await?;

    let iface: zbus::names::InterfaceName<'_> = "org.mpris.MediaPlayer2.Player"
        .try_into()
        .map_err(|e| anyhow::anyhow!("invalid interface name: {}", e))?;

    let playback = props.get(iface.clone(), "PlaybackStatus").await
        .ok()
        .and_then(|v| zbus::zvariant::Value::from(v).downcast::<String>().ok());

    let metadata = props.get(iface, "Metadata").await.ok();

    Ok(serde_json::json!({
        "player": player_name.trim_start_matches("org.mpris.MediaPlayer2."),
        "status": playback,
        "metadata": metadata.map(|m| format!("{:?}", m)),
    }))
}

/// Get current desktop theme via gsettings.
pub async fn get_theme() -> anyhow::Result<Value> {
    let output = tokio::process::Command::new("gsettings")
        .args(["get", "org.gnome.desktop.interface", "color-scheme"])
        .output().await
        .map_err(|e| anyhow::anyhow!("gsettings not available: {}", e))?;
    let scheme = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let mode = if scheme.contains("dark") { "dark" } else { "light" };
    Ok(serde_json::json!({"color_scheme": scheme, "mode": mode}))
}

/// Get current volume level from PulseAudio/PipeWire.
pub async fn get_volume() -> anyhow::Result<Value> {
    let vol_output = tokio::process::Command::new("pactl")
        .args(["get-sink-volume", "@DEFAULT_SINK@"])
        .output().await
        .map_err(|e| anyhow::anyhow!("pactl not available: {}", e))?;
    let mute_output = tokio::process::Command::new("pactl")
        .args(["get-sink-mute", "@DEFAULT_SINK@"])
        .output().await?;

    let vol_str = String::from_utf8_lossy(&vol_output.stdout);
    let mute_str = String::from_utf8_lossy(&mute_output.stdout);

    // Extract first percentage from volume output: "Volume: front-left: 65536 / 100% / ..."
    let percent = vol_str.split('%').next()
        .and_then(|s| s.split_whitespace().last())
        .and_then(|s| s.parse::<u32>().ok());
    let muted = mute_str.to_lowercase().contains("yes");

    Ok(serde_json::json!({"volume_percent": percent, "muted": muted}))
}

/// Focus a window by ID using wmctrl.
pub async fn focus_window(window_id: &str) -> anyhow::Result<Value> {
    validate_window_id(window_id)?;
    let id = window_id.to_string();
    let output = tokio::process::Command::new("wmctrl")
        .args(["-ia", &id])
        .output().await
        .map_err(|e| anyhow::anyhow!("wmctrl not available: {}", e))?;
    if output.status.success() {
        Ok(serde_json::json!({"window_id": window_id, "action": "focus", "status": "ok"}))
    } else {
        anyhow::bail!("wmctrl focus failed: {}", String::from_utf8_lossy(&output.stderr))
    }
}

/// Close a window by ID using wmctrl.
pub async fn close_window(window_id: &str) -> anyhow::Result<Value> {
    validate_window_id(window_id)?;
    let id = window_id.to_string();
    let output = tokio::process::Command::new("wmctrl")
        .args(["-ic", &id])
        .output().await
        .map_err(|e| anyhow::anyhow!("wmctrl not available: {}", e))?;
    if output.status.success() {
        Ok(serde_json::json!({"window_id": window_id, "action": "close", "status": "ok"}))
    } else {
        anyhow::bail!("wmctrl close failed: {}", String::from_utf8_lossy(&output.stderr))
    }
}

/// Launch an application.
pub async fn launch_app(app: &str) -> anyhow::Result<Value> {
    validate_app_name(app)?;
    let app_owned = app.to_string();
    // Try gtk-launch first, fall back to bare exec
    let res = tokio::process::Command::new("gtk-launch")
        .arg(&app_owned)
        .spawn();
    if res.is_ok() {
        return Ok(serde_json::json!({"app": app, "status": "launched"}));
    }
    tokio::process::Command::new(&app_owned)
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to launch {}: {}", app, e))?;
    Ok(serde_json::json!({"app": app, "status": "launched"}))
}

/// Set speaker volume percent (0-100).
pub async fn set_volume(percent: u32) -> anyhow::Result<Value> {
    if percent > 100 {
        anyhow::bail!("Volume percent must be 0-100");
    }
    let arg = format!("{}%", percent);
    let output = tokio::process::Command::new("pactl")
        .args(["set-sink-volume", "@DEFAULT_SINK@", &arg])
        .output().await
        .map_err(|e| anyhow::anyhow!("pactl not available: {}", e))?;
    if output.status.success() {
        Ok(serde_json::json!({"volume_percent": percent, "status": "ok"}))
    } else {
        anyhow::bail!("pactl set-volume failed: {}", String::from_utf8_lossy(&output.stderr))
    }
}

/// Set dark or light theme mode.
pub async fn set_theme(mode: &str) -> anyhow::Result<Value> {
    let scheme = match mode {
        "dark" => "prefer-dark",
        "light" => "prefer-light",
        _ => anyhow::bail!("Mode must be 'dark' or 'light'"),
    };
    let output = tokio::process::Command::new("gsettings")
        .args(["set", "org.gnome.desktop.interface", "color-scheme", scheme])
        .output().await
        .map_err(|e| anyhow::anyhow!("gsettings not available: {}", e))?;
    if output.status.success() {
        Ok(serde_json::json!({"mode": mode, "status": "ok"}))
    } else {
        anyhow::bail!("gsettings failed: {}", String::from_utf8_lossy(&output.stderr))
    }
}

/// Send a desktop notification via D-Bus org.freedesktop.Notifications.
pub async fn send_notification(conn: &Connection, summary: &str, body: &str, urgency: u8) -> anyhow::Result<Value> {
    if summary.is_empty() {
        anyhow::bail!("Notification summary cannot be empty");
    }
    let urgency = urgency.min(2); // 0=low, 1=normal, 2=critical

    // Build hints map with urgency
    let hints: std::collections::HashMap<&str, zbus::zvariant::Value<'_>> = [
        ("urgency", zbus::zvariant::Value::U8(urgency)),
    ].into_iter().collect();

    let proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.Notifications",
        "/org/freedesktop/Notifications",
        "org.freedesktop.Notifications",
    ).await?;

    let id: u32 = proxy.call(
        "Notify",
        &("neurond", 0u32, "", summary, body, Vec::<String>::new(), hints, -1i32),
    ).await?;

    Ok(serde_json::json!({"notification_id": id, "status": "sent"}))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Validation unit tests (no subprocess / D-Bus required) ──────────────

    #[test]
    fn test_validate_app_name_valid() {
        assert!(validate_app_name("firefox").is_ok());
        assert!(validate_app_name("my-app_v2.0").is_ok());
        assert!(validate_app_name("org.gnome.Files").is_ok());
    }

    #[test]
    fn test_validate_app_name_empty() {
        assert!(validate_app_name("").is_err());
    }

    #[test]
    fn test_validate_app_name_injection() {
        assert!(validate_app_name("firefox; rm -rf /").is_err());
        assert!(validate_app_name("$(evil)").is_err());
        assert!(validate_app_name("app`id`").is_err());
    }

    #[test]
    fn test_validate_app_name_too_long() {
        let long = "a".repeat(129);
        assert!(validate_app_name(&long).is_err());
    }

    #[test]
    fn test_validate_window_id_valid() {
        assert!(validate_window_id("0x01e00003").is_ok());
        assert!(validate_window_id("0xABCDEF12").is_ok());
        assert!(validate_window_id("1234ABCD").is_ok());
    }

    #[test]
    fn test_validate_window_id_invalid() {
        assert!(validate_window_id("").is_err());
        assert!(validate_window_id("0x01e0;rm").is_err());
        assert!(validate_window_id("window title with spaces").is_err());
    }

    #[test]
    fn test_validate_window_id_too_long() {
        let long = "0".repeat(21);
        assert!(validate_window_id(&long).is_err());
    }

    // ── set_volume validation ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_set_volume_too_high() {
        let result = set_volume(101).await;
        assert!(result.is_err(), "Volume > 100 must be rejected");
    }

    #[tokio::test]
    async fn test_set_volume_boundary() {
        // 100 should pass validation (pactl may fail without audio, which is fine)
        let result = set_volume(100).await;
        // Either succeeds (audio present) or fails due to missing pactl — not a validation error
        if let Err(e) = result {
            let msg = e.to_string();
            assert!(!msg.contains("Volume percent"), "Should not be a validation error");
        }
    }

    // ── set_theme validation ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_set_theme_invalid_mode() {
        let result = set_theme("neon-pink").await;
        assert!(result.is_err(), "Invalid theme mode must be rejected");
        assert!(result.unwrap_err().to_string().contains("must be"), "Error should mention valid modes");
    }

    #[tokio::test]
    async fn test_set_theme_valid_values_accepted_by_validator() {
        // Just test that "dark" and "light" pass the match arm without validation error.
        // The actual gsettings call may fail if GNOME isn't running — that's fine.
        for mode in ["dark", "light"] {
            let result = set_theme(mode).await;
            if let Err(e) = result {
                let msg = e.to_string();
                assert!(
                    !msg.contains("must be"),
                    "Valid mode '{}' should not fail validation, got: {}",
                    mode, msg
                );
            }
        }
    }

    // ── send_notification validation ─────────────────────────────────────────

    #[tokio::test]
    async fn test_send_notification_empty_summary() {
        // We need a session D-Bus connection; if unavailable just skip.
        if let Ok(conn) = zbus::Connection::session().await {
            let result = send_notification(&conn, "", "body", 1).await;
            assert!(result.is_err(), "Empty summary should be rejected");
        }
    }

    // ── launch_app validation ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_launch_app_invalid_name_rejected() {
        let result = launch_app("app; rm -rf /").await;
        assert!(result.is_err(), "Injection in app name must be rejected");
    }

    #[tokio::test]
    async fn test_launch_app_empty_rejected() {
        let result = launch_app("").await;
        assert!(result.is_err(), "Empty app name must be rejected");
    }

    // ── focus/close window validation ────────────────────────────────────────

    #[tokio::test]
    async fn test_focus_window_invalid_id() {
        let result = focus_window("not-hex!").await;
        assert!(result.is_err(), "Non-hex window ID must be rejected");
    }

    #[tokio::test]
    async fn test_close_window_invalid_id() {
        let result = close_window("window$(id)").await;
        assert!(result.is_err(), "Injection in window ID must be rejected");
    }

    // ── observe tools (graceful on missing desktop) ──────────────────────────

    #[tokio::test]
    async fn test_list_windows_returns_array_or_error() {
        let result = list_windows().await;
        if let Ok(val) = result {
            assert!(val.is_array(), "Windows should be an array");
        }
        // Err is fine — wmctrl may not be installed in test environment
    }

    #[tokio::test]
    async fn test_list_apps_returns_array_or_error() {
        let result = list_apps().await;
        if let Ok(val) = result {
            assert!(val.is_array(), "Apps should be an array");
        }
    }

    #[tokio::test]
    async fn test_get_clipboard_returns_content_or_error() {
        let result = get_clipboard().await;
        if let Ok(val) = result {
            assert!(val.get("content").is_some(), "Should have content key");
        }
    }

    #[tokio::test]
    async fn test_get_theme_returns_object_or_error() {
        let result = get_theme().await;
        if let Ok(val) = result {
            assert!(val.get("mode").is_some(), "Theme should have mode key");
        }
    }

    #[tokio::test]
    async fn test_get_volume_returns_object_or_error() {
        let result = get_volume().await;
        if let Ok(val) = result {
            assert!(val.get("volume_percent").is_some(), "Volume should have volume_percent key");
        }
    }

    #[tokio::test]
    async fn test_media_status_no_session_dbus() {
        // If session bus is available, check structure; otherwise skip gracefully
        if let Ok(conn) = zbus::Connection::session().await {
            let result = media_status(&conn).await;
            if let Ok(val) = result {
                // Either "no player running" or a player object
                assert!(
                    val.get("status").is_some() || val.get("player").is_some(),
                    "Media status should have status or player key"
                );
            }
        }
    }
}
