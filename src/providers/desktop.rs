use serde_json::Value;
use zbus::Connection;

pub async fn desktop_windows() -> anyhow::Result<Value> {
    crate::linux::desktop::list_windows().await
}

pub async fn desktop_apps() -> anyhow::Result<Value> {
    crate::linux::desktop::list_apps().await
}

pub async fn desktop_clipboard() -> anyhow::Result<Value> {
    crate::linux::desktop::get_clipboard().await
}

pub async fn desktop_media(conn: &Connection) -> anyhow::Result<Value> {
    crate::linux::desktop::media_status(conn).await
}

pub async fn desktop_theme() -> anyhow::Result<Value> {
    crate::linux::desktop::get_theme().await
}

pub async fn desktop_volume() -> anyhow::Result<Value> {
    crate::linux::desktop::get_volume().await
}

pub async fn desktop_focus(window_id: &str) -> anyhow::Result<Value> {
    crate::linux::desktop::focus_window(window_id).await
}

pub async fn desktop_close(window_id: &str) -> anyhow::Result<Value> {
    crate::linux::desktop::close_window(window_id).await
}

pub async fn desktop_launch(app: &str) -> anyhow::Result<Value> {
    crate::linux::desktop::launch_app(app).await
}

pub async fn desktop_set_volume(percent: u32) -> anyhow::Result<Value> {
    crate::linux::desktop::set_volume(percent).await
}

pub async fn desktop_set_theme(mode: &str) -> anyhow::Result<Value> {
    crate::linux::desktop::set_theme(mode).await
}

pub async fn desktop_notify(conn: &Connection, summary: &str, body: &str, urgency: u8) -> anyhow::Result<Value> {
    crate::linux::desktop::send_notification(conn, summary, body, urgency).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_volume_invalid() {
        // Volume > 100 should fail
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(desktop_set_volume(200));
        assert!(result.is_err(), "Volume > 100 should be rejected");
    }

    #[test]
    fn test_set_theme_invalid() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(desktop_set_theme("neon-pink"));
        assert!(result.is_err(), "Invalid theme mode should be rejected");
    }
}
