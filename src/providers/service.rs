use serde_json::Value;
use zbus::Connection;

pub async fn service_list(connection: &Connection) -> anyhow::Result<Value> {
    crate::linux::systemd::list_units(connection).await
}

pub async fn service_status(name: &str, connection: &Connection) -> anyhow::Result<Value> {
    crate::linux::systemd::get_unit_status(name, connection).await
}

pub async fn service_logs(name: &str, lines: usize) -> anyhow::Result<Value> {
    crate::linux::systemd::journal_tail(Some(name), lines).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_service_list() {
        let conn = Connection::system().await.expect("D-Bus connection");
        let result = service_list(&conn).await.unwrap();
        let arr = result.as_array().expect("Service list should be an array");
        assert!(!arr.is_empty(), "Should return some systemd services");
    }

    #[tokio::test]
    async fn test_service_status() {
        let conn = Connection::system().await.expect("D-Bus connection");
        let result = service_status("systemd-journald.service", &conn).await;
        if let Ok(val) = result {
            assert_eq!(val["Id"], "systemd-journald.service");
            assert!(val.get("ActiveState").is_some(), "Status should contain ActiveState");
        }
    }

    #[tokio::test]
    async fn test_service_logs() {
        let result = service_logs("systemd-journald.service", 5).await;
        if let Ok(val) = result {
            assert!(val.is_array() || val.is_object(), "Logs should return structured data");
        }
    }
}
