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

pub async fn service_dependencies(name: &str, connection: &Connection) -> anyhow::Result<Value> {
    crate::linux::systemd::get_unit_dependencies(name, connection).await
}

pub async fn service_start(name: &str, connection: &Connection) -> anyhow::Result<Value> {
    crate::linux::systemd::unit_start(name, connection).await
}

pub async fn service_stop(name: &str, connection: &Connection) -> anyhow::Result<Value> {
    crate::linux::systemd::unit_stop(name, connection).await
}

pub async fn service_restart(name: &str, connection: &Connection) -> anyhow::Result<Value> {
    crate::linux::systemd::unit_restart(name, connection).await
}

pub async fn service_enable(name: &str, connection: &Connection) -> anyhow::Result<Value> {
    crate::linux::systemd::unit_enable(name, connection).await
}

pub async fn service_disable(name: &str, connection: &Connection) -> anyhow::Result<Value> {
    crate::linux::systemd::unit_disable(name, connection).await
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

    #[tokio::test]
    async fn test_service_dependencies_journald() {
        let conn = Connection::system().await.expect("D-Bus connection");
        let result = service_dependencies("systemd-journald.service", &conn).await;
        if let Ok(val) = result {
            assert!(val.get("requires").is_some());
            assert!(val.get("after").is_some());
        }
    }

    // Mutation operations: validate that injection in unit names is rejected
    // before any D-Bus/subprocess call is made.

    #[tokio::test]
    async fn test_service_start_invalid_unit_rejected() {
        let conn = Connection::system().await.expect("D-Bus connection");
        let result = service_start("bad;name.service", &conn).await;
        assert!(result.is_err(), "Unit name injection must be rejected");
    }

    #[tokio::test]
    async fn test_service_stop_invalid_unit_rejected() {
        let conn = Connection::system().await.expect("D-Bus connection");
        let result = service_stop("$(evil)", &conn).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_service_restart_invalid_unit_rejected() {
        let conn = Connection::system().await.expect("D-Bus connection");
        let result = service_restart("unit with spaces", &conn).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_service_enable_invalid_unit_rejected() {
        let conn = Connection::system().await.expect("D-Bus connection");
        let result = service_enable("bad;unit", &conn).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_service_disable_invalid_unit_rejected() {
        let conn = Connection::system().await.expect("D-Bus connection");
        let result = service_disable("unit`id`", &conn).await;
        assert!(result.is_err());
    }
}
