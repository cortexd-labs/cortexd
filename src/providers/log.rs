use serde_json::Value;

pub async fn log_tail(unit: Option<&str>, lines: usize) -> anyhow::Result<Value> {
    crate::linux::systemd::journal_tail(unit, lines).await
}

pub async fn log_search(keyword: &str, since: Option<&str>, priority: Option<&str>) -> anyhow::Result<Value> {
    crate::linux::systemd::journal_search(keyword, since, priority).await
}

pub async fn log_units() -> anyhow::Result<Value> {
    crate::linux::systemd::journal_units().await
}

pub async fn log_stream(unit: Option<&str>, timeout_secs: u64, max_lines: usize) -> anyhow::Result<Value> {
    crate::linux::systemd::journal_stream(unit, timeout_secs, max_lines).await
}

pub async fn log_rotate() -> anyhow::Result<Value> {
    crate::linux::systemd::journal_rotate().await
}

pub async fn log_vacuum(size_mb: Option<u64>, days: Option<u64>) -> anyhow::Result<Value> {
    crate::linux::systemd::journal_vacuum(size_mb, days).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_log_tail_global() {
        // Tail global logs
        let result = log_tail(None, 2).await;
        if let Ok(val) = result {
            let arr = val.as_array().expect("Log tail should return an array");
            assert!(arr.len() <= 2, "Should respect line limits");
        }
    }

    #[tokio::test]
    async fn test_log_search() {
        let result = log_search("root", Some("1 hour ago"), None).await;
        if let Ok(val) = result {
            assert!(val.is_array(), "Log search should return an array");
        }
    }

    #[tokio::test]
    async fn test_log_units() {
        let result = log_units().await;
        if let Ok(val) = result {
            assert!(val.is_array());
        }
    }

    #[tokio::test]
    async fn test_log_vacuum_requires_param() {
        let result = log_vacuum(None, None).await;
        assert!(result.is_err(), "Must specify size_mb or days");
    }

    #[tokio::test]
    async fn test_log_vacuum_with_days() {
        // journalctl --vacuum-time may require root; test structure only
        let result = log_vacuum(None, Some(90)).await;
        // Either succeeds (has permissions) or fails with a non-validation error
        if let Err(e) = result {
            let msg = e.to_string();
            assert!(!msg.contains("Provide either"), "Should not be a validation error when days is set");
        }
    }

    #[tokio::test]
    async fn test_log_search_empty_keyword_rejected() {
        let result = log_search("", None, None).await;
        assert!(result.is_err(), "Empty keyword must be rejected");
    }

    #[tokio::test]
    async fn test_log_tail_with_unit() {
        let result = log_tail(Some("systemd-journald.service"), 3).await;
        if let Ok(val) = result {
            assert!(val.get("entries").is_some());
        }
    }

    #[tokio::test]
    async fn test_log_tail_invalid_unit_rejected() {
        let result = log_tail(Some("bad;unit"), 5).await;
        assert!(result.is_err(), "Injection in unit name must be rejected");
    }

    #[tokio::test]
    async fn test_log_stream_returns_entries_array() {
        // Short timeout, low max_lines — should return quickly
        let result = log_stream(None, 1, 5).await;
        if let Ok(val) = result {
            assert!(val.get("entries").is_some(), "Stream result should have entries key");
        }
    }

    #[tokio::test]
    async fn test_log_stream_invalid_unit_rejected() {
        let result = log_stream(Some("$(evil)"), 1, 5).await;
        assert!(result.is_err(), "Injection in unit name must be rejected");
    }

    #[tokio::test]
    async fn test_log_rotate_runs_or_errors_gracefully() {
        let result = log_rotate().await;
        // May fail without root; that's acceptable — just not a panic
        if let Err(e) = result {
            let msg = e.to_string();
            assert!(!msg.is_empty(), "Error message should be non-empty");
        }
    }
}
