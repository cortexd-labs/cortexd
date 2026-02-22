use serde_json::Value;

pub async fn log_tail(unit: Option<&str>, lines: usize) -> anyhow::Result<Value> {
    crate::linux::systemd::journal_tail(unit, lines).await
}

pub async fn log_search(keyword: &str, since: Option<&str>, priority: Option<&str>) -> anyhow::Result<Value> {
    crate::linux::systemd::journal_search(keyword, since, priority).await
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
}
