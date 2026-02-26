use serde::Serialize;
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::Write;
use chrono::Utc;

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub timestamp: String,
    pub tool: String,
    pub params: Value,
    pub decision: String,
    pub result: String,
    pub duration_ms: u64,
}

#[derive(Clone)]
pub struct AuditLogger {
    log_path: String,
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new("/var/log/neurond/audit.log")
    }
}

impl AuditLogger {
    pub fn new(path: &str) -> Self {
        Self {
            log_path: path.to_string(),
        }
    }

    pub async fn log(
        &self,
        tool: &str,
        params: &Value,
        decision: &str,
        result: &str,
        duration_ms: u64,
    ) -> anyhow::Result<()> {
        let timestamp = Utc::now().to_rfc3339();

        let event = AuditEvent {
            timestamp,
            tool: tool.to_string(),
            params: params.clone(),
            decision: decision.to_string(),
            result: result.to_string(),
            duration_ms,
        };

        let json_line = serde_json::to_string(&event)?;
        let log_path = self.log_path.clone();

        let handle = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .map_err(|e| anyhow::anyhow!("Audit log open failed ({}): {}", log_path, e))?;

            writeln!(file, "{}", json_line)
                .map_err(|e| anyhow::anyhow!("Audit log write failed: {}", e))?;

            Ok(())
        });

        // Await the task, propagate panic or underlying error
        handle.await.map_err(|e| anyhow::anyhow!("Audit log task panicked: {}", e))??;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_serialization() {
        let event = AuditEvent {
            timestamp: "2026-02-22T14:03:43Z".into(),
            tool: "system.cpu".into(),
            params: serde_json::json!({"test": true}),
            decision: "allowed".into(),
            result: "success".into(),
            duration_ms: 12,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("timestamp"));
        assert!(json.contains("system.cpu"));
        assert!(json.contains("12"));
    }
}
