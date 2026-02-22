use serde::Serialize;
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::Write;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

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
        Self::new("/var/log/cortexd/audit.log")
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
    ) {
        let ts = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "UnknownTime".to_string());

        let event = AuditEvent {
            timestamp: ts,
            tool: tool.to_string(),
            params: params.clone(),
            decision: decision.to_string(),
            result: result.to_string(),
            duration_ms,
        };

        match serde_json::to_string(&event) {
            Ok(json_line) => {
                let log_path = self.log_path.clone();
                let handle = tokio::task::spawn_blocking(move || {
                    match OpenOptions::new().create(true).append(true).open(&log_path) {
                        Ok(mut file) => {
                            if let Err(e) = writeln!(file, "{}", json_line) {
                                tracing::warn!("Audit log write failed: {}", e);
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Audit log open failed ({}): {}", log_path, e);
                        }
                    }
                });
                // Await the blocking task; log if it panics
                if let Err(e) = handle.await {
                    tracing::error!("Audit log task panicked: {}", e);
                }
            }
            Err(e) => {
                tracing::warn!("Audit event serialization failed: {}", e);
            }
        }
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
