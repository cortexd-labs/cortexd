use serde_json::Value;

fn validate_cron_schedule(schedule: &str) -> anyhow::Result<()> {
    let fields: Vec<&str> = schedule.split_whitespace().collect();
    if fields.len() != 5 && fields.len() != 6 {
        anyhow::bail!("Cron schedule must have 5 or 6 space-separated fields, got {}", fields.len());
    }
    // Reject shell metacharacters
    if schedule.chars().any(|c| matches!(c, ';' | '|' | '&' | '`' | '$' | '(' | ')' | '<' | '>')) {
        anyhow::bail!("Cron schedule contains unsafe characters");
    }
    Ok(())
}

fn validate_cron_command(cmd: &str) -> anyhow::Result<()> {
    if cmd.is_empty() || cmd.len() > 1024 {
        anyhow::bail!("Command must be 1-1024 characters");
    }
    Ok(())
}

fn parse_crontab_content(content: &str, source: &str) -> Vec<Value> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('@') {
            continue;
        }
        // Use split_whitespace to handle multiple spaces between fields
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        // /etc/crontab and /etc/cron.d/* use system format: min hour dom month dow USER command
        // /var/spool/cron/crontabs/* use user format: min hour dom month dow command
        let is_system = source == "/etc/crontab" || source.starts_with("/etc/cron.d/");
        if fields.len() >= 6 {
            let (sched, user, cmd) = if is_system {
                if fields.len() >= 7 {
                    (fields[..5].join(" "), fields[5], fields[6..].join(" "))
                } else {
                    continue;
                }
            } else {
                (fields[..5].join(" "), "", fields[5..].join(" "))
            };
            entries.push(serde_json::json!({
                "source": source,
                "schedule": sched,
                "user": user,
                "command": cmd,
            }));
        }
    }
    entries
}

/// List all cron jobs from system and user crontabs.
pub async fn schedule_cron_list() -> anyhow::Result<Value> {
    let mut entries = Vec::new();

    // System-wide crontab
    if let Ok(content) = tokio::fs::read_to_string("/etc/crontab").await {
        entries.extend(parse_crontab_content(&content, "/etc/crontab"));
    }

    // cron.d drop-ins
    if let Ok(mut dir) = tokio::fs::read_dir("/etc/cron.d").await {
        while let Ok(Some(entry)) = dir.next_entry().await {
            let path = entry.path();
            let source = path.display().to_string();
            if let Ok(content) = tokio::fs::read_to_string(&path).await {
                entries.extend(parse_crontab_content(&content, &source));
            }
        }
    }

    // User crontabs
    if let Ok(mut dir) = tokio::fs::read_dir("/var/spool/cron/crontabs").await {
        while let Ok(Some(entry)) = dir.next_entry().await {
            let path = entry.path();
            let source = path.display().to_string();
            if let Ok(content) = tokio::fs::read_to_string(&path).await {
                entries.extend(parse_crontab_content(&content, &source));
            }
        }
    }

    Ok(serde_json::json!(entries))
}

/// List active systemd timers with next trigger time.
pub async fn schedule_timers_list() -> anyhow::Result<Value> {
    let output = tokio::process::Command::new("systemctl")
        .args(["list-timers", "--all", "--no-pager", "--output=json"])
        .output().await
        .map_err(|e| anyhow::anyhow!("systemctl list-timers failed: {}", e))?;

    // Newer systemd supports --output=json; fall back to plain text parsing
    if let Ok(json) = serde_json::from_slice::<Value>(&output.stdout) {
        return Ok(json);
    }

    // Plain text fallback: parse tabular output
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut timers = Vec::new();
    for line in stdout.lines().skip(1) {
        let fields: Vec<&str> = line.splitn(5, ' ').collect();
        if fields.len() >= 4 && !line.trim().is_empty() {
            timers.push(serde_json::json!({
                "next": fields[0],
                "left": fields[1],
                "last": fields[2],
                "unit": fields[3],
            }));
        }
    }
    Ok(serde_json::json!(timers))
}

/// Add a cron job for a specific user.
pub async fn schedule_cron_add(username: &str, schedule: &str, command: &str) -> anyhow::Result<Value> {
    validate_cron_schedule(schedule)?;
    validate_cron_command(command)?;

    // Read current crontab for user
    let current = tokio::process::Command::new("crontab")
        .args(["-u", username, "-l"])
        .output().await
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let new_entry = format!("{} {}\n", schedule, command);
    let new_content = format!("{}{}", current, new_entry);

    // Write via stdin
    let mut child = tokio::process::Command::new("crontab")
        .args(["-u", username, "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("crontab spawn failed: {}", e))?;

    if let Some(stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        let mut stdin = stdin;
        stdin.write_all(new_content.as_bytes()).await
            .map_err(|e| anyhow::anyhow!("Failed to write crontab: {}", e))?;
    }
    child.wait().await
        .map_err(|e| anyhow::anyhow!("crontab wait failed: {}", e))?;

    Ok(serde_json::json!({"username": username, "entry": new_entry.trim(), "status": "added"}))
}

/// Remove cron jobs matching a command pattern for a user.
pub async fn schedule_cron_remove(username: &str, command_pattern: &str) -> anyhow::Result<Value> {
    if command_pattern.is_empty() {
        anyhow::bail!("command_pattern cannot be empty");
    }
    let current = tokio::process::Command::new("crontab")
        .args(["-u", username, "-l"])
        .output().await
        .map_err(|e| anyhow::anyhow!("crontab -l failed: {}", e))?;
    let content = String::from_utf8_lossy(&current.stdout);
    let before = content.lines().count();
    let filtered: String = content.lines()
        .filter(|l| !l.contains(command_pattern))
        .map(|l| format!("{}\n", l))
        .collect();
    let after = filtered.lines().count();

    let mut child = tokio::process::Command::new("crontab")
        .args(["-u", username, "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("crontab spawn failed: {}", e))?;
    if let Some(stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        let mut stdin = stdin;
        stdin.write_all(filtered.as_bytes()).await.ok();
    }
    child.wait().await.ok();

    Ok(serde_json::json!({"username": username, "removed": before - after, "status": "ok"}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_schedule_cron_list() {
        let result = schedule_cron_list().await.unwrap();
        assert!(result.is_array());
    }

    #[test]
    fn test_validate_cron_schedule() {
        assert!(validate_cron_schedule("* * * * *").is_ok());
        assert!(validate_cron_schedule("0 2 * * 0").is_ok());
        assert!(validate_cron_schedule("bad schedule").is_err());
        assert!(validate_cron_schedule("* * * * * $(evil)").is_err());
    }

    #[tokio::test]
    async fn test_schedule_timers_list() {
        let result = schedule_timers_list().await;
        if let Ok(val) = result {
            assert!(val.is_array() || val.is_object());
        }
    }

    #[test]
    fn test_validate_cron_schedule_6_fields() {
        // 6-field (seconds field) should also be accepted
        assert!(validate_cron_schedule("0 * * * * *").is_ok());
    }

    #[test]
    fn test_validate_cron_schedule_too_few_fields() {
        assert!(validate_cron_schedule("* * * *").is_err());
        assert!(validate_cron_schedule("").is_err());
    }

    #[test]
    fn test_validate_cron_command_empty() {
        assert!(validate_cron_command("").is_err());
    }

    #[test]
    fn test_validate_cron_command_too_long() {
        let long = "a".repeat(1025);
        assert!(validate_cron_command(&long).is_err());
    }

    #[test]
    fn test_validate_cron_command_valid() {
        assert!(validate_cron_command("/usr/bin/backup.sh").is_ok());
        assert!(validate_cron_command("echo hello").is_ok());
    }

    #[tokio::test]
    async fn test_schedule_cron_add_invalid_schedule() {
        let result = schedule_cron_add("root", "not-a-schedule", "/usr/bin/true").await;
        assert!(result.is_err(), "Invalid cron schedule must be rejected");
    }

    #[tokio::test]
    async fn test_schedule_cron_add_metachar_schedule_rejected() {
        let result = schedule_cron_add("root", "* * * * *; rm -rf /", "/usr/bin/true").await;
        assert!(result.is_err(), "Shell metacharacters in schedule must be rejected");
    }

    #[tokio::test]
    async fn test_schedule_cron_add_empty_command_rejected() {
        let result = schedule_cron_add("root", "* * * * *", "").await;
        assert!(result.is_err(), "Empty command must be rejected");
    }

    #[tokio::test]
    async fn test_schedule_cron_remove_empty_pattern_rejected() {
        let result = schedule_cron_remove("root", "").await;
        assert!(result.is_err(), "Empty pattern must be rejected");
    }

    #[tokio::test]
    async fn test_schedule_cron_list_has_required_fields() {
        let result = schedule_cron_list().await.unwrap();
        let arr = result.as_array().unwrap();
        for entry in arr {
            assert!(entry.get("schedule").is_some(), "Each entry needs schedule field");
            assert!(entry.get("command").is_some(), "Each entry needs command field");
            assert!(entry.get("source").is_some(), "Each entry needs source field");
        }
    }

    #[test]
    fn test_parse_crontab_content_system_format() {
        let content = "# comment\n0 5 * * 1  root  /usr/bin/backup.sh\n";
        let entries = parse_crontab_content(content, "/etc/crontab");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["schedule"], "0 5 * * 1");
        assert_eq!(entries[0]["command"], "/usr/bin/backup.sh");
    }

    #[test]
    fn test_parse_crontab_content_user_format() {
        let content = "0 3 * * *  /home/user/backup.sh\n";
        let entries = parse_crontab_content(content, "/var/spool/cron/crontabs/user");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["schedule"], "0 3 * * *");
    }
}
