use serde_json::Value;
use std::path::{Path, PathBuf};

/// Resolve the home directory for a user from /etc/passwd.
fn home_dir_for_user(username: &str) -> anyhow::Result<PathBuf> {
    let content = std::fs::read_to_string("/etc/passwd")
        .map_err(|e| anyhow::anyhow!("Cannot read /etc/passwd: {}", e))?;
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 6 && fields[0] == username {
            return Ok(PathBuf::from(fields[5]));
        }
    }
    anyhow::bail!("User '{}' not found in /etc/passwd", username)
}

fn validate_username(name: &str) -> anyhow::Result<()> {
    if name.is_empty() || name.len() > 64 {
        anyhow::bail!("Invalid username length");
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
        anyhow::bail!("Username contains invalid characters: {}", name);
    }
    Ok(())
}

/// List all local users from /etc/passwd.
pub async fn identity_users() -> anyhow::Result<Value> {
    let content = tokio::fs::read_to_string("/etc/passwd").await
        .map_err(|e| anyhow::anyhow!("Cannot read /etc/passwd: {}", e))?;
    let users: Vec<Value> = content.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 7 { return None; }
            Some(serde_json::json!({
                "username": f[0],
                "uid": f[2].parse::<u32>().ok(),
                "gid": f[3].parse::<u32>().ok(),
                "gecos": f[4],
                "home": f[5],
                "shell": f[6],
            }))
        })
        .collect();
    Ok(serde_json::json!(users))
}

/// List all local groups from /etc/group.
pub async fn identity_groups() -> anyhow::Result<Value> {
    let content = tokio::fs::read_to_string("/etc/group").await
        .map_err(|e| anyhow::anyhow!("Cannot read /etc/group: {}", e))?;
    let groups: Vec<Value> = content.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 4 { return None; }
            let members: Vec<&str> = f[3].split(',').filter(|m| !m.is_empty()).collect();
            Some(serde_json::json!({
                "name": f[0],
                "gid": f[2].parse::<u32>().ok(),
                "members": members,
            }))
        })
        .collect();
    Ok(serde_json::json!(groups))
}

/// Parse /etc/sudoers and drop-in files to map privilege escalation paths.
pub async fn identity_sudoers() -> anyhow::Result<Value> {
    let mut entries = Vec::new();

    async fn parse_sudoers_file(path: &Path, entries: &mut Vec<Value>) {
        if let Ok(content) = tokio::fs::read_to_string(path).await {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('#') || trimmed.starts_with("Defaults") || trimmed.is_empty() {
                    continue;
                }
                // Include any non-comment, non-defaults line (user/group rules)
                entries.push(serde_json::json!({
                    "source": path.display().to_string(),
                    "rule": trimmed,
                }));
            }
        }
    }

    parse_sudoers_file(Path::new("/etc/sudoers"), &mut entries).await;

    if let Ok(mut dir) = tokio::fs::read_dir("/etc/sudoers.d").await {
        while let Ok(Some(entry)) = dir.next_entry().await {
            parse_sudoers_file(&entry.path(), &mut entries).await;
        }
    }

    Ok(serde_json::json!(entries))
}

/// List authorized SSH public keys for a user.
pub async fn identity_ssh_keys_list(username: &str) -> anyhow::Result<Value> {
    validate_username(username)?;
    let home = home_dir_for_user(username)?;
    let auth_keys = home.join(".ssh/authorized_keys");
    let content = tokio::fs::read_to_string(&auth_keys).await
        .map_err(|e| anyhow::anyhow!("Cannot read authorized_keys for {}: {}", username, e))?;
    let keys: Vec<Value> = content.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .enumerate()
        .map(|(i, l)| {
            let parts: Vec<&str> = l.splitn(3, ' ').collect();
            serde_json::json!({
                "index": i,
                "type": parts.first().copied().unwrap_or(""),
                "comment": parts.get(2).copied().unwrap_or(""),
                "key": l,
            })
        })
        .collect();
    Ok(serde_json::json!(keys))
}

/// Add an SSH public key to a user's authorized_keys.
pub async fn identity_ssh_keys_add(username: &str, key: &str) -> anyhow::Result<Value> {
    validate_username(username)?;
    // Validate key format: must start with a known key type
    if !["ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
         "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"]
        .iter().any(|t| key.starts_with(t)) {
        anyhow::bail!("Key does not start with a recognized SSH key type");
    }
    let home = home_dir_for_user(username)?;
    let ssh_dir = home.join(".ssh");
    tokio::fs::create_dir_all(&ssh_dir).await.ok();
    let auth_keys = ssh_dir.join("authorized_keys");

    // Append key with trailing newline
    let mut current = tokio::fs::read_to_string(&auth_keys).await.unwrap_or_default();
    if !current.ends_with('\n') && !current.is_empty() {
        current.push('\n');
    }
    current.push_str(key);
    current.push('\n');
    tokio::fs::write(&auth_keys, &current).await
        .map_err(|e| anyhow::anyhow!("Failed to write authorized_keys: {}", e))?;
    Ok(serde_json::json!({"username": username, "action": "ssh-key-add", "status": "ok"}))
}

/// Remove a specific SSH public key by matching its comment or full key text.
pub async fn identity_ssh_keys_remove(username: &str, key_identifier: &str) -> anyhow::Result<Value> {
    validate_username(username)?;
    if key_identifier.is_empty() {
        anyhow::bail!("key_identifier cannot be empty");
    }
    let home = home_dir_for_user(username)?;
    let auth_keys = home.join(".ssh/authorized_keys");
    let content = tokio::fs::read_to_string(&auth_keys).await
        .map_err(|e| anyhow::anyhow!("Cannot read authorized_keys: {}", e))?;
    let before_count = content.lines().filter(|l| !l.trim().is_empty()).count();
    let filtered: String = content.lines()
        .filter(|l| !l.contains(key_identifier))
        .map(|l| format!("{}\n", l))
        .collect();
    let after_count = filtered.lines().filter(|l| !l.trim().is_empty()).count();
    tokio::fs::write(&auth_keys, &filtered).await
        .map_err(|e| anyhow::anyhow!("Failed to write authorized_keys: {}", e))?;
    Ok(serde_json::json!({
        "username": username,
        "keys_removed": before_count - after_count,
        "status": "ok"
    }))
}

/// Lock a user account using passwd -l.
pub async fn identity_user_lock(username: &str) -> anyhow::Result<Value> {
    validate_username(username)?;
    let username_owned = username.to_string();
    let output = tokio::process::Command::new("passwd")
        .args(["-l", &username_owned])
        .output().await
        .map_err(|e| anyhow::anyhow!("passwd -l failed: {}", e))?;
    if output.status.success() {
        Ok(serde_json::json!({"username": username, "action": "lock", "status": "ok"}))
    } else {
        anyhow::bail!("passwd -l failed: {}", String::from_utf8_lossy(&output.stderr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_identity_users() {
        let result = identity_users().await.unwrap();
        let arr = result.as_array().unwrap();
        assert!(!arr.is_empty(), "Should have at least root");
        assert!(arr[0].get("username").is_some());
        assert!(arr[0].get("uid").is_some());
    }

    #[tokio::test]
    async fn test_identity_groups() {
        let result = identity_groups().await.unwrap();
        let arr = result.as_array().unwrap();
        assert!(!arr.is_empty());
        assert!(arr[0].get("name").is_some());
    }

    #[tokio::test]
    async fn test_validate_username_invalid() {
        assert!(validate_username("user;bad").is_err());
        assert!(validate_username("").is_err());
        assert!(validate_username("user name").is_err());
    }

    #[tokio::test]
    async fn test_ssh_key_add_invalid_type() {
        let result = identity_ssh_keys_add("root", "not-a-key").await;
        assert!(result.is_err(), "Non-SSH key should be rejected");
    }

    #[test]
    fn test_validate_username_valid() {
        assert!(validate_username("root").is_ok());
        assert!(validate_username("john.doe").is_ok());
        assert!(validate_username("service-account").is_ok());
        assert!(validate_username("user_123").is_ok());
    }

    #[test]
    fn test_validate_username_too_long() {
        let long = "a".repeat(65);
        assert!(validate_username(&long).is_err());
    }

    #[tokio::test]
    async fn test_ssh_key_add_invalid_username() {
        let result = identity_ssh_keys_add("bad;user", "ssh-ed25519 AAAA comment").await;
        assert!(result.is_err(), "Invalid username must be rejected before key write");
    }

    #[tokio::test]
    async fn test_ssh_key_remove_empty_identifier_rejected() {
        let result = identity_ssh_keys_remove("root", "").await;
        assert!(result.is_err(), "Empty key identifier must be rejected");
    }

    #[tokio::test]
    async fn test_ssh_key_remove_invalid_username_rejected() {
        let result = identity_ssh_keys_remove("bad;user", "some-comment").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_user_lock_invalid_username_rejected() {
        let result = identity_user_lock("bad;name").await;
        assert!(result.is_err(), "Injection in username must be rejected");
    }

    #[tokio::test]
    async fn test_identity_sudoers_returns_array() {
        let result = identity_sudoers().await.unwrap();
        assert!(result.is_array(), "Sudoers should return an array");
        // Each entry should have source and rule fields
        if let Some(first) = result.as_array().and_then(|a| a.first()) {
            assert!(first.get("source").is_some());
            assert!(first.get("rule").is_some());
        }
    }

    #[tokio::test]
    async fn test_identity_ssh_keys_list_invalid_username() {
        let result = identity_ssh_keys_list("bad;user").await;
        assert!(result.is_err(), "Invalid username must be rejected");
    }

    #[tokio::test]
    async fn test_identity_users_has_required_fields() {
        let result = identity_users().await.unwrap();
        let arr = result.as_array().unwrap();
        for user in arr {
            assert!(user.get("username").is_some(), "Every user must have username");
            assert!(user.get("uid").is_some(), "Every user must have uid");
            assert!(user.get("home").is_some(), "Every user must have home");
        }
    }
}
