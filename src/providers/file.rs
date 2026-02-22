use serde_json::Value;
use std::os::unix::fs::PermissionsExt;

/// Allowed base directories for file operations.
/// Restricts MCP clients from reading arbitrary paths like /etc/shadow.
const ALLOWED_PREFIXES: &[&str] = &[
    "/var/log",
    "/var/lib",
    "/etc",
    "/tmp",
    "/home",
    "/opt",
    "/srv",
    "/usr/share",
    "/proc",
    "/sys/class",
];

/// Validate and canonicalize a path, ensuring it falls within allowed prefixes.
fn validate_path(path: &str) -> anyhow::Result<std::path::PathBuf> {
    let canonical = std::fs::canonicalize(path)
        .map_err(|e| anyhow::anyhow!("Path resolution failed for {}: {}", path, e))?;

    // Reject sensitive files explicitly, even within allowed directories
    let sensitive = [
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
    ];
    let canonical_str = canonical.to_string_lossy();
    for s in &sensitive {
        if canonical_str.as_ref() == *s {
            anyhow::bail!("Access denied: {} is a sensitive system file", s);
        }
    }

    // Check that path falls within an allowed prefix
    if !ALLOWED_PREFIXES.iter().any(|prefix| canonical.starts_with(prefix)) {
        anyhow::bail!(
            "Access denied: {} is outside allowed directories ({:?})",
            canonical.display(),
            ALLOWED_PREFIXES
        );
    }

    Ok(canonical)
}

pub async fn file_info(path: &str) -> anyhow::Result<Value> {
    let canonical = validate_path(path)?;
    let meta = tokio::fs::symlink_metadata(&canonical).await
        .map_err(|e| anyhow::anyhow!("Failed to stat {}: {}", canonical.display(), e))?;

    Ok(serde_json::json!({
        "path": canonical.display().to_string(),
        "size_bytes": meta.len(),
        "is_dir": meta.is_dir(),
        "is_file": meta.is_file(),
        "is_symlink": meta.is_symlink(),
        "modified": meta.modified().ok().map(|t|
            t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        ),
        "permissions": format!("{:o}", meta.permissions().mode()),
    }))
}

pub async fn file_list(path: &str) -> anyhow::Result<Value> {
    let canonical = validate_path(path)?;
    if !canonical.is_dir() {
        anyhow::bail!("{} is not a directory", canonical.display());
    }

    let mut entries = Vec::new();
    let mut dir = tokio::fs::read_dir(&canonical).await
        .map_err(|e| anyhow::anyhow!("Failed to read directory {}: {}", canonical.display(), e))?;

    while let Some(entry) = dir.next_entry().await? {
        let meta = entry.metadata().await.ok();
        entries.push(serde_json::json!({
            "name": entry.file_name().to_string_lossy(),
            "is_dir": meta.as_ref().map(|m| m.is_dir()).unwrap_or(false),
            "size_bytes": meta.as_ref().map(|m| m.len()).unwrap_or(0),
        }));
    }

    Ok(serde_json::json!(entries))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_file_info() {
        let result = file_info("/etc/hostname").await;
        if let Ok(val) = result {
            assert!(val.get("path").is_some());
            assert!(val.get("size_bytes").is_some());
            assert_eq!(val["is_file"].as_bool().unwrap(), true);
        }
    }

    #[tokio::test]
    async fn test_file_info_directory() {
        let result = file_info("/tmp").await.unwrap();
        assert_eq!(result["is_dir"].as_bool().unwrap(), true);
    }

    #[tokio::test]
    async fn test_file_list() {
        let result = file_list("/etc").await.unwrap();
        let arr = result.as_array().expect("Should return an array");
        assert!(!arr.is_empty(), "/etc should have entries");
        let first = &arr[0];
        assert!(first.get("name").is_some());
    }

    #[tokio::test]
    async fn test_file_info_nonexistent() {
        let result = file_info("/nonexistent/path/file.txt").await;
        assert!(result.is_err(), "Nonexistent file should error");
    }

    #[tokio::test]
    async fn test_path_traversal_blocked() {
        // Attempt to access a path outside allowed directories
        let result = file_info("/root/.ssh/id_rsa").await;
        assert!(result.is_err(), "Should deny access to /root");
    }

    #[tokio::test]
    async fn test_sensitive_file_blocked() {
        let result = file_info("/etc/shadow").await;
        assert!(result.is_err(), "Should deny access to /etc/shadow");
    }
}
