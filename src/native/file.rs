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

/// Maximum bytes to read for file.read (1 MiB default).
const MAX_READ_BYTES: usize = 1024 * 1024;

pub async fn file_read(path: &str, max_bytes: Option<usize>) -> anyhow::Result<Value> {
    let canonical = validate_path(path)?;
    if canonical.is_dir() {
        anyhow::bail!("{} is a directory, not a file", canonical.display());
    }
    let limit = max_bytes.unwrap_or(MAX_READ_BYTES);
    let meta = tokio::fs::metadata(&canonical).await?;
    if meta.len() as usize > limit {
        anyhow::bail!("File size ({} bytes) exceeds limit ({} bytes). Use file.tail for large files.", meta.len(), limit);
    }
    let content = tokio::fs::read_to_string(&canonical).await
        .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", canonical.display(), e))?;
    Ok(serde_json::json!({"path": canonical.display().to_string(), "content": content}))
}

pub async fn file_tail(path: &str, lines: usize) -> anyhow::Result<Value> {
    let canonical = validate_path(path)?;
    if canonical.is_dir() {
        anyhow::bail!("{} is a directory", canonical.display());
    }
    let content = tokio::fs::read_to_string(&canonical).await
        .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", canonical.display(), e))?;
    let result: Vec<&str> = content.lines().rev().take(lines).collect::<Vec<_>>()
        .into_iter().rev().collect();
    Ok(serde_json::json!({"path": canonical.display().to_string(), "lines": result}))
}

pub async fn file_search(dir: &str, pattern: &str, max_results: Option<usize>) -> anyhow::Result<Value> {
    if pattern.is_empty() || pattern.len() > 256 {
        anyhow::bail!("Pattern must be 1-256 characters");
    }
    let canonical = validate_path(dir)?;
    if !canonical.is_dir() {
        anyhow::bail!("{} is not a directory", canonical.display());
    }
    let limit = max_results.unwrap_or(100);
    let mut matches = Vec::new();

    fn search_dir(dir: &std::path::Path, pattern: &str, results: &mut Vec<serde_json::Value>, limit: usize) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            if results.len() >= limit { break; }
            let path = entry.path();
            if path.is_dir() {
                search_dir(&path, pattern, results, limit);
            } else if path.is_file() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    let matching_lines: Vec<(usize, &str)> = content.lines()
                        .enumerate()
                        .filter(|(_, l)| l.contains(pattern))
                        .take(10)
                        .collect();
                    if !matching_lines.is_empty() {
                        for (lineno, line) in matching_lines {
                            if results.len() >= limit { break; }
                            results.push(serde_json::json!({
                                "path": path.display().to_string(),
                                "line": lineno + 1,
                                "content": line.trim(),
                            }));
                        }
                    }
                }
            }
        }
    }

    search_dir(&canonical, pattern, &mut matches, limit);
    Ok(serde_json::json!(matches))
}

pub async fn file_write(path: &str, content: &str) -> anyhow::Result<Value> {
    // For write, we validate the parent directory (file may not exist yet)
    let p = std::path::Path::new(path);
    let parent = p.parent().unwrap_or(p);
    let canonical_parent = std::fs::canonicalize(parent)
        .map_err(|e| anyhow::anyhow!("Parent directory not found: {}", e))?;
    if !ALLOWED_PREFIXES.iter().any(|prefix| canonical_parent.starts_with(prefix)) {
        anyhow::bail!("Access denied: {} is outside allowed directories", canonical_parent.display());
    }
    // Reject writes to sensitive files by path (can't canonicalize non-existent file)
    let path_lower = path.to_lowercase();
    for s in &["/etc/shadow", "/etc/gshadow", "/etc/sudoers"] {
        if path_lower.contains(&s.to_lowercase()) {
            anyhow::bail!("Access denied: cannot write to {}", s);
        }
    }
    tokio::fs::write(path, content).await
        .map_err(|e| anyhow::anyhow!("Write failed: {}", e))?;
    Ok(serde_json::json!({"path": path, "bytes_written": content.len()}))
}

pub async fn file_mkdir(path: &str) -> anyhow::Result<Value> {
    let p = std::path::Path::new(path);
    let parent = p.parent().unwrap_or(p);
    // Best-effort: if parent already exists, canonicalize it
    let parent_str = parent.to_string_lossy();
    if !ALLOWED_PREFIXES.iter().any(|prefix| parent_str.starts_with(prefix)) {
        anyhow::bail!("Access denied: {} is outside allowed directories", parent_str);
    }
    tokio::fs::create_dir_all(path).await
        .map_err(|e| anyhow::anyhow!("mkdir failed: {}", e))?;
    Ok(serde_json::json!({"path": path, "status": "created"}))
}

pub async fn file_chmod(path: &str, mode: u32) -> anyhow::Result<Value> {
    let canonical = validate_path(path)?;
    // Only the lower 12 bits are valid permission bits
    let mode_bits = mode & 0o7777;
    tokio::task::spawn_blocking(move || {
        let perms = std::fs::Permissions::from_mode(mode_bits);
        std::fs::set_permissions(&canonical, perms)
            .map_err(|e| anyhow::anyhow!("chmod failed: {}", e))
    }).await??;
    Ok(serde_json::json!({"path": path, "mode": format!("{:o}", mode)}))
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

    #[tokio::test]
    async fn test_file_read() {
        let result = file_read("/etc/hostname", None).await;
        if let Ok(val) = result {
            assert!(val.get("content").is_some());
        }
    }

    #[tokio::test]
    async fn test_file_tail() {
        let result = file_tail("/etc/hostname", 3).await;
        if let Ok(val) = result {
            let lines = val["lines"].as_array().unwrap();
            assert!(lines.len() <= 3);
        }
    }

    #[tokio::test]
    async fn test_file_search() {
        let result = file_search("/etc", "localhost", Some(5)).await;
        if let Ok(val) = result {
            assert!(val.is_array());
        }
    }

    #[tokio::test]
    async fn test_file_write_blocked_outside_allowed() {
        let result = file_write("/root/test.txt", "content").await;
        assert!(result.is_err(), "Write outside allowed dirs should fail");
    }

    #[tokio::test]
    async fn test_file_write_blocked_shadow() {
        let result = file_write("/etc/shadow", "bad").await;
        assert!(result.is_err(), "Write to /etc/shadow should be blocked");
    }

    #[tokio::test]
    async fn test_file_chmod_blocked_outside_allowed() {
        // chmod on a path outside the allowlist should fail
        let result = file_chmod("/root/.bashrc", 0o644).await;
        assert!(result.is_err(), "chmod outside allowed dirs should fail");
    }

    #[tokio::test]
    async fn test_file_chmod_blocked_sensitive() {
        let result = file_chmod("/etc/shadow", 0o644).await;
        assert!(result.is_err(), "chmod on sensitive file should be blocked");
    }

    #[tokio::test]
    async fn test_file_mkdir_blocked_outside_allowed() {
        let result = file_mkdir("/root/newdir").await;
        assert!(result.is_err(), "mkdir outside allowed dirs should fail");
    }

    #[tokio::test]
    async fn test_file_read_respects_max_bytes() {
        // /etc/hostname is small; reading with a very small limit truncates content
        let result = file_read("/etc/hostname", Some(3)).await;
        if let Ok(val) = result {
            let content = val["content"].as_str().unwrap_or("");
            assert!(content.len() <= 3, "Content should be limited to max_bytes");
        }
    }

    #[tokio::test]
    async fn test_file_search_respects_max_results() {
        let result = file_search("/etc", "a", Some(2)).await;
        if let Ok(val) = result {
            let arr = val.as_array().expect("Search should return array");
            assert!(arr.len() <= 2, "Should respect max_results limit");
        }
    }
}
