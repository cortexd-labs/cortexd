use bollard::Docker;
use bollard::container::{ListContainersOptions, LogsOptions, RemoveContainerOptions, StatsOptions};
use futures::StreamExt;
use serde_json::Value;

fn connect_docker() -> anyhow::Result<Docker> {
    Docker::connect_with_socket_defaults()
        .map_err(|e| anyhow::anyhow!("Docker connection failed: {}", e))
}

pub async fn container_list() -> anyhow::Result<Value> {
    let docker = connect_docker()?;
    let options = ListContainersOptions::<String> {
        all: true,
        ..Default::default()
    };

    let containers = docker
        .list_containers(Some(options))
        .await
        .map_err(|e| anyhow::anyhow!("Docker list_containers failed: {}", e))?;

    let mapped: Vec<Value> = containers
        .into_iter()
        .map(|c| {
            let id = c.id.as_deref().unwrap_or("");
            let short_id = id.get(..12).unwrap_or(id);
            serde_json::json!({
                "id": short_id,
                "names": c.names,
                "image": c.image,
                "state": c.state,
                "status": c.status,
                "created": c.created,
            })
        })
        .collect();

    Ok(serde_json::json!(mapped))
}

pub async fn container_stats(id: &str) -> anyhow::Result<Value> {
    let docker = connect_docker()?;
    let stats = docker
        .stats(id, Some(StatsOptions { stream: false, ..Default::default() }))
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("No stats returned for container {}", id))?
        .map_err(|e| anyhow::anyhow!("Docker stats failed: {}", e))?;

    let cpu_delta = stats.cpu_stats.cpu_usage.total_usage
        .saturating_sub(stats.precpu_stats.cpu_usage.total_usage);
    let system_delta = stats.cpu_stats.system_cpu_usage.unwrap_or(0)
        .saturating_sub(stats.precpu_stats.system_cpu_usage.unwrap_or(0));
    let num_cpus = stats.cpu_stats.online_cpus.unwrap_or(1);
    let cpu_pct = if system_delta > 0 {
        (cpu_delta as f64 / system_delta as f64) * num_cpus as f64 * 100.0
    } else {
        0.0
    };

    Ok(serde_json::json!({
        "cpu_percent": (cpu_pct * 10.0).round() / 10.0,
        "memory_usage": stats.memory_stats.usage,
        "memory_limit": stats.memory_stats.limit,
        "network_rx_bytes": stats.networks.as_ref()
            .map(|n| n.values().map(|v| v.rx_bytes).sum::<u64>()),
        "network_tx_bytes": stats.networks.as_ref()
            .map(|n| n.values().map(|v| v.tx_bytes).sum::<u64>()),
    }))
}

pub async fn container_status(id: &str) -> anyhow::Result<Value> {
    let docker = connect_docker()?;
    let info = docker.inspect_container(id, None).await
        .map_err(|e| anyhow::anyhow!("inspect_container failed: {}", e))?;
    let state = info.state.as_ref();
    Ok(serde_json::json!({
        "id": info.id.as_deref().and_then(|s| s.get(..12)).unwrap_or(""),
        "name": info.name,
        "status": state.and_then(|s| s.status.as_ref()).map(|s| format!("{:?}", s)),
        "running": state.and_then(|s| s.running),
        "paused": state.and_then(|s| s.paused),
        "exit_code": state.and_then(|s| s.exit_code),
        "started_at": state.and_then(|s| s.started_at.as_deref()),
        "finished_at": state.and_then(|s| s.finished_at.as_deref()),
    }))
}

pub async fn container_logs(id: &str, lines: Option<usize>, since: Option<&str>) -> anyhow::Result<Value> {
    let docker = connect_docker()?;
    let tail = lines.map(|n| n.to_string()).unwrap_or_else(|| "50".to_string());
    let options = LogsOptions::<String> {
        stdout: true,
        stderr: true,
        tail,
        since: since.and_then(|s| s.parse::<i64>().ok()).unwrap_or(0),
        ..Default::default()
    };
    let mut stream = docker.logs(id, Some(options));
    let mut entries = Vec::new();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(log) => entries.push(log.to_string()),
            Err(e) => return Err(anyhow::anyhow!("container logs error: {}", e)),
        }
    }
    Ok(serde_json::json!({"id": id, "logs": entries}))
}

pub async fn container_inspect(id: &str) -> anyhow::Result<Value> {
    let docker = connect_docker()?;
    let info = docker.inspect_container(id, None).await
        .map_err(|e| anyhow::anyhow!("inspect_container failed: {}", e))?;
    Ok(serde_json::to_value(info).unwrap_or_default())
}

pub async fn container_start(id: &str) -> anyhow::Result<Value> {
    let docker = connect_docker()?;
    docker.start_container::<String>(id, None).await
        .map_err(|e| anyhow::anyhow!("start_container failed: {}", e))?;
    Ok(serde_json::json!({"id": id, "action": "start", "status": "ok"}))
}

pub async fn container_stop(id: &str) -> anyhow::Result<Value> {
    let docker = connect_docker()?;
    docker.stop_container(id, None).await
        .map_err(|e| anyhow::anyhow!("stop_container failed: {}", e))?;
    Ok(serde_json::json!({"id": id, "action": "stop", "status": "ok"}))
}

pub async fn container_restart(id: &str) -> anyhow::Result<Value> {
    let docker = connect_docker()?;
    docker.restart_container(id, None).await
        .map_err(|e| anyhow::anyhow!("restart_container failed: {}", e))?;
    Ok(serde_json::json!({"id": id, "action": "restart", "status": "ok"}))
}

pub async fn container_remove(id: &str, force: bool) -> anyhow::Result<Value> {
    let docker = connect_docker()?;
    let options = RemoveContainerOptions { force, ..Default::default() };
    docker.remove_container(id, Some(options)).await
        .map_err(|e| anyhow::anyhow!("remove_container failed: {}", e))?;
    Ok(serde_json::json!({"id": id, "action": "remove", "status": "ok"}))
}

// Docker tests require a running Docker daemon, so they are gated.
// When Docker is unavailable, all operations should return a clean error (not panic).
// When Docker IS available, container operations against unknown IDs should also error.
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_container_list_returns_array_or_errors_cleanly() {
        let result = container_list().await;
        if let Ok(val) = result {
            assert!(val.is_array());
        }
        // Err is acceptable when Docker is not running
    }

    #[tokio::test]
    async fn test_container_stats_unknown_id() {
        let result = container_stats("nonexistent-container-id").await;
        assert!(result.is_err(), "Should fail for unknown container ID");
    }

    #[tokio::test]
    async fn test_container_status_unknown_id() {
        let result = container_status("nonexistent-container-id").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_container_logs_unknown_id() {
        let result = container_logs("nonexistent-container-id", Some(10), None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_container_inspect_unknown_id() {
        let result = container_inspect("nonexistent-container-id").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_container_start_unknown_id() {
        let result = container_start("nonexistent-container-id").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_container_stop_unknown_id() {
        let result = container_stop("nonexistent-container-id").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_container_restart_unknown_id() {
        let result = container_restart("nonexistent-container-id").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_container_remove_unknown_id() {
        let result = container_remove("nonexistent-container-id", false).await;
        assert!(result.is_err());
    }
}
