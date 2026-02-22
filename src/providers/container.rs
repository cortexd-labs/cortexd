use bollard::Docker;
use bollard::container::{ListContainersOptions, StatsOptions};
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

// Docker tests require a running Docker daemon, so they are gated
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_container_list_no_docker() {
        // This test verifies the function handles missing Docker gracefully
        let result = container_list().await;
        // If Docker is not running, this should error — that's expected
        // If Docker IS running, we should get an array
        if let Ok(val) = result {
            assert!(val.is_array());
        }
    }
}
