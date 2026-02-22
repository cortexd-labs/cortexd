use serde_json::Value;

pub async fn network_interfaces() -> anyhow::Result<Value> {
    crate::linux::network::list_interfaces().await
}

pub async fn network_addresses() -> anyhow::Result<Value> {
    crate::linux::network::list_addresses().await
}

pub async fn network_routes() -> anyhow::Result<Value> {
    crate::linux::network::list_routes().await
}

pub async fn network_connections() -> anyhow::Result<Value> {
    crate::linux::network::active_connections()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_network_interfaces() {
        let result = network_interfaces().await.unwrap();
        let arr = result.as_array().expect("Should be array");
        assert!(!arr.is_empty(), "Should have at least loopback");
    }

    #[tokio::test]
    async fn test_network_addresses() {
        let result = network_addresses().await.unwrap();
        assert!(result.is_array());
    }

    #[tokio::test]
    async fn test_network_connections() {
        let result = network_connections().await.unwrap();
        assert!(result.is_array());
    }
}
