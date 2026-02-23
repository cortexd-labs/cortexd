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

pub fn network_ports() -> anyhow::Result<Value> {
    crate::linux::network::listening_ports()
}

pub fn network_dns() -> anyhow::Result<Value> {
    crate::linux::network::dns_config()
}

pub async fn network_firewall_add(table: &str, chain: &str, rule: &str) -> anyhow::Result<Value> {
    crate::linux::network::firewall_add(table, chain, rule).await
}

pub async fn network_firewall_remove(table: &str, chain: &str, rule: &str) -> anyhow::Result<Value> {
    crate::linux::network::firewall_remove(table, chain, rule).await
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

    #[tokio::test]
    async fn test_network_routes() {
        let result = network_routes().await.unwrap();
        let arr = result.as_array().expect("Routes should be an array");
        // Any Linux system should have at least a loopback route
        let has_family = arr.iter().any(|r| r.get("family").is_some());
        assert!(has_family || arr.is_empty(), "Routes should have family field");
    }

    #[test]
    fn test_network_ports_returns_array() {
        let result = network_ports().unwrap();
        assert!(result.is_array(), "Ports should be an array");
    }

    #[test]
    fn test_network_dns_has_required_keys() {
        let result = network_dns().unwrap();
        assert!(result.get("nameservers").is_some(), "DNS config should have nameservers");
        assert!(result.get("search_domains").is_some(), "DNS config should have search_domains");
    }

    #[tokio::test]
    async fn test_network_firewall_add_invalid_chain() {
        let result = network_firewall_add("filter", "INPUT;DROP", "-j ACCEPT").await;
        assert!(result.is_err(), "Injection in chain name must be rejected");
    }

    #[tokio::test]
    async fn test_network_firewall_add_invalid_rule() {
        let result = network_firewall_add("filter", "INPUT", "$(rm -rf /)").await;
        assert!(result.is_err(), "Injection in rule must be rejected");
    }

    #[tokio::test]
    async fn test_network_firewall_remove_invalid_chain() {
        let result = network_firewall_remove("filter", "FORWARD`evil`", "-j DROP").await;
        assert!(result.is_err());
    }
}
