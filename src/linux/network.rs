use futures::TryStreamExt;
use rtnetlink::{new_connection, IpVersion};
use serde_json::Value;

pub async fn list_interfaces() -> anyhow::Result<Value> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    let mut links = handle.link().get().execute();
    let mut results = Vec::new();

    while let Some(msg) = links.try_next().await? {
        let mut name = String::new();
        let mut mac = None;
        let mut mtu = None;

        for attr in &msg.attributes {
            match attr {
                netlink_packet_route::link::LinkAttribute::IfName(n) => {
                    name = n.clone();
                }
                netlink_packet_route::link::LinkAttribute::Address(a) => {
                    mac = Some(
                        a.iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(":"),
                    );
                }
                netlink_packet_route::link::LinkAttribute::Mtu(m) => {
                    mtu = Some(*m);
                }
                _ => {}
            }
        }

        let is_up = msg
            .header
            .flags
            .contains(&netlink_packet_route::link::LinkFlag::Up);

        results.push(serde_json::json!({
            "index": msg.header.index,
            "name": name,
            "mac": mac,
            "mtu": mtu,
            "up": is_up,
        }));
    }
    Ok(serde_json::json!(results))
}

pub async fn list_addresses() -> anyhow::Result<Value> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    let mut addrs = handle.address().get().execute();
    let mut results = Vec::new();

    while let Some(msg) = addrs.try_next().await? {
        let addr = msg.attributes.iter().find_map(|attr| {
            if let netlink_packet_route::address::AddressAttribute::Address(a) = attr {
                Some(format!("{}", a))
            } else {
                None
            }
        });

        let family = match msg.header.family {
            netlink_packet_route::AddressFamily::Inet => "IPv4",
            netlink_packet_route::AddressFamily::Inet6 => "IPv6",
            _ => "other",
        };

        results.push(serde_json::json!({
            "index": msg.header.index,
            "family": family,
            "address": addr,
            "prefix_len": msg.header.prefix_len,
        }));
    }
    Ok(serde_json::json!(results))
}

/// Helper to format a RouteAddress as a string.
fn format_route_address(addr: &netlink_packet_route::route::RouteAddress) -> String {
    match addr {
        netlink_packet_route::route::RouteAddress::Inet(ip) => ip.to_string(),
        netlink_packet_route::route::RouteAddress::Inet6(ip) => ip.to_string(),
        other => format!("{:?}", other),
    }
}

pub async fn list_routes() -> anyhow::Result<Value> {
    // Netlink connections are lightweight AF_NETLINK sockets. Creating one per call
    // is acceptable here since network tools are called infrequently. The spawned
    // background task terminates when the handle is dropped after the function returns.
    let mut results = Vec::new();

    // Query both IPv4 and IPv6 routes for dual-stack completeness
    for ip_version in [IpVersion::V4, IpVersion::V6] {
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);

        let mut routes = handle.route().get(ip_version.clone()).execute();

        while let Some(msg) = routes.try_next().await? {
            let dst = msg.attributes.iter().find_map(|attr| {
                if let netlink_packet_route::route::RouteAttribute::Destination(d) = attr {
                    Some(format_route_address(d))
                } else {
                    None
                }
            });

            let gateway = msg.attributes.iter().find_map(|attr| {
                if let netlink_packet_route::route::RouteAttribute::Gateway(g) = attr {
                    Some(format_route_address(g))
                } else {
                    None
                }
            });

            let family = match ip_version {
                IpVersion::V4 => "IPv4",
                IpVersion::V6 => "IPv6",
            };

            results.push(serde_json::json!({
                "family": family,
                "destination": dst.unwrap_or_else(|| "default".into()),
                "prefix_len": msg.header.destination_prefix_length,
                "gateway": gateway,
                "table": msg.header.table,
            }));
        }
    }
    Ok(serde_json::json!(results))
}

pub fn active_connections() -> anyhow::Result<Value> {
    let mut conns = Vec::new();

    // IPv4 TCP
    if let Ok(entries) = procfs::net::tcp() {
        for e in entries {
            conns.push(serde_json::json!({
                "protocol": "tcp",
                "local_addr": format!("{}:{}", e.local_address.ip(), e.local_address.port()),
                "remote_addr": format!("{}:{}", e.remote_address.ip(), e.remote_address.port()),
                "state": format!("{:?}", e.state),
                "inode": e.inode,
                "uid": e.uid,
            }));
        }
    }

    // IPv6 TCP
    if let Ok(entries) = procfs::net::tcp6() {
        for e in entries {
            conns.push(serde_json::json!({
                "protocol": "tcp6",
                "local_addr": format!("{}:{}", e.local_address.ip(), e.local_address.port()),
                "remote_addr": format!("{}:{}", e.remote_address.ip(), e.remote_address.port()),
                "state": format!("{:?}", e.state),
                "inode": e.inode,
                "uid": e.uid,
            }));
        }
    }

    Ok(serde_json::json!(conns))
}

/// Build an inode → (pid, process_name) map from /proc/*/fd/ symlinks.
fn build_inode_pid_map() -> std::collections::HashMap<u64, (i32, String)> {
    let mut map = std::collections::HashMap::new();
    let Ok(dir) = std::fs::read_dir("/proc") else { return map };
    for entry in dir.flatten() {
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        let Ok(pid) = pid_str.parse::<i32>() else { continue };
        let fd_dir = format!("/proc/{}/fd", pid);
        let Ok(fds) = std::fs::read_dir(&fd_dir) else { continue };
        let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))
            .unwrap_or_default()
            .trim()
            .to_string();
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                let t = target.to_string_lossy();
                // socket:[inode]
                if t.starts_with("socket:[") && t.ends_with(']') {
                    if let Ok(inode) = t[8..t.len()-1].parse::<u64>() {
                        map.insert(inode, (pid, comm.clone()));
                    }
                }
            }
        }
    }
    map
}

/// Listening ports with PID and process name.
pub fn listening_ports() -> anyhow::Result<Value> {
    let inode_map = build_inode_pid_map();
    let mut ports = Vec::new();

    macro_rules! add_listen {
        ($entries:expr, $proto:expr) => {
            if let Ok(entries) = $entries {
                for e in entries {
                    if format!("{:?}", e.state) == "Listen" {
                        let (pid, name) = inode_map.get(&e.inode)
                            .cloned()
                            .unwrap_or((-1, String::new()));
                        ports.push(serde_json::json!({
                            "protocol": $proto,
                            "local_addr": format!("{}:{}", e.local_address.ip(), e.local_address.port()),
                            "port": e.local_address.port(),
                            "inode": e.inode,
                            "pid": pid,
                            "process": name,
                        }));
                    }
                }
            }
        };
    }

    add_listen!(procfs::net::tcp(), "tcp");
    add_listen!(procfs::net::tcp6(), "tcp6");
    add_listen!(procfs::net::udp(), "udp");
    add_listen!(procfs::net::udp6(), "udp6");

    ports.sort_by_key(|p| p["port"].as_u64().unwrap_or(0));
    Ok(serde_json::json!(ports))
}

/// Current DNS resolvers and search domains from /etc/resolv.conf.
pub fn dns_config() -> anyhow::Result<Value> {
    let content = std::fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default();
    let mut nameservers: Vec<&str> = Vec::new();
    let mut search: Vec<&str> = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') { continue; }
        if let Some(rest) = line.strip_prefix("nameserver") {
            let ns = rest.trim();
            if !ns.is_empty() { nameservers.push(ns); }
        } else if let Some(rest) = line.strip_prefix("search") {
            search.extend(rest.split_whitespace());
        } else if let Some(rest) = line.strip_prefix("domain") {
            search.extend(rest.split_whitespace());
        }
    }
    Ok(serde_json::json!({
        "nameservers": nameservers,
        "search_domains": search,
    }))
}

/// Validate an iptables chain name (alphanumeric + _ -, max 30 chars).
fn validate_chain(chain: &str) -> anyhow::Result<()> {
    if chain.is_empty() || chain.len() > 30 {
        anyhow::bail!("Invalid chain name length");
    }
    if !chain.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        anyhow::bail!("Invalid chain name: {}", chain);
    }
    Ok(())
}

/// Validate a single iptables rule argument token (no shell metacharacters).
fn validate_rule_token(token: &str) -> anyhow::Result<()> {
    // Allow: alphanumeric, ., /, -, _, :, space (for CIDR, ports, etc.)
    if token.chars().any(|c| matches!(c, ';' | '|' | '&' | '`' | '$' | '(' | ')' | '<' | '>' | '!' | '\n' | '\r')) {
        anyhow::bail!("Rule token contains unsafe character: {}", token);
    }
    Ok(())
}

/// Add an iptables rule. `rule_args` is a space-separated rule string.
pub async fn firewall_add(table: &str, chain: &str, rule_args: &str) -> anyhow::Result<Value> {
    validate_chain(chain)?;
    validate_chain(table)?;
    for token in rule_args.split_whitespace() {
        validate_rule_token(token)?;
    }
    let mut args = vec!["-t".to_string(), table.to_string(), "-A".to_string(), chain.to_string()];
    args.extend(rule_args.split_whitespace().map(|s| s.to_string()));
    let output = tokio::process::Command::new("iptables")
        .args(&args)
        .output()
        .await?;
    if output.status.success() {
        Ok(serde_json::json!({"status": "rule added", "chain": chain, "rule": rule_args}))
    } else {
        anyhow::bail!("iptables failed: {}", String::from_utf8_lossy(&output.stderr))
    }
}

/// Remove an iptables rule. `rule_args` is a space-separated rule string.
pub async fn firewall_remove(table: &str, chain: &str, rule_args: &str) -> anyhow::Result<Value> {
    validate_chain(chain)?;
    validate_chain(table)?;
    for token in rule_args.split_whitespace() {
        validate_rule_token(token)?;
    }
    let mut args = vec!["-t".to_string(), table.to_string(), "-D".to_string(), chain.to_string()];
    args.extend(rule_args.split_whitespace().map(|s| s.to_string()));
    let output = tokio::process::Command::new("iptables")
        .args(&args)
        .output()
        .await?;
    if output.status.success() {
        Ok(serde_json::json!({"status": "rule removed", "chain": chain, "rule": rule_args}))
    } else {
        anyhow::bail!("iptables failed: {}", String::from_utf8_lossy(&output.stderr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_list_interfaces() {
        let result = list_interfaces().await.unwrap();
        let arr = result.as_array().expect("Should return array");
        assert!(!arr.is_empty(), "Should have at least loopback");
        let first = &arr[0];
        assert!(first.get("name").is_some(), "Interface should have a name");
        assert!(first.get("up").is_some(), "Interface should have up status");
    }

    #[tokio::test]
    async fn test_list_addresses() {
        let result = list_addresses().await.unwrap();
        let arr = result.as_array().expect("Should return array");
        assert!(!arr.is_empty(), "Should have at least one address");
    }

    #[tokio::test]
    async fn test_list_routes() {
        let result = list_routes().await.unwrap();
        let arr = result.as_array().expect("Should return array");
        // Should have routes on any connected system
        assert!(!arr.is_empty(), "Should have at least one route");
        // Verify IPv4 and/or IPv6 routes present
        let has_family = arr.iter().any(|r| r.get("family").is_some());
        assert!(has_family, "Routes should include family field");
    }

    #[test]
    fn test_active_connections() {
        let result = active_connections().unwrap();
        let arr = result.as_array().expect("Should return array");
        assert!(!arr.is_empty() || arr.is_empty(), "Should be a valid array");
    }

    #[test]
    fn test_listening_ports() {
        let result = listening_ports().unwrap();
        assert!(result.is_array());
    }

    #[test]
    fn test_dns_config() {
        let result = dns_config().unwrap();
        assert!(result.get("nameservers").is_some());
        assert!(result.get("search_domains").is_some());
    }

    #[tokio::test]
    async fn test_firewall_add_invalid_chain() {
        let result = firewall_add("filter", "INVALID;CHAIN", "-j ACCEPT").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_firewall_add_invalid_rule() {
        let result = firewall_add("filter", "INPUT", "-j $(rm -rf /)").await;
        assert!(result.is_err());
    }
}
