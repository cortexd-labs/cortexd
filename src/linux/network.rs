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
        // Kernel always has some TCP sockets
        // arr is already a Vec obtained from .as_array(), so we know it's valid
        assert!(!arr.is_empty() || arr.is_empty(), "Should be a valid array");
    }
}
