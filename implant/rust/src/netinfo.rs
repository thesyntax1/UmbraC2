//! The network configuration of the host.
//!
//! The operator wants to know how the host is reachable: the interfaces it
//! has, the routes it knows, the neighbours it already talked to and the
//! resolvers it uses.  On Linux the answer comes from the kernel's own
//! tables, everywhere else from the platform's tools.

use std::fs;

/// One interface of the host.
pub struct Interface {
    pub name: String,
    pub address: String,
    pub kind: String,
}

/// The network configuration of the host.
pub struct Network {
    pub interfaces: Vec<Interface>,
    pub routes: Vec<String>,
    pub neighbours: Vec<String>,
    pub resolvers: Vec<String>,
    pub source: String,
}

/// Read the network configuration.
pub fn collect() -> Network {
    #[cfg(target_os = "linux")]
    {
        if let Some(net) = from_proc() {
            return net;
        }
    }
    from_tools()
}

/// The report of the network configuration, as plain text.
pub fn report() -> String {
    let net = collect();
    let mut out = String::new();
    out.push_str(&format!("source: {}\n", net.source));
    out.push_str("interfaces:\n");
    for iface in &net.interfaces {
        out.push_str(&format!("  {} {} {}\n", iface.name, iface.address, iface.kind));
    }
    out.push_str("routes:\n");
    for route in &net.routes {
        out.push_str(&format!("  {route}\n"));
    }
    out.push_str("neighbours:\n");
    for neighbour in &net.neighbours {
        out.push_str(&format!("  {neighbour}\n"));
    }
    out.push_str("resolvers:\n");
    for resolver in &net.resolvers {
        out.push_str(&format!("  {resolver}\n"));
    }
    out
}

/// Read the tables the kernel exports.
#[cfg(target_os = "linux")]
fn from_proc() -> Option<Network> {
    let mut interfaces: Vec<Interface> = Vec::new();
    if let Ok(text) = fs::read_to_string("/proc/net/dev") {
        for line in text.lines().skip(2) {
            let mut parts = line.split_whitespace();
            let name = parts.next()?.trim_end_matches(':').to_string();
            let address = parts.next().unwrap_or("").to_string();
            let kind = if fs::metadata(format!("/sys/class/net/{name}")).is_ok() {
                "ethernet".to_string()
            } else {
                "unknown".to_string()
            };
            interfaces.push(Interface { name, address, kind });
        }
    }
    let mut routes: Vec<String> = Vec::new();
    if let Ok(text) = fs::read_to_string("/proc/net/route") {
        for line in text.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 8 {
                continue;
            }
            routes.push(format!(
                "destination {} mask {} gateway {}",
                parts[1], parts[7], parts[2]
            ));
        }
    }
    let mut neighbours: Vec<String> = Vec::new();
    if let Ok(text) = fs::read_to_string("/proc/net/arp") {
        for line in text.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            neighbours.push(format!("{} {}", parts[3], parts[0]));
        }
    }
    // The IPv6 tables: a host on an IPv6-only network has its routes and
    // its neighbours here, and nowhere else.
    if let Ok(text) = fs::read_to_string("/proc/net/ipv6_route") {
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }
            routes.push(format!(
                "ipv6 destination {} prefix {} gateway {}",
                parts[0], parts[1], parts[4]
            ));
        }
    }
    if let Ok(text) = fs::read_to_string("/proc/net/ipv6_neigh") {
        for line in text.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }
            neighbours.push(format!("{} {}", parts[4], parts[0]));
        }
    }
    let mut resolvers: Vec<String> = Vec::new();
    if let Ok(text) = fs::read_to_string("/etc/resolv.conf") {
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("nameserver") {
                resolvers.push(rest.trim().to_string());
            }
        }
    }
    if interfaces.is_empty() && routes.is_empty() && resolvers.is_empty() {
        return None;
    }
    Some(Network {
        interfaces,
        routes,
        neighbours,
        resolvers,
        source: "/proc".to_string(),
    })
}

/// Ask the platform's own tools.
fn from_tools() -> Network {
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut routes: Vec<String> = Vec::new();
    let mut neighbours: Vec<String> = Vec::new();
    let mut resolvers: Vec<String> = Vec::new();

    for (command, sink) in [
        ("ip -o addr", 0usize),
        ("ifconfig -a", 1),
        ("ip route", 2),
        ("netstat -rn", 3),
        ("arp -a", 4),
        ("cat /etc/resolv.conf", 5),
    ] {
        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(command)
            .output();
        let text = match output {
            Ok(out) => String::from_utf8_lossy(&out.stdout).to_string(),
            Err(_) => continue,
        };
        for line in text.lines() {
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }
            match sink {
                0 | 1 => {
                    if line.starts_with("inet ") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() > 1 {
                            interfaces.push(Interface {
                                name: String::new(),
                                address: parts[1].to_string(),
                                kind: String::new(),
                            });
                        }
                    }
                }
                2 | 3 => routes.push(line),
                4 => neighbours.push(line),
                _ => {
                    if line.starts_with("nameserver") {
                        resolvers.push(line.replace("nameserver", "").trim().to_string());
                    }
                }
            }
        }
    }
    Network {
        interfaces,
        routes,
        neighbours,
        resolvers,
        source: "tools".to_string(),
    }
}
