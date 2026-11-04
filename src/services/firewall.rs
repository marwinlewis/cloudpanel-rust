//! UFW rules: ports and port ranges (optionally limited to a source IP/CIDR) and IP
//! block-list entries. Commands are built from validated parts and run via execve.

use super::cmd::{run, CmdOutcome};
use tracing::{info, warn};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Any,
}

impl Protocol {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "tcp" => Some(Protocol::Tcp),
            "udp" => Some(Protocol::Udp),
            "any" => Some(Protocol::Any),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Any => "any",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Deny,
}

impl Action {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Action::Allow),
            "deny" => Some(Action::Deny),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Deny => "deny",
        }
    }
}

/// A validated rule.
#[derive(Clone)]
pub struct Rule {
    pub action: Action,
    pub port: Option<u16>,
    pub port_end: Option<u16>,
    pub protocol: Protocol,
    pub source: Option<String>,
}

impl Rule {
    /// The ufw arguments after `allow`/`deny` (shared by add and delete).
    pub fn spec(&self) -> Vec<String> {
        match (self.port, &self.source) {
            // Block-list entry: everything from an address.
            (None, Some(src)) => vec!["from".into(), src.clone()],
            (None, None) => vec![],
            (Some(p), None) if self.port_end.is_none() => match self.protocol {
                Protocol::Any => vec![p.to_string()],
                proto => vec![format!("{p}/{}", proto.as_str())],
            },
            (Some(p), src) => {
                let ports = match self.port_end {
                    Some(e) => format!("{p}:{e}"),
                    None => p.to_string(),
                };
                let mut v = Vec::new();
                if self.protocol != Protocol::Any {
                    v.push("proto".into());
                    v.push(self.protocol.as_str().into());
                }
                v.push("from".into());
                v.push(src.clone().unwrap_or_else(|| "any".into()));
                v.extend(["to".into(), "any".into(), "port".into(), ports]);
                v
            }
        }
    }

    pub fn is_block(&self) -> bool {
        self.port.is_none()
    }

    pub fn covers_port(&self, port: u16) -> bool {
        match (self.port, self.port_end) {
            (None, _) => true,
            (Some(a), None) => a == port,
            (Some(a), Some(b)) => (a..=b).contains(&port),
        }
    }
}

/// Is `ip` inside `cidr` (or equal to a bare address)?
pub fn cidr_contains(cidr: &str, ip: std::net::IpAddr) -> bool {
    let (addr, prefix) = match cidr.split_once('/') {
        Some((a, p)) => (a, p.parse::<u32>().ok()),
        None => (cidr, None),
    };
    let Ok(net) = addr.parse::<std::net::IpAddr>() else {
        return false;
    };
    match (net, ip) {
        (std::net::IpAddr::V4(n), std::net::IpAddr::V4(i)) => {
            let bits = prefix.unwrap_or(32).min(32);
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            (u32::from(n) & mask) == (u32::from(i) & mask)
        }
        (std::net::IpAddr::V6(n), std::net::IpAddr::V6(i)) => {
            let bits = prefix.unwrap_or(128).min(128);
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            (u128::from(n) & mask) == (u128::from(i) & mask)
        }
        _ => false,
    }
}

pub struct FirewallService;

fn ufw(args: &[&str]) -> Result<String, String> {
    match run("ufw", args) {
        CmdOutcome::Ok(out) => Ok(out),
        CmdOutcome::Failed(e) => Err(format!("ufw: {e}")),
        CmdOutcome::Missing => {
            warn!("ufw not installed; rule stored but not applied");
            Ok(String::new())
        }
    }
}

impl FirewallService {
    pub fn add(rule: &Rule, comment: Option<&str>) -> Result<(), String> {
        let spec = rule.spec();
        let mut args: Vec<String> = Vec::new();
        if rule.is_block() {
            // Block-list entries go first so they win over allow rules.
            args.push("prepend".into());
        }
        args.push(rule.action.as_str().into());
        args.extend(spec.iter().cloned());
        if let Some(c) = comment {
            args.push("comment".into());
            args.push(c.to_string());
        }
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        match ufw(&argv) {
            Ok(_) => {}
            Err(e) if rule.is_block() => {
                // Older ufw or an empty rule set: fall back to a normal rule.
                warn!("ufw prepend failed ({e}); adding block rule normally");
                let fallback: Vec<&str> = argv[1..].to_vec();
                ufw(&fallback)?;
            }
            Err(e) => return Err(e),
        }
        info!("ufw {} {}", rule.action.as_str(), spec.join(" "));
        Ok(())
    }

    pub fn delete(rule: &Rule) -> Result<(), String> {
        let spec = rule.spec();
        let mut args: Vec<&str> = vec!["--force", "delete", rule.action.as_str()];
        args.extend(spec.iter().map(String::as_str));
        ufw(&args)?;
        info!("ufw delete {} {}", rule.action.as_str(), spec.join(" "));
        Ok(())
    }

    /// `ufw status verbose` (raw), or None when ufw is missing.
    pub fn status() -> Option<String> {
        match run("ufw", &["status", "verbose"]) {
            CmdOutcome::Ok(out) => Some(out),
            CmdOutcome::Failed(e) => Some(e),
            CmdOutcome::Missing => None,
        }
    }

    /// SSH ports from `sshd -T` (defaults to 22).
    pub fn ssh_ports() -> Vec<u16> {
        match run("sshd", &["-T"]) {
            CmdOutcome::Ok(out) => {
                let v: Vec<u16> = out
                    .lines()
                    .filter_map(|l| l.strip_prefix("port "))
                    .filter_map(|p| p.trim().parse().ok())
                    .collect();
                if v.is_empty() {
                    vec![22]
                } else {
                    v
                }
            }
            _ => vec![22],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(action: Action, port: Option<u16>, end: Option<u16>, proto: Protocol, src: Option<&str>) -> Rule {
        Rule {
            action,
            port,
            port_end: end,
            protocol: proto,
            source: src.map(str::to_string),
        }
    }

    #[test]
    fn specs() {
        assert_eq!(
            r(Action::Allow, Some(80), None, Protocol::Tcp, None).spec(),
            vec!["80/tcp"]
        );
        assert_eq!(r(Action::Allow, Some(53), None, Protocol::Any, None).spec(), vec!["53"]);
        assert_eq!(
            r(Action::Allow, Some(6000), Some(6010), Protocol::Udp, None)
                .spec()
                .join(" "),
            "proto udp from any to any port 6000:6010"
        );
        assert_eq!(
            r(Action::Allow, Some(3306), None, Protocol::Tcp, Some("10.0.0.0/8"))
                .spec()
                .join(" "),
            "proto tcp from 10.0.0.0/8 to any port 3306"
        );
        let block = r(Action::Deny, None, None, Protocol::Any, Some("203.0.113.9"));
        assert_eq!(block.spec().join(" "), "from 203.0.113.9");
        assert!(block.covers_port(22));
    }

    #[test]
    fn cidr_matching() {
        let ip: std::net::IpAddr = "10.1.2.3".parse().unwrap();
        assert!(cidr_contains("10.0.0.0/8", ip));
        assert!(!cidr_contains("192.168.0.0/16", ip));
        assert!(cidr_contains("10.1.2.3", ip));
        assert!(cidr_contains("0.0.0.0/0", ip));
        let v6: std::net::IpAddr = "2001:db8::5".parse().unwrap();
        assert!(cidr_contains("2001:db8::/32", v6));
        assert!(!cidr_contains("10.0.0.0/8", v6));
    }
}
