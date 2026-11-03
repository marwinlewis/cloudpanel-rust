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

pub struct FirewallService;

fn rule_spec(port: u16, protocol: Protocol) -> String {
    match protocol {
        Protocol::Any => port.to_string(),
        p => format!("{port}/{}", p.as_str()),
    }
}

fn ufw(args: &[&str]) -> Result<(), String> {
    match run("ufw", args) {
        CmdOutcome::Ok(_) => Ok(()),
        CmdOutcome::Failed(e) => Err(format!("ufw: {e}")),
        CmdOutcome::Missing => {
            warn!("ufw not installed; rule stored but not applied");
            Ok(())
        }
    }
}

impl FirewallService {
    pub fn add(port: u16, protocol: Protocol, action: Action) -> Result<(), String> {
        let spec = rule_spec(port, protocol);
        ufw(&[action.as_str(), &spec])?;
        info!("ufw {} {}", action.as_str(), spec);
        Ok(())
    }

    pub fn delete(port: u16, protocol: Protocol, action: Action) -> Result<(), String> {
        let spec = rule_spec(port, protocol);
        ufw(&["--force", "delete", action.as_str(), &spec])?;
        info!("ufw delete {} {}", action.as_str(), spec);
        Ok(())
    }
}
