use super::cmd::{run, CmdOutcome};
use crate::db::models::DockerContainerInfo;
use serde::Deserialize;
use tracing::info;

#[derive(Debug, Deserialize)]
struct DockerPsEntry {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Names")]
    names: String,
    #[serde(rename = "Image")]
    image: String,
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "State")]
    state: String,
    #[serde(rename = "Ports")]
    ports: String,
}

#[derive(Clone, Copy)]
pub enum ContainerAction {
    Start,
    Stop,
    Restart,
}

impl ContainerAction {
    fn as_str(self) -> &'static str {
        match self {
            ContainerAction::Start => "start",
            ContainerAction::Stop => "stop",
            ContainerAction::Restart => "restart",
        }
    }
}

pub struct DockerService;

fn docker(args: &[&str]) -> Result<String, String> {
    match run("docker", args) {
        CmdOutcome::Ok(out) => Ok(out),
        CmdOutcome::Failed(e) => Err(e),
        CmdOutcome::Missing => Err("Docker is not installed on this server".into()),
    }
}

impl DockerService {
    pub fn is_available() -> bool {
        docker(&["version", "--format", "{{.Server.Version}}"]).is_ok()
    }

    pub fn list_containers() -> Result<Vec<DockerContainerInfo>, String> {
        let stdout = docker(&["ps", "-a", "--format", "{{json .}}"])?;
        Ok(stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<DockerPsEntry>(l).ok())
            .map(|e| DockerContainerInfo {
                id: e.id,
                name: e.names,
                image: e.image,
                status: e.status,
                state: e.state,
                ports: e
                    .ports
                    .split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect(),
            })
            .collect())
    }

    /// `id` must already be validated with `validate::container_id`.
    pub fn act(id: &str, action: ContainerAction) -> Result<(), String> {
        docker(&[action.as_str(), id])?;
        info!("docker {} {}", action.as_str(), id);
        Ok(())
    }

    /// `id` must already be validated; `tail` is clamped by the caller.
    pub fn logs(id: &str, tail: usize) -> Result<String, String> {
        let tail = tail.to_string();
        let out = std::process::Command::new("docker")
            .args(["logs", "--tail", &tail, "--timestamps", id])
            .output()
            .map_err(|e| format!("Failed to run docker: {e}"))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        // Containers write to both streams; show both.
        let mut logs = String::from_utf8_lossy(&out.stdout).into_owned();
        logs.push_str(&String::from_utf8_lossy(&out.stderr));
        Ok(logs)
    }
}
