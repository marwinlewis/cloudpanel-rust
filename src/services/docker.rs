use super::cmd::{run, run_streaming, run_with, CmdOpts, CmdOutcome};
use crate::db::models::DockerContainerInfo;
use crate::jobs::JobLog;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
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
    pub fn as_str(self) -> &'static str {
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

fn docker_job(args: &[&str], cwd: Option<&Path>, log: &JobLog) -> Result<(), String> {
    log.line(&format!("$ docker {}", args.join(" ")));
    let mut opts = CmdOpts::default().timeout(3600);
    if let Some(c) = cwd {
        opts = opts.cwd(c);
    }
    let r = run_streaming("docker", args, &opts, &mut |l, _| log.line(l));
    if r.missing {
        return Err("Docker is not installed on this server".into());
    }
    if !r.success() {
        return Err(format!("docker exited with code {}", r.code.unwrap_or(-1)));
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ImageInfo {
    #[serde(rename(deserialize = "ID"))]
    pub id: String,
    #[serde(rename(deserialize = "Repository"))]
    pub repository: String,
    #[serde(rename(deserialize = "Tag"))]
    pub tag: String,
    #[serde(rename(deserialize = "Size"))]
    pub size: String,
    #[serde(rename(deserialize = "CreatedSince"))]
    pub created: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StatsInfo {
    #[serde(rename(deserialize = "ID"))]
    pub id: String,
    #[serde(rename(deserialize = "Name"))]
    pub name: String,
    #[serde(rename(deserialize = "CPUPerc"))]
    pub cpu: String,
    #[serde(rename(deserialize = "MemUsage"))]
    pub mem_usage: String,
    #[serde(rename(deserialize = "MemPerc"))]
    pub mem_perc: String,
    #[serde(rename(deserialize = "NetIO"))]
    pub net_io: String,
}

fn json_lines<T: serde::de::DeserializeOwned>(out: &str) -> Vec<T> {
    out.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// A validated `docker run` request.
#[derive(Deserialize, Clone, Debug)]
pub struct RunSpec {
    pub image: String,
    pub name: String,
    #[serde(default = "default_restart")]
    pub restart: String,
    #[serde(default)]
    pub ports: Vec<PortMap>,
    #[serde(default)]
    pub env: Vec<(String, String)>,
    #[serde(default)]
    pub volumes: Vec<VolumeMap>,
}

fn default_restart() -> String {
    "unless-stopped".into()
}

#[derive(Deserialize, Clone, Debug)]
pub struct PortMap {
    pub host: u16,
    pub container: u16,
    #[serde(default = "tcp")]
    pub protocol: String,
    /// Publish on all interfaces (bypasses UFW). Default: 127.0.0.1 only.
    #[serde(default)]
    pub public: bool,
}

fn tcp() -> String {
    "tcp".into()
}

#[derive(Deserialize, Clone, Debug)]
pub struct VolumeMap {
    /// Named volume or absolute host path.
    pub source: String,
    pub target: String,
    #[serde(default)]
    pub read_only: bool,
}

impl RunSpec {
    /// Validate and turn into `docker run` arguments. Host paths must be inside one of
    /// `allowed_roots`; no privileged flags are ever produced.
    pub fn to_args(&self, allowed_roots: &[PathBuf]) -> Result<Vec<String>, String> {
        let image = crate::validate::image_ref(&self.image)?;
        let name = crate::validate::container_id(&self.name)?;
        if !matches!(self.restart.as_str(), "no" | "always" | "unless-stopped" | "on-failure") {
            return Err("Restart policy must be no, always, unless-stopped or on-failure".into());
        }
        let mut args: Vec<String> = vec![
            "run".into(),
            "-d".into(),
            "--name".into(),
            name,
            "--restart".into(),
            self.restart.clone(),
        ];
        for p in &self.ports {
            if p.host == 0 || p.container == 0 {
                return Err("Ports must be between 1 and 65535".into());
            }
            if !matches!(p.protocol.as_str(), "tcp" | "udp") {
                return Err("Port protocol must be tcp or udp".into());
            }
            let bind = if p.public { "" } else { "127.0.0.1:" };
            args.push("-p".into());
            args.push(format!("{bind}{}:{}/{}", p.host, p.container, p.protocol));
        }
        for (k, v) in &self.env {
            let k = crate::validate::env_key(k)?;
            let v = crate::validate::env_value(v)?;
            args.push("-e".into());
            args.push(format!("{k}={v}"));
        }
        for v in &self.volumes {
            let target = v.target.trim();
            if !target.starts_with('/') || target.contains([':', ',', '\n']) || target.contains("..") {
                return Err(format!("Invalid container path '{target}'"));
            }
            let source = v.source.trim();
            if source.starts_with('/') {
                let p = crate::validate::absolute(Path::new(source));
                if source.contains("..")
                    || !allowed_roots
                        .iter()
                        .any(|r| p.starts_with(crate::validate::absolute(r)))
                {
                    return Err(format!(
                        "Host paths must be inside {}",
                        allowed_roots
                            .iter()
                            .map(|r| r.display().to_string())
                            .collect::<Vec<_>>()
                            .join(" or ")
                    ));
                }
                if source.contains([':', ',']) {
                    return Err("Host path contains unsupported characters".into());
                }
            } else {
                let ok = source.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
                    && source.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
                    && source.len() <= 64;
                if !ok {
                    return Err(format!("Invalid volume name '{source}'"));
                }
            }
            args.push("-v".into());
            args.push(format!("{source}:{target}{}", if v.read_only { ":ro" } else { "" }));
        }
        args.push("--".into());
        args.push(image);
        Ok(args)
    }
}

impl DockerService {
    pub fn is_available() -> bool {
        docker(&["version", "--format", "{{.Server.Version}}"]).is_ok()
    }

    pub fn list_containers() -> Result<Vec<DockerContainerInfo>, String> {
        let stdout = docker(&["ps", "-a", "--format", "{{json .}}"])?;
        Ok(json_lines::<DockerPsEntry>(&stdout)
            .into_iter()
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

    pub fn remove_container(id: &str, force: bool) -> Result<(), String> {
        let mut args = vec!["rm"];
        if force {
            args.push("-f");
        }
        args.push("--");
        args.push(id);
        docker(&args).map(|_| ())
    }

    /// `id` must already be validated; `tail` is clamped by the caller.
    pub fn logs(id: &str, tail: usize) -> Result<String, String> {
        let tail = tail.to_string();
        let r = run_with(
            "docker",
            &["logs", "--tail", &tail, "--timestamps", id],
            &CmdOpts::default().timeout(30),
        );
        if r.missing {
            return Err("Docker is not installed on this server".into());
        }
        if !r.success() {
            return Err(r.stderr.trim().to_string());
        }
        // Containers write to both streams; show both.
        Ok(r.combined())
    }

    pub fn stats() -> Result<Vec<StatsInfo>, String> {
        Ok(json_lines(&docker(&[
            "stats",
            "--no-stream",
            "--format",
            "{{json .}}",
        ])?))
    }

    pub fn images() -> Result<Vec<ImageInfo>, String> {
        Ok(json_lines(&docker(&["images", "--format", "{{json .}}"])?))
    }

    pub fn remove_image(id: &str, force: bool) -> Result<(), String> {
        let mut args = vec!["rmi"];
        if force {
            args.push("-f");
        }
        args.push("--");
        args.push(id);
        docker(&args).map(|_| ())
    }

    pub fn prune_images() -> Result<String, String> {
        docker(&["image", "prune", "-f"])
    }

    pub fn pull(image: &str, log: &JobLog) -> Result<(), String> {
        docker_job(&["pull", "--", image], None, log)
    }

    pub fn run(args: &[String], log: &JobLog) -> Result<(), String> {
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        docker_job(&argv, None, log)
    }
}

// ---------- Compose stacks ----------

pub const MAX_COMPOSE_BYTES: usize = 256 * 1024;

pub fn stack_name(input: &str) -> Result<String, String> {
    let s = input.trim();
    let ok = s
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && s.len() <= 40
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if ok {
        Ok(s.to_string())
    } else {
        Err("Stack names use lowercase letters, digits, - and _ (max 40)".into())
    }
}

#[derive(Serialize)]
pub struct Stack {
    pub name: String,
    pub services: Vec<serde_json::Value>,
}

fn stack_dir(root: &Path, name: &str) -> PathBuf {
    root.join(name)
}

fn compose_args<'a>(root: &Path, name: &'a str, extra: &[&'a str]) -> Vec<String> {
    let dir = stack_dir(root, name);
    let mut v = vec![
        "compose".to_string(),
        "-p".into(),
        name.to_string(),
        "-f".into(),
        dir.join("compose.yaml").to_string_lossy().into_owned(),
    ];
    if dir.join(".env").exists() {
        v.push("--env-file".into());
        v.push(dir.join(".env").to_string_lossy().into_owned());
    }
    v.extend(extra.iter().map(|s| s.to_string()));
    v
}

pub fn list_stacks(root: &Path) -> Vec<Stack> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return out;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if stack_name(&name).is_err() || !e.path().join("compose.yaml").exists() {
            continue;
        }
        let args = compose_args(root, &name, &["ps", "--all", "--format", "json"]);
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let services = match run("docker", &argv) {
            CmdOutcome::Ok(s) => {
                // Newer compose prints one JSON object per line; older prints an array.
                serde_json::from_str::<Vec<serde_json::Value>>(&s).unwrap_or_else(|_| json_lines(&s))
            }
            _ => vec![],
        };
        out.push(Stack { name, services });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

pub fn read_stack(root: &Path, name: &str) -> Result<(String, String), String> {
    let dir = stack_dir(root, name);
    let compose = std::fs::read_to_string(dir.join("compose.yaml")).map_err(|_| "Stack not found".to_string())?;
    let env = std::fs::read_to_string(dir.join(".env")).unwrap_or_default();
    Ok((compose, env))
}

/// Save compose.yaml + .env and validate with `docker compose config -q`; restores the
/// previous files if validation fails.
pub fn save_stack(root: &Path, name: &str, compose: &str, env: &str) -> Result<(), String> {
    if compose.len() > MAX_COMPOSE_BYTES || env.len() > 64 * 1024 {
        return Err("Compose file is too large".into());
    }
    let dir = stack_dir(root, name);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    crate::fsutil::set_mode(&dir, 0o700).map_err(|e| e.to_string())?;
    let cf = dir.join("compose.yaml");
    let ef = dir.join(".env");
    let prev = (std::fs::read(&cf).ok(), std::fs::read(&ef).ok());
    crate::fsutil::write_atomic(&cf, compose.as_bytes(), 0o600).map_err(|e| e.to_string())?;
    if env.trim().is_empty() {
        let _ = std::fs::remove_file(&ef);
    } else {
        crate::fsutil::write_atomic(&ef, env.as_bytes(), 0o600).map_err(|e| e.to_string())?;
    }
    let args = compose_args(root, name, &["config", "-q"]);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    match run("docker", &argv) {
        CmdOutcome::Ok(_) | CmdOutcome::Missing => Ok(()),
        CmdOutcome::Failed(e) => {
            match prev.0 {
                Some(p) => {
                    let _ = crate::fsutil::write_atomic(&cf, &p, 0o600);
                }
                None => {
                    let _ = std::fs::remove_dir_all(&dir);
                }
            }
            if let Some(p) = prev.1 {
                let _ = crate::fsutil::write_atomic(&ef, &p, 0o600);
            }
            Err(format!("Invalid compose file: {}", super::cmd::tail(&e, 1500)))
        }
    }
}

pub fn stack_action(root: &Path, name: &str, action: &str, log: &JobLog) -> Result<(), String> {
    let extra: &[&str] = match action {
        "up" => &["up", "-d", "--remove-orphans"],
        "down" => &["down"],
        "pull" => &["pull"],
        "restart" => &["restart"],
        _ => return Err("Unknown action".into()),
    };
    let args = compose_args(root, name, extra);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let dir = stack_dir(root, name);
    docker_job(&argv, Some(&dir), log)
}

pub fn stack_logs(root: &Path, name: &str, tail: usize) -> Result<String, String> {
    let t = tail.to_string();
    let args = compose_args(root, name, &["logs", "--no-color", "--tail", &t]);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let r = run_with("docker", &argv, &CmdOpts::default().timeout(30));
    if r.missing {
        return Err("Docker is not installed on this server".into());
    }
    Ok(r.combined())
}

pub fn delete_stack(root: &Path, name: &str, log: &JobLog) -> Result<(), String> {
    let _ = stack_action(root, name, "down", log);
    std::fs::remove_dir_all(stack_dir(root, name)).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_spec_is_safe_by_default() {
        let spec = RunSpec {
            image: "nginx:1.27".into(),
            name: "web".into(),
            restart: "unless-stopped".into(),
            ports: vec![PortMap {
                host: 8080,
                container: 80,
                protocol: "tcp".into(),
                public: false,
            }],
            env: vec![("A".into(), "b c".into())],
            volumes: vec![
                VolumeMap {
                    source: "webdata".into(),
                    target: "/data".into(),
                    read_only: false,
                },
                VolumeMap {
                    source: "/home/app/htdocs".into(),
                    target: "/usr/share/nginx/html".into(),
                    read_only: true,
                },
            ],
        };
        let args = spec.to_args(&[PathBuf::from("/home")]).unwrap().join(" ");
        assert!(args.contains("-p 127.0.0.1:8080:80/tcp"));
        assert!(args.contains("-e A=b c"));
        assert!(args.contains("-v /home/app/htdocs:/usr/share/nginx/html:ro"));
        assert!(args.ends_with("-- nginx:1.27"));
        let mut bad = spec.clone();
        bad.volumes = vec![VolumeMap {
            source: "/etc".into(),
            target: "/x".into(),
            read_only: false,
        }];
        assert!(bad.to_args(&[PathBuf::from("/home")]).is_err());
        let mut bad = spec.clone();
        bad.image = "--privileged".into();
        assert!(bad.to_args(&[]).is_err());
        let mut bad = spec;
        bad.volumes[0].source = "/home/../etc".into();
        assert!(bad.to_args(&[PathBuf::from("/home")]).is_err());
    }

    #[test]
    fn stack_names() {
        assert!(stack_name("blog-prod").is_ok());
        assert!(stack_name("../x").is_err());
        assert!(stack_name("Blog").is_err());
    }
}
