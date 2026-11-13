//! Is a newer CloudPanel released? Asks GitHub for the latest release, the same one `install.sh`
//! installs, once a day and whenever an admin asks. Installing it is the admin's decision: a
//! button in the panel, or the same command run on the server.
//!
//! The upgrade runs `install.sh` from the release's own tag in a transient systemd unit. It can't
//! be a child of the panel: the panel's sandbox can't write the binary, and the panel is restarted
//! part-way through. What happened is read back from the unit's state and its log.
//!
//! The answer is stored, but whether it is an update is worked out from the running version each
//! time, so the notice goes away by itself once the new version is running.

use super::alerts;
use super::cmd::{self, CmdOpts};
use crate::api::error::{ApiError, ApiResult};
use crate::auth::AuthUser;
use crate::config::Config;
use crate::db;
use crate::state::SharedState;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

pub const SETTING: &str = "panel_update";
pub const DEFAULT_URL: &str = "https://api.github.com/repos/marwinlewis/cloudpanel-rust/releases/latest";
pub const UPGRADE_COMMAND: &str =
    "curl -fsSL https://raw.githubusercontent.com/marwinlewis/cloudpanel-rust/main/install.sh | sudo bash";
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");

const REPO: &str = "marwinlewis/cloudpanel-rust";
/// The transient unit an upgrade runs in. One name, so two can't run at once.
const UPGRADE_UNIT: &str = "cloudpanel-upgrade";
const UPGRADE_LOG: &str = "upgrade.log";
const PANEL_UNIT_FILE: &str = "/etc/systemd/system/cloudpanel.service";

/// What the upgrade unit runs, as `bash -c SCRIPT name VERSION INSTALLER_URL`. The version and
/// address are arguments, never part of the text. The installer keeps data, secrets and earlier
/// choices. It is told to leave other packages alone, so nginx and PHP keep serving the sites, and
/// to leave the firewall alone, which the admin manages from the panel after installing.
/// If the new version doesn't stay up, the previous binary is put back.
const UPGRADE_SCRIPT: &str = r#"set -uo pipefail
version="$1"
installer_url="$2"
bin=/usr/local/bin/cloudpanel
echo "Upgrading CloudPanel to v$version"
cp -p "$bin" "$bin.prev" || { echo "Could not keep a copy of the current version"; exit 1; }
tmp=$(mktemp -d -p /var/tmp cloudpanel-upgrade.XXXXXX) || exit 1
trap 'rm -rf "$tmp"' EXIT
restore() {
  if ! cmp -s "$bin" "$bin.prev"; then
    echo "Putting the previous version back"
    install -m 0755 "$bin.prev" "$bin.new" && mv -f "$bin.new" "$bin"
    systemctl restart cloudpanel
  fi
  rm -f "$bin.prev"
}
if ! curl -fsSL --retry 3 -o "$tmp/install.sh" "$installer_url"; then
  echo "Could not download the installer from $installer_url"
  rm -f "$bin.prev"
  exit 1
fi
if ! bash "$tmp/install.sh" --version "v$version" --no-upgrade --no-firewall; then
  echo "The installer failed"
  restore
  exit 1
fi
up=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  sleep 2
  if systemctl is-active --quiet cloudpanel; then up=$((up + 1)); else up=0; fi
done
if [ "$up" -lt 8 ]; then
  echo "CloudPanel v$version did not stay running"
  restore
  exit 1
fi
rm -f "$bin.prev"
echo "CloudPanel v$version is running"
"#;

const CHECK_EVERY_HOURS: i64 = 24;
const RETRY_AFTER_HOURS: i64 = 1;
const MIN_WAIT: Duration = Duration::from_secs(60);

/// Fields in the order they compare. A pre-release comes before its own final version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    is_final: bool,
}

fn number(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

impl Version {
    /// `1.2.3` or `1.2.3-rc1`, with or without the `v` that tags have.
    fn parse(s: &str) -> Option<Version> {
        let s = s.strip_prefix('v').unwrap_or(s);
        let (core, is_final) = match s.split_once('-') {
            Some((_, "")) => return None,
            Some((core, _)) => (core, false),
            None => (s, true),
        };
        let mut parts = core.split('.');
        let version = Version {
            major: number(parts.next()?)?,
            minor: number(parts.next()?)?,
            patch: number(parts.next()?)?,
            is_final,
        };
        parts.next().is_none().then_some(version)
    }
}

fn is_newer(candidate: &str, current: &str) -> bool {
    match (Version::parse(candidate), Version::parse(current)) {
        (Some(candidate), Some(current)) => candidate > current,
        _ => false,
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Release {
    version: String,
    url: Option<String>,
    published_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
struct Stored {
    /// The last check that got an answer. A failed one leaves this and `release` alone.
    checked_at: Option<DateTime<Utc>>,
    release: Option<Release>,
    failed_at: Option<DateTime<Utc>>,
    error: Option<String>,
    /// The newest version the alert channels were told about, so they hear about each only once.
    notified: Option<String>,
    /// The upgrade last started from the panel, until the version it aimed for is running.
    #[serde(default)]
    upgrade: Option<Upgrade>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Upgrade {
    target: String,
    from: String,
    started_at: DateTime<Utc>,
}

/// How the upgrade last started stands. Worked out, never stored: its unit is running, or it
/// ended, and then the version that is running says whether it worked.
fn upgrade_state(upgrade: Option<&Upgrade>, current: &str, unit_active: bool) -> &'static str {
    match upgrade {
        None => "none",
        // The version it aimed for is answering: done, as far as the page goes, even while the
        // unit still watches that it stays up.
        Some(u) if u.target == current => "none",
        Some(_) if unit_active => "running",
        Some(_) => "failed",
    }
}

/// A version that may be handed to the installer: one that parses, in the characters a tag has.
/// The part after a `-` is otherwise free text.
fn safe_version(v: &str) -> bool {
    v.len() <= 40
        && Version::parse(v).is_some()
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

fn installer_url(config: &Config, version: &str) -> String {
    match &config.upgrade_installer_url {
        Some(url) => url.clone(),
        None => format!("https://raw.githubusercontent.com/{REPO}/v{version}/install.sh"),
    }
}

/// Whether this panel was installed as the systemd service the installer upgrades. A development
/// build, or one run by hand, has nothing to upgrade in place.
fn can_upgrade() -> bool {
    cmd::systemd_run().is_some() && std::path::Path::new(PANEL_UNIT_FILE).exists()
}

fn unit_active() -> bool {
    cmd::run_with(
        "systemctl",
        &["is-active", "--quiet", UPGRADE_UNIT],
        &CmdOpts::default().timeout(10),
    )
    .success()
}

/// The end of the upgrade's log, without the colours the installer adds for a terminal.
fn plain_tail(text: &str, max_lines: usize) -> String {
    let mut plain = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            plain.push(c);
        }
    }
    // The installer's summary repeats the first admin password for as long as it was never changed.
    let lines: Vec<&str> = plain
        .lines()
        .filter(|l| !l.trim_start().starts_with("Password"))
        .collect();
    lines[lines.len().saturating_sub(max_lines)..].join("\n")
}

fn log_tail(config: &Config) -> String {
    let text = std::fs::read(config.log_dir.join(UPGRADE_LOG))
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    plain_tail(&text, 60)
}

/// What the page shows about upgrading, next to what `status_of` says about releases.
struct UpgradeView {
    can_upgrade: bool,
    unit_active: bool,
    log_tail: String,
}

impl UpgradeView {
    /// Asks systemd only while an upgrade is on record, as this runs on every page change.
    fn read(config: &Config, stored: &Stored) -> UpgradeView {
        let pending = stored.upgrade.is_some();
        UpgradeView {
            can_upgrade: can_upgrade(),
            unit_active: pending && unit_active(),
            log_tail: if pending { log_tail(config) } else { String::new() },
        }
    }
}

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    html_url: Option<String>,
    published_at: Option<DateTime<Utc>>,
}

fn parse_response(body: &str) -> Result<Release, String> {
    let r: GithubRelease = serde_json::from_str(body).map_err(|e| format!("unexpected answer: {e}"))?;
    if Version::parse(&r.tag_name).is_none() {
        return Err(format!("the latest release has an unknown version: '{}'", r.tag_name));
    }
    Ok(Release {
        version: r.tag_name.strip_prefix('v').unwrap_or(&r.tag_name).to_string(),
        // Becomes a link in the panel.
        url: r.html_url.filter(|u| u.starts_with("https://")),
        published_at: r.published_at,
    })
}

/// reqwest's own message is only "error sending request". What went wrong (DNS, a refused
/// connection, a certificate) is in its sources, and is what an admin needs to see.
pub(crate) fn with_causes(e: &dyn std::error::Error) -> String {
    let mut text = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        text.push_str(&format!(": {cause}"));
        source = cause.source();
    }
    text
}

/// `None` when nothing has been released yet, which GitHub answers with a 404.
async fn fetch(url: &str) -> Result<Option<Release>, String> {
    let res = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        // GitHub refuses requests without one.
        .user_agent(concat!("cloudpanel/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?
        .get(url)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| with_causes(&e))?;
    if res.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !res.status().is_success() {
        return Err(format!("{url} returned {}", res.status()));
    }
    parse_response(&res.text().await.map_err(|e| e.to_string())?).map(Some)
}

/// Record a check's outcome. Returns a release the alert channels should be told about.
fn record(
    stored: &mut Stored,
    outcome: Result<Option<Release>, String>,
    current: &str,
    now: DateTime<Utc>,
) -> Option<Release> {
    match outcome {
        Ok(release) => {
            stored.checked_at = Some(now);
            stored.release = release;
            stored.failed_at = None;
            stored.error = None;
        }
        Err(e) => {
            stored.failed_at = Some(now);
            stored.error = Some(e);
            return None;
        }
    }
    let release = stored.release.clone().filter(|r| is_newer(&r.version, current))?;
    if stored.notified.as_deref() == Some(release.version.as_str()) {
        return None;
    }
    stored.notified = Some(release.version.clone());
    Some(release)
}

fn status_of(stored: &Stored, current: &str, view: &UpgradeView) -> serde_json::Value {
    let release = stored.release.as_ref();
    let state = upgrade_state(stored.upgrade.as_ref(), current, view.unit_active);
    let upgrade = stored.upgrade.as_ref().filter(|_| state != "none");
    json!({
        "can_upgrade": view.can_upgrade,
        "upgrade": {
            "state": state,
            "target": upgrade.map(|u| &u.target),
            "started_at": upgrade.map(|u| u.started_at),
            "log_tail": upgrade.map(|_| &view.log_tail),
        },
        "current": current,
        "latest": release.map(|r| &r.version),
        "update_available": release.is_some_and(|r| is_newer(&r.version, current)),
        "release_url": release.and_then(|r| r.url.as_ref()),
        "published_at": release.and_then(|r| r.published_at),
        "checked_at": stored.checked_at,
        "failed_at": stored.failed_at,
        "error": stored.error,
        "upgrade_command": UPGRADE_COMMAND,
    })
}

/// What the panel knows, without asking GitHub.
pub fn status(config: &Config, conn: &rusqlite::Connection) -> rusqlite::Result<serde_json::Value> {
    let stored: Stored = db::get_json(conn, SETTING)?;
    Ok(status_of(&stored, CURRENT, &UpgradeView::read(config, &stored)))
}

/// Forget an upgrade once the version it aimed for is the one running. Called at startup, which
/// is where a finished upgrade leaves the panel.
pub fn settle_upgrade(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    let mut stored: Stored = db::get_json(conn, SETTING)?;
    // While the unit is still watching the new version, the record stays: if this version stops
    // and the previous one is put back, that one finds it and reports the failure.
    if let Some(u) = stored
        .upgrade
        .as_ref()
        .filter(|u| u.target == CURRENT && !unit_active())
    {
        tracing::info!("upgraded from v{} to v{}", u.from, u.target);
        stored.upgrade = None;
        db::set_json(conn, SETTING, &stored)?;
    }
    Ok(())
}

fn launch_upgrade(config: &Config, version: &str) -> Result<(), String> {
    let systemd_run = cmd::systemd_run().ok_or("systemd-run is not available")?;
    let log = config.log_dir.join(UPGRADE_LOG);
    // systemd writes from the start of the file without emptying it.
    // Only root reads it: the installer's output can name the first admin password.
    crate::fsutil::write_atomic(&log, b"", 0o600).map_err(|e| format!("Failed to write {}: {e}", log.display()))?;
    let url = installer_url(config, version);
    let mut args: Vec<String> = vec![
        format!("--unit={UPGRADE_UNIT}"),
        "--collect".into(),
        "--no-block".into(),
        "--quiet".into(),
        format!("--property=StandardOutput=file:{}", log.display()),
        "--property=StandardError=inherit".into(),
        // The installer runs for minutes on a slow server, but never for hours.
        "--property=RuntimeMaxSec=3600".into(),
        "--setenv=DEBIAN_FRONTEND=noninteractive".into(),
    ];
    if let Some(base) = &config.upgrade_release_base {
        args.push(format!("--setenv=CLOUDPANEL_RELEASE_BASE={base}"));
    }
    args.extend(
        ["--", "/bin/bash", "-c", UPGRADE_SCRIPT, UPGRADE_UNIT, version, &url]
            .iter()
            .map(|s| s.to_string()),
    );
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let program = systemd_run.to_string_lossy();
    let r = cmd::run_with(&program, &args, &CmdOpts::default().timeout(30));
    if r.success() {
        Ok(())
    } else {
        Err(format!(
            "Could not start the upgrade: {}",
            cmd::tail(r.combined().trim(), 600)
        ))
    }
}

/// Start upgrading to the release the last check found. Returns at once: the page follows the
/// status, through the restart, until the new version answers.
pub async fn start_upgrade(state: &SharedState, actor: AuthUser) -> ApiResult<serde_json::Value> {
    let config = state.config.clone();
    state
        .db(move |conn| {
            let mut stored: Stored = db::get_json(conn, SETTING)?;
            let version = stored
                .release
                .as_ref()
                .map(|r| r.version.clone())
                .filter(|v| is_newer(v, CURRENT))
                .ok_or_else(|| ApiError::BadRequest("CloudPanel is already up to date".into()))?;
            if !safe_version(&version) {
                return Err(ApiError::BadRequest(format!(
                    "The release has a version the panel won't install: '{version}'"
                )));
            }
            if !can_upgrade() {
                return Err(ApiError::Unprocessable(
                    "This panel doesn't run as the systemd service the installer sets up, so it can't upgrade \
                     itself. Run the command on the server instead."
                        .into(),
                ));
            }
            if unit_active() {
                return Err(ApiError::Conflict("An upgrade is already running".into()));
            }
            stored.upgrade = Some(Upgrade {
                target: version.clone(),
                from: CURRENT.to_string(),
                started_at: Utc::now(),
            });
            db::set_json(conn, SETTING, &stored)?;
            if let Err(e) = launch_upgrade(&config, &version) {
                stored.upgrade = None;
                db::set_json(conn, SETTING, &stored)?;
                return Err(ApiError::Unprocessable(e));
            }
            crate::audit::record(
                conn,
                &actor,
                "panel.upgrade",
                Some(&format!("v{version}")),
                Some(CURRENT),
            );
            let view = UpgradeView {
                can_upgrade: true,
                unit_active: true,
                log_tail: String::new(),
            };
            Ok(status_of(&stored, CURRENT, &view))
        })
        .await
}

/// Ask GitHub now. Being unable to reach it isn't an error here: the answer says so, and what the
/// last good check found still stands.
pub async fn check(state: &SharedState) -> ApiResult<serde_json::Value> {
    // A manual check during the daily one must not tell the channels twice.
    static CHECKING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _one_at_a_time = CHECKING.lock().await;

    let outcome = fetch(&state.config.panel_release_url).await;
    if let Err(e) = &outcome {
        tracing::warn!("could not check for a new CloudPanel release: {e}");
    }
    let st = state.clone();
    state
        .db(move |conn| {
            let mut stored: Stored = db::get_json(conn, SETTING)?;
            let announce = record(&mut stored, outcome, CURRENT, Utc::now());
            db::set_json(conn, SETTING, &stored)?;
            if let Some(release) = announce {
                let (title, body) = announcement(&release, CURRENT);
                alerts::notify_event(&st.config, &st.pool, &title, &body);
            }
            Ok(status_of(&stored, CURRENT, &UpgradeView::read(&st.config, &stored)))
        })
        .await
}

fn announcement(release: &Release, current: &str) -> (String, String) {
    let mut body = format!(
        "This server runs v{current}. To update it, press Upgrade under Services > Updates in the panel, \
         or run this on the server:\n\n{UPGRADE_COMMAND}\n\nYour data, secrets and certificate are kept."
    );
    if let Some(url) = &release.url {
        body.push_str(&format!("\n\nRelease notes: {url}"));
    }
    (format!("{} v{}", alerts::PANEL_UPDATE_TITLE, release.version), body)
}

/// How long until the next check is due. Stored times count, so that restarting the panel doesn't
/// mean another request, and a manual check puts off the next daily one.
fn due_in(stored: &Stored, now: DateTime<Utc>) -> Duration {
    let after_success = stored.checked_at.map(|t| t + ChronoDuration::hours(CHECK_EVERY_HOURS));
    let after_failure = stored.failed_at.map(|t| t + ChronoDuration::hours(RETRY_AFTER_HOURS));
    let Some(due) = after_success.max(after_failure) else {
        return Duration::ZERO;
    };
    // Bounded, in case the clock was wrong when these were saved.
    (due - now)
        .min(ChronoDuration::hours(CHECK_EVERY_HOURS))
        .to_std()
        .unwrap_or(Duration::ZERO)
}

async fn time_to_next_check(state: &SharedState) -> Duration {
    let stored: Stored = state
        .db(|conn| Ok(db::get_json(conn, SETTING)?))
        .await
        .unwrap_or_default();
    due_in(&stored, Utc::now())
}

/// Keep checking for as long as the panel runs.
pub fn start(state: SharedState) {
    tokio::spawn(async move {
        // Let the server finish starting first.
        tokio::time::sleep(Duration::from_secs(30)).await;
        loop {
            if time_to_next_check(&state).await.is_zero() {
                // Failures are logged and stored by the check itself.
                let _ = check(&state).await;
            }
            // At least a minute, so a database that won't save the result can't cause a tight loop.
            tokio::time::sleep(time_to_next_check(&state).await.max(MIN_WAIT)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(version: &str) -> Release {
        Release {
            version: version.into(),
            url: Some(format!("https://example.com/{version}")),
            published_at: None,
        }
    }

    fn view(unit_active: bool) -> UpgradeView {
        UpgradeView {
            can_upgrade: true,
            unit_active,
            log_tail: "log".into(),
        }
    }

    fn at(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    #[test]
    fn compares_versions_as_numbers() {
        assert!(is_newer("0.3.4", "0.3.0"));
        assert!(is_newer("v0.3.10", "0.3.9"));
        assert!(is_newer("0.4.0", "0.3.99"));
        assert!(is_newer("1.0.0", "0.99.99"));
        assert!(is_newer("1.0.0", "1.0.0-rc1"));
        assert!(is_newer("1.0.0-rc1", "0.9.0"));
        assert!(!is_newer("0.3.0", "0.3.0"));
        assert!(!is_newer("v0.3.0", "0.3.0"));
        assert!(!is_newer("0.2.9", "0.3.0"));
        assert!(!is_newer("1.0.0-rc1", "1.0.0"));
    }

    #[test]
    fn an_unknown_version_is_never_an_update() {
        for bad in [
            "", "v", "latest", "1", "1.2", "1.2.3.4", "1.2.x", "1.2.3-", "+1.2.3", "1.+2.3",
        ] {
            assert_eq!(Version::parse(bad), None, "{bad}");
            assert!(!is_newer(bad, "0.3.0"), "{bad}");
        }
        assert!(!is_newer("9.9.9", "dev"));
    }

    #[test]
    fn reads_githubs_answer() {
        let r = parse_response(
            r#"{"url":"x","tag_name":"v0.3.4","name":"v0.3.4","draft":false,"prerelease":false,"html_url":"https://github.com/o/r/releases/tag/v0.3.4","published_at":"2026-11-06T17:58:29Z","assets":[],"body":"notes"}"#,
        )
        .unwrap();
        assert_eq!(r.version, "0.3.4");
        assert_eq!(r.url.as_deref(), Some("https://github.com/o/r/releases/tag/v0.3.4"));
        assert_eq!(r.published_at, Some(at("2026-11-06T17:58:29Z")));
    }

    #[test]
    fn refuses_an_answer_it_cannot_use() {
        assert!(parse_response("<html>rate limited</html>").is_err());
        assert!(parse_response(r#"{"message":"API rate limit exceeded"}"#).is_err());
        assert!(parse_response(r#"{"tag_name":"nightly"}"#).is_err());
        // Only a web address may become a link.
        let r = parse_response(r#"{"tag_name":"v1.0.0","html_url":"javascript:alert(1)"}"#).unwrap();
        assert_eq!(r.url, None);
    }

    #[test]
    fn announces_each_new_version_once() {
        let now = at("2026-11-07T00:00:00Z");
        let mut s = Stored::default();
        assert_eq!(record(&mut s, Ok(Some(release("0.3.0"))), "0.3.0", now), None);
        assert_eq!(record(&mut s, Ok(Some(release("0.2.0"))), "0.3.0", now), None);
        assert_eq!(record(&mut s, Ok(None), "0.3.0", now), None);

        assert_eq!(
            record(&mut s, Ok(Some(release("0.3.1"))), "0.3.0", now),
            Some(release("0.3.1"))
        );
        assert_eq!(record(&mut s, Ok(Some(release("0.3.1"))), "0.3.0", now), None);
        // A failed check in between doesn't make it new again.
        assert_eq!(record(&mut s, Err("down".into()), "0.3.0", now), None);
        assert_eq!(record(&mut s, Ok(Some(release("0.3.1"))), "0.3.0", now), None);

        assert_eq!(
            record(&mut s, Ok(Some(release("0.3.2"))), "0.3.0", now),
            Some(release("0.3.2"))
        );
        // After updating to it, the next one is news too.
        assert_eq!(record(&mut s, Ok(Some(release("0.3.2"))), "0.3.2", now), None);
        assert_eq!(
            record(&mut s, Ok(Some(release("0.3.3"))), "0.3.2", now),
            Some(release("0.3.3"))
        );
    }

    #[test]
    fn a_failed_check_keeps_what_the_last_good_one_found() {
        let (t1, t2, t3) = (
            at("2026-11-07T00:00:00Z"),
            at("2026-11-08T00:00:00Z"),
            at("2026-11-09T00:00:00Z"),
        );
        let mut s = Stored::default();
        record(&mut s, Ok(Some(release("0.3.1"))), "0.3.0", t1);
        record(&mut s, Err("down".into()), "0.3.0", t2);
        let st = status_of(&s, "0.3.0", &view(false));
        assert_eq!(st["latest"], "0.3.1");
        assert_eq!(st["update_available"], true);
        assert_eq!(st["checked_at"], json!(t1));
        assert_eq!(st["failed_at"], json!(t2));
        assert_eq!(st["error"], "down");

        record(&mut s, Ok(Some(release("0.3.1"))), "0.3.0", t3);
        let st = status_of(&s, "0.3.0", &view(false));
        assert_eq!(st["checked_at"], json!(t3));
        assert!(st["failed_at"].is_null());
        assert!(st["error"].is_null());
    }

    #[test]
    fn the_notice_goes_away_once_the_new_version_is_running() {
        let mut s = Stored::default();
        record(&mut s, Ok(Some(release("0.3.1"))), "0.3.0", at("2026-11-07T00:00:00Z"));
        assert_eq!(status_of(&s, "0.3.0", &view(false))["update_available"], true);
        let st = status_of(&s, "0.3.1", &view(false));
        assert_eq!(st["update_available"], false);
        assert_eq!(st["current"], "0.3.1");
        assert_eq!(st["latest"], "0.3.1");
    }

    #[test]
    fn the_status_before_any_check_says_so() {
        let st = status_of(&Stored::default(), "0.3.0", &view(false));
        assert_eq!(st["update_available"], false);
        assert!(st["latest"].is_null());
        assert!(st["checked_at"].is_null());
    }

    #[test]
    fn schedules_from_the_stored_times() {
        let now = at("2026-11-07T12:00:00Z");
        let hours = |h: u64| Duration::from_secs(h * 3600);
        let mut s = Stored::default();
        assert_eq!(due_in(&s, now), Duration::ZERO);

        s.checked_at = Some(at("2026-11-07T02:00:00Z"));
        assert_eq!(due_in(&s, now), hours(14));
        s.checked_at = Some(at("2026-11-05T00:00:00Z"));
        assert_eq!(due_in(&s, now), Duration::ZERO);

        // A failure retries sooner than a day, but never before it's due again.
        s.failed_at = Some(at("2026-11-07T11:30:00Z"));
        assert_eq!(due_in(&s, now), Duration::from_secs(30 * 60));
        s.failed_at = Some(at("2026-11-07T10:00:00Z"));
        assert_eq!(due_in(&s, now), Duration::ZERO);

        // A clock that was far ahead can't put checks off for long.
        let s = Stored {
            checked_at: Some(at("2030-01-01T00:00:00Z")),
            ..Stored::default()
        };
        assert_eq!(due_in(&s, now), hours(24));
    }

    #[test]
    fn the_announcement_says_what_to_do() {
        let (title, body) = announcement(&release("0.3.1"), "0.3.0");
        assert_eq!(title, "Update available: CloudPanel v0.3.1");
        assert!(body.contains("v0.3.0"));
        assert!(body.contains(UPGRADE_COMMAND));
        assert!(body.contains("https://example.com/0.3.1"));
    }

    #[test]
    fn an_upgrade_is_running_failed_or_forgotten() {
        let mut s = Stored::default();
        assert_eq!(status_of(&s, "0.3.0", &view(false))["upgrade"]["state"], "none");
        s.upgrade = Some(Upgrade {
            target: "0.3.1".into(),
            from: "0.3.0".into(),
            started_at: at("2026-11-07T00:00:00Z"),
        });
        let st = status_of(&s, "0.3.0", &view(true));
        assert_eq!(st["upgrade"]["state"], "running");
        assert_eq!(st["upgrade"]["target"], "0.3.1");
        assert_eq!(st["upgrade"]["log_tail"], "log");
        // The new version starts while the unit is still watching it.
        assert_eq!(status_of(&s, "0.3.1", &view(true))["upgrade"]["state"], "none");
        // Ended on the old version: it didn't work, and the log says why.
        let st = status_of(&s, "0.3.0", &view(false));
        assert_eq!(st["upgrade"]["state"], "failed");
        assert_eq!(st["upgrade"]["log_tail"], "log");
        // Ended on the new one: nothing left to say.
        let st = status_of(&s, "0.3.1", &view(false));
        assert_eq!(st["upgrade"]["state"], "none");
        assert!(st["upgrade"]["target"].is_null());
        assert!(st["upgrade"]["log_tail"].is_null());
    }

    #[test]
    fn only_a_plain_version_reaches_the_installer() {
        for ok in ["0.3.5", "1.0.0", "1.0.0-rc1", "1.0.0-beta.2"] {
            assert!(safe_version(ok), "{ok}");
        }
        for bad in [
            "1.0.0-$(reboot)",
            "1.0.0-a b",
            "1.0.0-a;b",
            "1.0.0-a/b",
            "1.0.0-`id`",
            "1.0.0-a'b",
            "latest",
            "",
            "1.0.0-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(!safe_version(bad), "{bad}");
        }
    }

    #[test]
    fn the_upgrade_script_takes_the_version_as_an_argument() {
        assert!(UPGRADE_SCRIPT.contains(r#"--version "v$version" --no-upgrade --no-firewall"#));
        assert!(UPGRADE_SCRIPT.contains(r#"version="$1""#));
        assert!(!UPGRADE_SCRIPT.contains(CURRENT));
        let mut c = Config::from_env();
        c.upgrade_installer_url = None;
        assert_eq!(
            installer_url(&c, "0.3.5"),
            format!("https://raw.githubusercontent.com/{REPO}/v0.3.5/install.sh")
        );
    }

    #[test]
    fn the_log_tail_is_plain_text() {
        let log = "one\n\u{1b}[1m==>\u{1b}[0m Installing\nthree\n";
        assert_eq!(plain_tail(log, 2), "==> Installing\nthree");
        assert_eq!(plain_tail("", 5), "");
        assert_eq!(
            plain_tail("  Username  admin\n  Password  hunter2\nend\n", 5),
            "  Username  admin\nend"
        );
    }

    #[test]
    fn an_old_stored_answer_still_reads() {
        let s: Stored = serde_json::from_str(
            r#"{"checked_at":null,"release":null,"failed_at":null,"error":null,"notified":"0.3.1"}"#,
        )
        .unwrap();
        assert_eq!(s.upgrade, None);
    }

    #[test]
    fn the_release_url_and_the_command_name_the_same_repository() {
        assert_eq!(
            REPO,
            env!("CARGO_PKG_REPOSITORY").trim_start_matches("https://github.com/")
        );
        let repo = env!("CARGO_PKG_REPOSITORY").trim_start_matches("https://github.com/");
        assert!(DEFAULT_URL.contains(repo));
        assert!(UPGRADE_COMMAND.contains(repo));
    }
}
