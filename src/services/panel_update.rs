//! Is a newer CloudPanel released? Asks GitHub for the latest release, the same one `install.sh`
//! installs, once a day and whenever an admin asks. This only ever reports: installing stays a
//! step the admin takes on the server.
//!
//! The answer is stored, but whether it is an update is worked out from the running version each
//! time, so the notice goes away by itself once the new version is running.

use super::alerts;
use crate::api::error::ApiResult;
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

fn status_of(stored: &Stored, current: &str) -> serde_json::Value {
    let release = stored.release.as_ref();
    json!({
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
pub fn status(conn: &rusqlite::Connection) -> rusqlite::Result<serde_json::Value> {
    Ok(status_of(&db::get_json(conn, SETTING)?, CURRENT))
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
            Ok(status_of(&stored, CURRENT))
        })
        .await
}

fn announcement(release: &Release, current: &str) -> (String, String) {
    let mut body = format!(
        "This server runs v{current}. To update it, run this on the server:\n\n{UPGRADE_COMMAND}\n\nYour data, secrets and certificate are kept."
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
        let st = status_of(&s, "0.3.0");
        assert_eq!(st["latest"], "0.3.1");
        assert_eq!(st["update_available"], true);
        assert_eq!(st["checked_at"], json!(t1));
        assert_eq!(st["failed_at"], json!(t2));
        assert_eq!(st["error"], "down");

        record(&mut s, Ok(Some(release("0.3.1"))), "0.3.0", t3);
        let st = status_of(&s, "0.3.0");
        assert_eq!(st["checked_at"], json!(t3));
        assert!(st["failed_at"].is_null());
        assert!(st["error"].is_null());
    }

    #[test]
    fn the_notice_goes_away_once_the_new_version_is_running() {
        let mut s = Stored::default();
        record(&mut s, Ok(Some(release("0.3.1"))), "0.3.0", at("2026-11-07T00:00:00Z"));
        assert_eq!(status_of(&s, "0.3.0")["update_available"], true);
        let st = status_of(&s, "0.3.1");
        assert_eq!(st["update_available"], false);
        assert_eq!(st["current"], "0.3.1");
        assert_eq!(st["latest"], "0.3.1");
    }

    #[test]
    fn the_status_before_any_check_says_so() {
        let st = status_of(&Stored::default(), "0.3.0");
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
    fn the_release_url_and_the_command_name_the_same_repository() {
        let repo = env!("CARGO_PKG_REPOSITORY").trim_start_matches("https://github.com/");
        assert!(DEFAULT_URL.contains(repo));
        assert!(UPGRADE_COMMAND.contains(repo));
    }
}
