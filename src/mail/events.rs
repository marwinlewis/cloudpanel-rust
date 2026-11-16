//! Delivery tracking and webhooks.
//!
//! Postfix logs every message twice in ways that matter here: `cleanup` names the queue id it gave
//! a Message-ID, and the delivery agents log `status=sent|deferred|bounced` per recipient under
//! that queue id. The service follows those lines in the journal and updates the message log.
//! Status changes are queued as webhook calls, signed the way Resend's (Svix) are, so existing
//! verification code works.

use super::store::{self, MessageLog};
use base64::Engine;
use rusqlite::Connection;
use serde_json::json;
use std::io::BufRead;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Every event type a webhook can subscribe to.
pub const EVENT_TYPES: &[&str] = &[
    "email.sent",
    "email.delivered",
    "email.delivery_delayed",
    "email.bounced",
];

#[derive(Debug, PartialEq, Eq)]
pub enum LogLine {
    MessageId {
        queue_id: String,
        message_id: String,
    },
    Status {
        queue_id: String,
        recipient: String,
        status: String,
        detail: String,
    },
}

fn is_queue_id(s: &str) -> bool {
    (6..=20).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Parse one Postfix log line (with or without the `postfix/smtp[123]: ` prefix).
pub fn parse_line(line: &str) -> Option<LogLine> {
    // Find "<queue id>: " anywhere: the prefix differs between `-o cat` and syslog files.
    let (queue_id, rest) = line.split(": ").collect::<Vec<_>>().windows(2).find_map(|w| {
        let qid = w[0].rsplit(' ').next()?;
        is_queue_id(qid).then_some(())?;
        let idx = line.find(&format!("{qid}: "))?;
        Some((qid.to_string(), line[idx + qid.len() + 2..].to_string()))
    })?;
    if let Some(mid) = rest.strip_prefix("message-id=") {
        let mid = mid.trim();
        return (!mid.is_empty()).then(|| LogLine::MessageId {
            queue_id,
            message_id: mid.to_string(),
        });
    }
    let to = rest.strip_prefix("to=<")?;
    let recipient = to.split('>').next()?.to_string();
    let status_at = rest.find(", status=")?;
    let after = &rest[status_at + ", status=".len()..];
    let status = after.split([' ', ',']).next()?.to_string();
    let detail = after
        .find('(')
        .map(|i| after[i + 1..].trim_end().trim_end_matches(')').to_string())
        .unwrap_or_default();
    Some(LogLine::Status {
        queue_id,
        recipient,
        status,
        detail,
    })
}

/// Record a parsed line. Lines about mail the service didn't send are ignored.
pub fn apply(conn: &Connection, line: &LogLine) -> rusqlite::Result<()> {
    match line {
        LogLine::MessageId { queue_id, message_id } => {
            if let Some(m) = store::message_by_message_id(conn, message_id)? {
                store::set_queue_id(conn, &m.id, queue_id)?;
            }
        }
        LogLine::Status {
            queue_id,
            recipient,
            status,
            detail,
        } => {
            let Some(m) = store::message_by_queue_id(conn, queue_id)? else {
                return Ok(());
            };
            let kind = match status.as_str() {
                "sent" => "delivered",
                "deferred" => "delivery_delayed",
                "bounced" | "expired" | "undeliverable" => "bounced",
                _ => return Ok(()),
            };
            store::add_event(conn, &m.id, kind, Some(recipient), Some(detail))?;
            let new_status = aggregate(conn, &m)?;
            if new_status != m.status {
                store::set_status(conn, &m.id, &new_status)?;
                let extra = json!({ "recipient": recipient, "detail": detail });
                emit(conn, &format!("email.{new_status}"), &m, Some(extra));
            }
        }
    }
    Ok(())
}

/// The message's status from its per-recipient events: any bounce wins, then all delivered, then
/// delayed when the latest word on someone is a deferral.
fn aggregate(conn: &Connection, m: &MessageLog) -> rusqlite::Result<String> {
    let events = store::events_for(conn, &m.id)?;
    let mut latest: std::collections::HashMap<String, String> = Default::default();
    for e in &events {
        if let Some(r) = &e.recipient {
            latest.insert(r.to_ascii_lowercase(), e.kind.clone());
        }
    }
    if latest.values().any(|k| k == "bounced") {
        return Ok("bounced".into());
    }
    let all_delivered =
        m.to.iter()
            .all(|r| latest.get(&r.to_ascii_lowercase()).is_some_and(|k| k == "delivered"));
    if all_delivered {
        return Ok("delivered".into());
    }
    if latest.values().any(|k| k == "delivery_delayed") {
        return Ok("delivery_delayed".into());
    }
    Ok(m.status.clone())
}

/// Queue `kind` for every webhook that wants it.
pub fn emit(conn: &Connection, kind: &str, m: &MessageLog, extra: Option<serde_json::Value>) {
    let Ok(hooks) = store::list_webhooks(conn) else { return };
    let mut data = json!({
        "email_id": m.id,
        "from": m.from,
        "to": m.to,
        "subject": m.subject,
        "created_at": m.created_at,
    });
    if let (Some(serde_json::Value::Object(x)), Some(d)) = (extra, data.as_object_mut()) {
        d.extend(x);
    }
    let payload = json!({ "type": kind, "created_at": super::now(), "data": data }).to_string();
    for h in hooks
        .iter()
        .filter(|h| h.events.is_empty() || h.events.iter().any(|e| e == kind))
    {
        if let Err(e) = store::enqueue_webhook(conn, &h.id, &payload) {
            tracing::warn!("could not queue webhook {}: {e}", h.id);
        }
    }
}

/// A new signing secret, `whsec_` + base64 like Svix's.
pub fn new_secret() -> String {
    use rand::RngCore;
    let mut b = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut b);
    format!("whsec_{}", base64::engine::general_purpose::STANDARD.encode(b))
}

/// The `svix-signature` value for a payload.
pub fn sign_payload(secret: &str, msg_id: &str, timestamp: i64, body: &str) -> Result<String, String> {
    let raw = secret.strip_prefix("whsec_").unwrap_or(secret);
    let key = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|_| "bad webhook secret".to_string())?;
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key);
    let tag = ring::hmac::sign(&k, format!("{msg_id}.{timestamp}.{body}").as_bytes());
    Ok(format!(
        "v1,{}",
        base64::engine::general_purpose::STANDARD.encode(tag.as_ref())
    ))
}

/// Seconds to wait before attempt `n` (1-based) of a failed call. None gives up.
fn backoff(attempt: u32) -> Option<i64> {
    [5, 300, 1800, 7200, 18_000, 36_000].get(attempt as usize).copied()
}

/// Deliver queued webhook calls, forever.
pub async fn run_webhooks(db: Arc<Mutex<Connection>>) {
    let http = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("cloudpanel-mail-webhooks")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("webhooks disabled: {e}");
            return;
        }
    };
    loop {
        let due = {
            let c = db.lock().unwrap_or_else(|e| e.into_inner());
            store::due_webhooks(&c, 50).unwrap_or_default()
        };
        for out in due {
            let hook = {
                let c = db.lock().unwrap_or_else(|e| e.into_inner());
                store::get_webhook(&c, &out.webhook).ok().flatten()
            };
            let Some(hook) = hook else { continue };
            let ts = chrono::Utc::now().timestamp();
            let ok = match sign_payload(&hook.secret, &out.id, ts, &out.payload) {
                Ok(sig) => http
                    .post(&hook.url)
                    .header("content-type", "application/json")
                    .header("svix-id", &out.id)
                    .header("svix-timestamp", ts.to_string())
                    .header("svix-signature", sig)
                    .body(out.payload.clone())
                    .send()
                    .await
                    .is_ok_and(|r| r.status().is_success()),
                Err(_) => false,
            };
            let c = db.lock().unwrap_or_else(|e| e.into_inner());
            if ok {
                let _ = store::webhook_done(&c, &out.id);
            } else if let Some(wait) = backoff(out.attempts) {
                let next = (chrono::Utc::now() + chrono::Duration::seconds(wait))
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                let _ = store::webhook_retry(&c, &out.id, &next);
            } else {
                tracing::warn!(
                    "webhook {} to {} failed {} times; dropped",
                    out.id,
                    hook.url,
                    out.attempts + 1
                );
                let _ = store::webhook_done(&c, &out.id);
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// Follow Postfix's lines in the journal, forever (a blocking thread).
pub fn follow_journal(db: Arc<Mutex<Connection>>, cursor_file: std::path::PathBuf) {
    loop {
        let cursor = format!("--cursor-file={}", cursor_file.display());
        let child = std::process::Command::new("journalctl")
            .args([
                "--follow",
                "--output=cat",
                cursor.as_str(),
                "-t",
                "postfix/cleanup",
                "-t",
                "postfix/smtp",
                "-t",
                "postfix/error",
                "-t",
                "postfix/bounce",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn();
        match child {
            Ok(mut child) => {
                if let Some(out) = child.stdout.take() {
                    for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
                        if let Some(parsed) = parse_line(&line) {
                            let c = db.lock().unwrap_or_else(|e| e.into_inner());
                            if let Err(e) = apply(&c, &parsed) {
                                tracing::warn!("could not record a delivery event: {e}");
                            }
                        }
                    }
                }
                let _ = child.wait();
            }
            Err(e) => tracing::warn!("journalctl unavailable, delivery status won't update: {e}"),
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_postfix_lines() {
        assert_eq!(
            parse_line("4F9D61E0A2: message-id=<abc@mail.example.com>"),
            Some(LogLine::MessageId {
                queue_id: "4F9D61E0A2".into(),
                message_id: "<abc@mail.example.com>".into()
            })
        );
        let l = "Nov 16 10:00:00 host postfix/smtp[123]: 4bTpLm5ZY2zJrNC: to=<you@gmail.com>, relay=gmail-smtp-in.l.google.com[142.250.1.27]:25, delay=1.2, delays=0.1/0/0.5/0.6, dsn=2.0.0, status=sent (250 2.0.0 OK  1700000000 x)";
        assert_eq!(
            parse_line(l),
            Some(LogLine::Status {
                queue_id: "4bTpLm5ZY2zJrNC".into(),
                recipient: "you@gmail.com".into(),
                status: "sent".into(),
                detail: "250 2.0.0 OK  1700000000 x".into()
            })
        );
        assert!(parse_line("4F9D61E0A2: removed").is_none());
        assert!(parse_line("connect from unknown[1.2.3.4]").is_none());
        let deferred = "ABCDEF1234: to=<a@b.c>, relay=none, delay=30, status=deferred (connect to b.c[1.2.3.4]:25: Connection timed out)";
        assert!(matches!(parse_line(deferred), Some(LogLine::Status { status, .. }) if status == "deferred"));
    }

    fn sent_message(conn: &Connection, to: &[&str]) -> MessageLog {
        let now = crate::mail::now();
        let m = MessageLog {
            id: "m1".into(),
            key_id: "k".into(),
            source: "api".into(),
            from: "me@example.com".into(),
            to: to.iter().map(|s| s.to_string()).collect(),
            subject: "s".into(),
            message_id: "<1@h>".into(),
            queue_id: None,
            status: "sent".into(),
            created_at: now.clone(),
            updated_at: now,
        };
        store::add_message(conn, &m).unwrap();
        m
    }

    fn status(conn: &Connection) -> String {
        store::get_message(conn, "m1").unwrap().unwrap().status
    }

    #[test]
    fn tracks_delivery_and_queues_webhooks() {
        let c = store::open_memory();
        store::add_webhook(
            &c,
            &store::Webhook {
                id: "w".into(),
                url: "https://example.com/h".into(),
                events: vec!["email.delivered".into(), "email.bounced".into()],
                secret: new_secret(),
                created_at: crate::mail::now(),
            },
        )
        .unwrap();
        sent_message(&c, &["a@x.com", "b@y.com"]);
        let line = |s: &str| parse_line(s).unwrap();
        apply(&c, &line("QID0000001: message-id=<1@h>")).unwrap();
        apply(&c, &line("QID0000001: to=<a@x.com>, status=sent (ok)")).unwrap();
        assert_eq!(status(&c), "sent");
        apply(&c, &line("QID0000001: to=<b@y.com>, status=deferred (try later)")).unwrap();
        assert_eq!(status(&c), "delivery_delayed");
        apply(&c, &line("QID0000001: to=<b@y.com>, status=sent (ok)")).unwrap();
        assert_eq!(status(&c), "delivered");
        // Only delivered is subscribed (not delivery_delayed).
        let due = store::due_webhooks(&c, 10).unwrap();
        assert_eq!(due.len(), 1);
        assert!(due[0].payload.contains("\"type\":\"email.delivered\""));
        // Lines about other mail are ignored.
        apply(&c, &line("OTHERQID99: to=<z@z.com>, status=bounced (no)")).unwrap();
        assert_eq!(status(&c), "delivered");
    }

    #[test]
    fn signatures_match_svix() {
        // Known answer computed with Svix's documented scheme (HMAC-SHA256 over "id.ts.body").
        let sig = sign_payload(
            "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw",
            "msg_p5jXN8AQM9LWM0D4loKWxJek",
            1614265330,
            r#"{"test": 2432232314}"#,
        )
        .unwrap();
        assert_eq!(sig, "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=");
        assert!(new_secret().starts_with("whsec_"));
        assert_eq!(backoff(0), Some(5));
        assert_eq!(backoff(6), None);
    }
}
