//! The send path shared by SMTP and HTTP: check the key and sender, enforce limits, sign with DKIM,
//! log, and hand the message to Postfix.

use super::store::{self, ApiKey, MessageLog};
use super::{dkim, events, message, MailConfig};
use rusqlite::Connection;
use std::sync::{Arc, Mutex};

/// Gives a signed message to the MTA.
pub trait Handoff: Send + Sync {
    fn submit(&self, envelope_from: &str, recipients: &[String], raw: &[u8]) -> Result<(), String>;
}

/// Postfix's `sendmail`. Only root and the service's user may submit (`authorized_submit_users`).
pub struct Sendmail {
    pub path: std::path::PathBuf,
}

impl Handoff for Sendmail {
    fn submit(&self, envelope_from: &str, recipients: &[String], raw: &[u8]) -> Result<(), String> {
        use crate::services::cmd::{run_with, CmdOpts};
        let mut args: Vec<&str> = vec!["-i", "-f", envelope_from, "--"];
        args.extend(recipients.iter().map(String::as_str));
        let r = run_with(
            &self.path.to_string_lossy(),
            &args,
            &CmdOpts::default().stdin(raw.to_vec()).timeout(60),
        );
        if r.success() {
            Ok(())
        } else {
            Err(format!("sendmail failed: {}", r.combined().trim()))
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SendError {
    /// The request itself is wrong (422 / SMTP 550-554).
    Invalid(String),
    /// The key may not send this (403 / SMTP 550).
    Forbidden(String),
    /// Over the key's hourly limit (429 / SMTP 451).
    RateLimited(u32),
    /// Our side failed (500 / SMTP 451).
    Internal(String),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(m) | Self::Forbidden(m) | Self::Internal(m) => f.write_str(m),
            Self::RateLimited(n) => write!(f, "This key may send {n} emails per hour; try again later"),
        }
    }
}

/// Where a message came from, kept in its log row.
#[derive(Clone, Copy)]
pub enum Source {
    Smtp,
    Api,
}

pub struct Mailer {
    pub config: MailConfig,
    pub db: Arc<Mutex<Connection>>,
    pub handoff: Arc<dyn Handoff>,
}

impl Mailer {
    pub fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Check that `key` may send from `address`. Used at SMTP MAIL FROM and again on the message.
    pub fn check_sender(&self, key: &ApiKey, address: &str) -> Result<String, SendError> {
        let domain =
            super::domain_of(address).ok_or_else(|| SendError::Invalid(format!("Invalid sender {address}")))?;
        if let Some(only) = &key.domain {
            if !only.eq_ignore_ascii_case(&domain) {
                return Err(SendError::Forbidden(format!("This key may only send from {only}")));
            }
        }
        let d = store::get_domain(&self.conn(), &domain).map_err(|e| SendError::Internal(e.to_string()))?;
        match d {
            Some(d) if d.verified => Ok(domain),
            Some(_) => Err(SendError::Forbidden(format!(
                "{domain} isn't verified yet. Run: cloudpanel mail-domain-verify --domain {domain}"
            ))),
            None => Err(SendError::Forbidden(format!(
                "{domain} isn't a sending domain on this server"
            ))),
        }
    }

    /// Validate, sign, log and submit one message. Returns its id.
    pub fn send(
        &self,
        key: &ApiKey,
        source: Source,
        envelope_from: &str,
        recipients: &[String],
        raw: Vec<u8>,
    ) -> Result<String, SendError> {
        if recipients.is_empty() {
            return Err(SendError::Invalid("No recipients".into()));
        }
        if recipients.len() > super::MAX_RECIPIENTS {
            return Err(SendError::Invalid(format!(
                "At most {} recipients per email",
                super::MAX_RECIPIENTS
            )));
        }
        if raw.len() > super::MAX_MESSAGE_BYTES {
            return Err(SendError::Invalid("The message is too large".into()));
        }
        if message::header_count(&raw, "from") != 1 {
            return Err(SendError::Invalid("The message needs exactly one From header".into()));
        }
        let header_from = message::header(&raw, "from")
            .and_then(|v| message::first_address(&v))
            .ok_or_else(|| SendError::Invalid("The From header has no address".into()))?;
        let domain = self.check_sender(key, &header_from)?;
        if envelope_from != header_from {
            // Gmail and most clients use the same address for both; anything else must be ours too.
            self.check_sender(key, envelope_from)?;
        }

        let since =
            (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let sent =
            store::count_sent_since(&self.conn(), &key.id, &since).map_err(|e| SendError::Internal(e.to_string()))?;
        if sent >= key.hourly_limit {
            return Err(SendError::RateLimited(key.hourly_limit));
        }

        let (raw, message_id) = message::ensure_message_id(raw, &self.config.hostname);
        let subject = message::header(&raw, "subject").unwrap_or_default();
        let signer = dkim::Signer::load(&self.config.dkim_key_path(&domain), &domain, super::DKIM_SELECTOR)
            .map_err(SendError::Internal)?;
        let signed = signer
            .sign(&raw, chrono::Utc::now().timestamp())
            .map_err(SendError::Invalid)?;

        let now = super::now();
        let log = MessageLog {
            id: super::new_id(),
            key_id: key.id.clone(),
            source: match source {
                Source::Smtp => "smtp".into(),
                Source::Api => "api".into(),
            },
            from: header_from,
            to: recipients.to_vec(),
            subject: subject.chars().take(300).collect(),
            message_id,
            queue_id: None,
            status: "sent".into(),
            created_at: now.clone(),
            updated_at: now,
        };
        {
            // Logged before the handoff, so Postfix's first log line about it always finds the row.
            let conn = self.conn();
            store::add_message(&conn, &log).map_err(|e| SendError::Internal(e.to_string()))?;
            let _ = store::touch_key(&conn, &key.id);
        }
        if let Err(e) = self.handoff.submit(envelope_from, recipients, &signed) {
            let conn = self.conn();
            let _ = store::set_status(&conn, &log.id, "failed");
            let _ = store::add_event(&conn, &log.id, "failed", None, Some(&e));
            tracing::error!("handing message {} to Postfix failed: {e}", log.id);
            return Err(SendError::Internal("The mail server couldn't queue the message".into()));
        }
        let conn = self.conn();
        let _ = store::add_event(&conn, &log.id, "sent", None, None);
        events::emit(&conn, "email.sent", &log, None);
        Ok(log.id)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Envelope sender, recipients, message.
    pub type Submission = (String, Vec<String>, Vec<u8>);

    /// Records what would have gone to Postfix.
    #[derive(Default)]
    pub struct Captured(pub Mutex<Vec<Submission>>);
    impl Handoff for Captured {
        fn submit(&self, f: &str, r: &[String], raw: &[u8]) -> Result<(), String> {
            self.0.lock().unwrap().push((f.into(), r.to_vec(), raw.to_vec()));
            Ok(())
        }
    }

    /// A mailer with `example.com` verified and its test DKIM key, and a key for it.
    pub fn fixture() -> (Mailer, Arc<Captured>, ApiKey, String, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mut config = MailConfig::from_env();
        config.state_dir = dir.path().to_path_buf();
        config.hostname = "mail.example.com".into();
        std::fs::create_dir_all(config.dkim_dir()).unwrap();
        let pem = include_str!("testdata/dkim-test-key.pem");
        std::fs::write(config.dkim_key_path("example.com"), pem).unwrap();
        let conn = store::open_memory();
        store::add_domain(&conn, "example.com", &dkim::public_key_b64(pem).unwrap()).unwrap();
        store::set_domain_verified(&conn, "example.com", true).unwrap();
        store::add_domain(&conn, "pending.com", "x").unwrap();
        let (key, full) = super::super::keys::generate("test", "sending", None, 3);
        store::add_key(&conn, &key).unwrap();
        let cap = Arc::new(Captured::default());
        let m = Mailer {
            config,
            db: Arc::new(Mutex::new(conn)),
            handoff: cap.clone(),
        };
        (m, cap, key, full, dir)
    }

    fn raw(from: &str) -> Vec<u8> {
        format!("From: {from}\r\nTo: you@example.org\r\nSubject: Hi\r\n\r\nHello\r\n").into_bytes()
    }

    #[test]
    fn sends_signed_and_logged() {
        let (m, cap, key, _, _d) = fixture();
        let id = m
            .send(
                &key,
                Source::Smtp,
                "me@example.com",
                &["you@example.org".into()],
                raw("Me <me@example.com>"),
            )
            .unwrap();
        let sent = cap.0.lock().unwrap();
        let text = String::from_utf8_lossy(&sent[0].2);
        assert!(text.starts_with("DKIM-Signature: v=1;"));
        assert!(text.contains("Message-ID: <"));
        let pk = store::get_domain(&m.conn(), "example.com")
            .unwrap()
            .unwrap()
            .dkim_public;
        dkim::verify(&sent[0].2, &pk).unwrap();
        let log = store::get_message(&m.conn(), &id).unwrap().unwrap();
        assert_eq!(log.status, "sent");
        assert_eq!(log.subject, "Hi");
    }

    #[test]
    fn refuses_other_domains_and_spoofed_envelopes() {
        let (m, cap, key, _, _d) = fixture();
        let to = vec!["you@example.org".to_string()];
        let e = m
            .send(&key, Source::Smtp, "x@gmail.com", &to, raw("x@gmail.com"))
            .unwrap_err();
        assert!(matches!(e, SendError::Forbidden(_)));
        let e = m
            .send(&key, Source::Smtp, "x@pending.com", &to, raw("x@pending.com"))
            .unwrap_err();
        assert!(e.to_string().contains("isn't verified"));
        let e = m
            .send(&key, Source::Smtp, "x@gmail.com", &to, raw("me@example.com"))
            .unwrap_err();
        assert!(matches!(e, SendError::Forbidden(_)));
        let two_from = b"From: me@example.com\r\nFrom: x@gmail.com\r\n\r\nx".to_vec();
        assert!(matches!(
            m.send(&key, Source::Smtp, "me@example.com", &to, two_from),
            Err(SendError::Invalid(_))
        ));
        assert!(cap.0.lock().unwrap().is_empty());
    }

    #[test]
    fn domain_scoped_keys_and_hourly_limit() {
        let (m, _cap, mut key, _, _d) = fixture();
        let to = vec!["you@example.org".to_string()];
        key.domain = Some("other.com".into());
        assert!(matches!(
            m.send(&key, Source::Api, "me@example.com", &to, raw("me@example.com")),
            Err(SendError::Forbidden(_))
        ));
        key.domain = None;
        for _ in 0..3 {
            m.send(&key, Source::Api, "me@example.com", &to, raw("me@example.com"))
                .unwrap();
        }
        assert_eq!(
            m.send(&key, Source::Api, "me@example.com", &to, raw("me@example.com")),
            Err(SendError::RateLimited(3))
        );
    }
}
