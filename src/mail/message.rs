//! Messages: reading the few headers the service needs from submitted mail, and building mail from
//! an HTTP API request (the same JSON shape as Resend's `POST /emails`).

use base64::Engine;
use lettre::message::header::{ContentType, HeaderName, HeaderValue};
use lettre::message::{Attachment, Mailbox, MultiPart, SinglePart};
use serde::{Deserialize, Deserializer};

/// The bare address in a header like `"Name" <a@b.c>`, `a@b.c (Name)` or `a@b.c`. The first one
/// when there are several.
pub fn first_address(value: &str) -> Option<String> {
    let v = value.replace("\r\n", " ");
    let candidate = match (v.find('<'), v.find('>')) {
        (Some(s), Some(e)) if e > s => v[s + 1..e].to_string(),
        _ => v.split(',').next()?.split('(').next()?.to_string(),
    };
    let a = candidate.trim().trim_matches('"').trim();
    (a.contains('@') && !a.contains(char::is_whitespace)).then(|| a.to_string())
}

/// The value of the first header named `name`, unfolded.
pub fn header(raw: &[u8], name: &str) -> Option<String> {
    let msg = super::dkim::to_crlf(raw);
    let (head, _) = super::dkim::split(&msg);
    super::dkim::header_fields(head)
        .into_iter()
        .find(|(n, _)| n.trim().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.replace("\r\n", "").trim().to_string())
}

/// Count of header fields named `name`.
pub fn header_count(raw: &[u8], name: &str) -> usize {
    let msg = super::dkim::to_crlf(raw);
    let (head, _) = super::dkim::split(&msg);
    super::dkim::header_fields(head)
        .iter()
        .filter(|(n, _)| n.trim().eq_ignore_ascii_case(name))
        .count()
}

/// Put `Message-ID` on top of a message that has none.
pub fn ensure_message_id(raw: Vec<u8>, host: &str) -> (Vec<u8>, String) {
    if let Some(id) = header(&raw, "message-id").filter(|v| !v.is_empty()) {
        return (raw, id);
    }
    let id = format!("<{}@{host}>", super::new_id());
    let mut out = format!("Message-ID: {id}\r\n").into_bytes();
    out.extend(raw);
    (out, id)
}

fn one_or_many<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match Option::<OneOrMany>::deserialize(d)? {
        None => Vec::new(),
        Some(OneOrMany::One(s)) => vec![s],
        Some(OneOrMany::Many(v)) => v,
    })
}

#[derive(Deserialize, Debug, Default, Clone)]
pub struct AttachmentIn {
    pub filename: String,
    /// Base64 content.
    pub content: String,
    #[serde(default)]
    pub content_type: Option<String>,
}

/// Accepted so Resend clients that send tags work; not stored.
#[allow(dead_code)]
#[derive(Deserialize, Debug, Default, Clone)]
pub struct Tag {
    pub name: String,
    pub value: String,
}

/// `POST /emails` body. Field names match Resend's API.
#[derive(Deserialize, Debug, Default, Clone)]
pub struct SendRequest {
    pub from: String,
    #[serde(deserialize_with = "one_or_many")]
    pub to: Vec<String>,
    pub subject: String,
    #[serde(default, deserialize_with = "one_or_many")]
    pub cc: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    pub bcc: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    pub reply_to: Vec<String>,
    #[serde(default)]
    pub html: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub attachments: Vec<AttachmentIn>,
    /// Accepted for compatibility with Resend clients.
    #[allow(dead_code)]
    #[serde(default)]
    pub tags: Vec<Tag>,
}

/// A built message ready for the send path.
#[derive(Debug)]
pub struct Built {
    pub raw: Vec<u8>,
    pub envelope_from: String,
    pub recipients: Vec<String>,
    #[allow(dead_code)]
    pub message_id: String,
}

fn mailbox(s: &str, field: &str) -> Result<Mailbox, String> {
    s.trim()
        .parse::<Mailbox>()
        .map_err(|_| format!("Invalid `{field}` address: {s}"))
}

/// Headers an API caller may not set, because the service sets them or they'd confuse delivery.
const RESERVED: &[&str] = &[
    "from",
    "to",
    "cc",
    "bcc",
    "reply-to",
    "subject",
    "message-id",
    "date",
    "mime-version",
    "content-type",
    "content-transfer-encoding",
    "dkim-signature",
    "return-path",
    "received",
    "sender",
];

/// Turn an API request into a MIME message.
pub fn build(req: &SendRequest, host: &str) -> Result<Built, String> {
    if req.to.is_empty() {
        return Err("`to` needs at least one address".into());
    }
    let total = req.to.len() + req.cc.len() + req.bcc.len();
    if total > super::MAX_RECIPIENTS {
        return Err(format!("At most {} recipients per email", super::MAX_RECIPIENTS));
    }
    if req.html.as_deref().unwrap_or("").is_empty() && req.text.as_deref().unwrap_or("").is_empty() {
        return Err("Give `html`, `text` or both".into());
    }
    if req.subject.contains(['\r', '\n']) {
        return Err("`subject` can't contain line breaks".into());
    }
    let from = mailbox(&req.from, "from")?;
    let message_id = format!("<{}@{host}>", super::new_id());
    let mut b = lettre::Message::builder()
        .from(from.clone())
        .subject(req.subject.clone())
        .message_id(Some(message_id.clone()));
    for a in &req.to {
        b = b.to(mailbox(a, "to")?);
    }
    for a in &req.cc {
        b = b.cc(mailbox(a, "cc")?);
    }
    for a in &req.bcc {
        b = b.bcc(mailbox(a, "bcc")?);
    }
    for a in &req.reply_to {
        b = b.reply_to(mailbox(a, "reply_to")?);
    }
    for (name, value) in &req.headers {
        if RESERVED.contains(&name.to_ascii_lowercase().as_str()) {
            return Err(format!("Header {name} can't be set here"));
        }
        if value.contains(['\r', '\n']) {
            return Err(format!("Header {name} can't contain line breaks"));
        }
        let hn = HeaderName::new_from_ascii(name.clone()).map_err(|_| format!("Invalid header name {name}"))?;
        b = b.raw_header(HeaderValue::new(hn, value.clone()));
    }

    let body = match (
        req.text.as_deref().filter(|s| !s.is_empty()),
        req.html.as_deref().filter(|s| !s.is_empty()),
    ) {
        (Some(t), Some(h)) => MultiPart::alternative_plain_html(t.to_string(), h.to_string()),
        (Some(t), None) => MultiPart::mixed().singlepart(SinglePart::plain(t.to_string())),
        (None, Some(h)) => MultiPart::mixed().singlepart(SinglePart::html(h.to_string())),
        (None, None) => unreachable!("checked above"),
    };
    let message = if req.attachments.is_empty() {
        b.multipart(body)
    } else {
        let mut mixed = MultiPart::mixed().multipart(body);
        for a in &req.attachments {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(a.content.trim())
                .map_err(|_| format!("Attachment {} isn't valid base64", a.filename))?;
            let ct = a
                .content_type
                .clone()
                .unwrap_or_else(|| mime_guess::from_path(&a.filename).first_or_octet_stream().to_string());
            let ct = ContentType::parse(&ct).map_err(|_| format!("Invalid content type for {}", a.filename))?;
            mixed = mixed.singlepart(Attachment::new(a.filename.clone()).body(bytes, ct));
        }
        b.multipart(mixed)
    }
    .map_err(|e| format!("Could not build the email: {e}"))?;

    let recipients = message.envelope().to().iter().map(ToString::to_string).collect();
    Ok(Built {
        raw: message.formatted(),
        envelope_from: from.email.to_string(),
        recipients,
        message_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_from_headers() {
        assert_eq!(
            first_address("\"Me\" <me@example.com>").as_deref(),
            Some("me@example.com")
        );
        assert_eq!(first_address(" me@example.com (Me)").as_deref(), Some("me@example.com"));
        assert_eq!(first_address("a@x.com, b@y.com").as_deref(), Some("a@x.com"));
        assert_eq!(first_address("undisclosed"), None);
    }

    #[test]
    fn reads_headers_and_adds_message_id() {
        let raw = b"From: Me <me@example.com>\nSubject: Hi\n there\n\nbody".to_vec();
        assert_eq!(header(&raw, "subject").as_deref(), Some("Hi there"));
        assert_eq!(header_count(&raw, "from"), 1);
        let (with, id) = ensure_message_id(raw, "mail.example.com");
        assert!(id.ends_with("@mail.example.com>"));
        assert_eq!(header(&with, "message-id").as_deref(), Some(id.as_str()));
        let (same, id2) = ensure_message_id(with.clone(), "x");
        assert_eq!(id, id2);
        assert_eq!(same, with);
    }

    #[test]
    fn builds_from_resend_shaped_json() {
        let req: SendRequest = serde_json::from_str(
            r#"{"from":"Acme <hi@example.com>","to":"you@example.org","bcc":["hidden@example.net"],
                "subject":"Hello","html":"<p>Hi</p>","text":"Hi","headers":{"X-Entity-Ref-ID":"123"},
                "attachments":[{"filename":"a.txt","content":"aGVsbG8="}],"tags":[{"name":"k","value":"v"}]}"#,
        )
        .unwrap();
        let b = build(&req, "mail.example.com").unwrap();
        let text = String::from_utf8_lossy(&b.raw);
        assert_eq!(b.envelope_from, "hi@example.com");
        assert_eq!(b.recipients, vec!["you@example.org", "hidden@example.net"]);
        assert!(!text.contains("hidden@example.net"), "Bcc must not be in the headers");
        assert!(text.contains("X-Entity-Ref-ID: 123"));
        assert!(text.contains(&format!("Message-ID: {}", b.message_id)));
        assert!(text.contains("multipart/alternative"));
        assert!(text.contains("filename=\"a.txt\""));
    }

    #[test]
    fn rejects_bad_requests() {
        let mut req = SendRequest {
            from: "hi@example.com".into(),
            to: vec!["you@example.org".into()],
            subject: "x".into(),
            text: Some("t".into()),
            ..Default::default()
        };
        assert!(build(&req, "h").is_ok());
        req.headers.insert("Bcc".into(), "x@y.z".into());
        assert!(build(&req, "h").is_err());
        req.headers.clear();
        req.subject = "a\r\nBcc: x@y.z".into();
        assert!(build(&req, "h").is_err());
        req.subject = "x".into();
        req.text = None;
        assert!(build(&req, "h").is_err());
        req.text = Some("t".into());
        req.to = (0..51).map(|i| format!("u{i}@example.org")).collect();
        assert!(build(&req, "h").is_err());
    }
}
