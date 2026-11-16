//! The submission server: ESMTP on 587 (STARTTLS) and 465 (implicit TLS).
//!
//! Only authenticated clients can send, only after TLS, and only from domains their key allows.
//! Mail for anyone else is never accepted here; inbound mail goes to Postfix on port 25.

use super::keys;
use super::send::{Mailer, SendError, Source};
use super::store::ApiKey;
use base64::Engine;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

const MAX_LINE: usize = 1000;
const IDLE: Duration = Duration::from_secs(300);
const MAX_AUTH_FAILURES: u32 = 5;
const AUTH_WINDOW: Duration = Duration::from_secs(15 * 60);
const MAX_CONNECTIONS: usize = 256;

pub type TlsConfig = Arc<RwLock<Option<Arc<rustls::ServerConfig>>>>;

/// Load the certificate and key into a TLS config.
pub fn load_tls(cert: &std::path::Path, key: &std::path::Path) -> Result<Arc<rustls::ServerConfig>, String> {
    let cert_pem = std::fs::read(cert).map_err(|e| format!("Could not read {}: {e}", cert.display()))?;
    let key_pem = std::fs::read(key).map_err(|e| format!("Could not read {}: {e}", key.display()))?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<_, _>>()
        .map_err(|_| format!("{} isn't a PEM certificate", cert.display()))?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(|_| format!("{} isn't a PEM key", key.display()))?
        .ok_or_else(|| format!("No private key in {}", key.display()))?;
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS certificate rejected: {e}"))?;
    Ok(Arc::new(cfg))
}

/// Failed AUTH attempts per client address.
#[derive(Default)]
pub struct AuthLimiter(Mutex<HashMap<IpAddr, (u32, Instant)>>);

impl AuthLimiter {
    pub fn blocked(&self, ip: IpAddr) -> bool {
        let map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        map.get(&ip)
            .is_some_and(|(n, since)| *n >= MAX_AUTH_FAILURES && since.elapsed() < AUTH_WINDOW)
    }

    pub fn fail(&self, ip: IpAddr) {
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() > 10_000 {
            map.retain(|_, (_, since)| since.elapsed() < AUTH_WINDOW);
        }
        let e = map.entry(ip).or_insert((0, Instant::now()));
        if e.1.elapsed() >= AUTH_WINDOW {
            *e = (0, Instant::now());
        }
        e.0 += 1;
    }

    pub fn succeed(&self, ip: IpAddr) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).remove(&ip);
    }
}

pub struct Server {
    pub mailer: Arc<Mailer>,
    pub tls: TlsConfig,
    pub limiter: AuthLimiter,
    pub hostname: String,
}

/// What a session ended with.
enum End {
    Closed,
    /// The client asked for STARTTLS on a plain connection.
    StartTls,
}

#[derive(Default)]
struct Txn {
    from: Option<String>,
    rcpts: Vec<String>,
}

/// Read one line (up to LF) of at most `max` bytes. None on EOF. Overlong lines are an error.
async fn read_line<R: AsyncRead + Unpin>(r: &mut BufReader<R>, max: usize) -> std::io::Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    loop {
        let buf = tokio::time::timeout(IDLE, r.fill_buf())
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "idle"))??;
        if buf.is_empty() {
            return Ok(if out.is_empty() { None } else { Some(out) });
        }
        let (chunk, done) = match buf.iter().position(|b| *b == b'\n') {
            Some(i) => (&buf[..=i], true),
            None => (buf, false),
        };
        if out.len() + chunk.len() > max {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "line too long"));
        }
        out.extend_from_slice(chunk);
        let n = chunk.len();
        r.consume(n);
        if done {
            return Ok(Some(out));
        }
    }
}

fn trim_eol(line: &[u8]) -> String {
    String::from_utf8_lossy(line).trim_end_matches(['\r', '\n']).to_string()
}

/// `<addr>` from `FROM:<addr> SIZE=…` or `TO:<addr>`. `<>` gives an empty string.
fn path_arg(rest: &str, prefix: &str) -> Option<(String, String)> {
    let r = rest.trim_start();
    if r.len() < prefix.len() || !r[..prefix.len()].eq_ignore_ascii_case(prefix) {
        return None;
    }
    let r = r[prefix.len()..].trim_start();
    let r = r.strip_prefix('<')?;
    let end = r.find('>')?;
    Some((r[..end].trim().to_string(), r[end + 1..].trim().to_string()))
}

fn send_error_reply(e: &SendError) -> String {
    match e {
        SendError::Invalid(m) => format!("554 5.6.0 {m}"),
        SendError::Forbidden(m) => format!("550 5.7.1 {m}"),
        SendError::RateLimited(_) => format!("451 4.7.1 {e}"),
        SendError::Internal(m) => format!("451 4.3.0 {m}"),
    }
}

impl Server {
    async fn reply<W: AsyncWrite + Unpin>(w: &mut W, text: &str) -> std::io::Result<()> {
        w.write_all(text.as_bytes()).await?;
        w.write_all(b"\r\n").await?;
        w.flush().await
    }

    fn tls_available(&self) -> bool {
        self.tls.read().unwrap_or_else(|e| e.into_inner()).is_some()
    }

    async fn check_key(&self, ip: IpAddr, secret: &str) -> Option<ApiKey> {
        let mailer = self.mailer.clone();
        let secret = secret.to_string();
        let key = tokio::task::spawn_blocking(move || keys::authenticate(&mailer.conn(), &secret))
            .await
            .ok()
            .flatten();
        match &key {
            Some(_) => self.limiter.succeed(ip),
            None => {
                self.limiter.fail(ip);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        key
    }

    /// One SMTP conversation. `greet` sends the banner (not after STARTTLS).
    async fn session<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
        peer: SocketAddr,
        secure: bool,
        greet: bool,
    ) -> std::io::Result<(End, S)> {
        let mut r = BufReader::new(stream);
        if greet {
            Self::reply(r.get_mut(), &format!("220 {} ESMTP CloudPanel", self.hostname)).await?;
        }
        let ip = peer.ip();
        let mut helo = false;
        let mut key: Option<ApiKey> = None;
        let mut txn = Txn::default();
        let mut errors = 0u32;

        while let Some(raw) = read_line(&mut r, MAX_LINE).await? {
            let line = trim_eol(&raw);
            let (verb, rest) = line.split_once(' ').unwrap_or((line.as_str(), ""));
            let verb = verb.to_ascii_uppercase();
            match verb.as_str() {
                "EHLO" | "HELO" => {
                    helo = true;
                    txn = Txn::default();
                    if verb == "HELO" {
                        Self::reply(r.get_mut(), &format!("250 {}", self.hostname)).await?;
                        continue;
                    }
                    let mut caps = vec![
                        self.hostname.clone(),
                        format!("SIZE {}", super::MAX_MESSAGE_BYTES),
                        "8BITMIME".into(),
                        "ENHANCEDSTATUSCODES".into(),
                    ];
                    if !secure && self.tls_available() {
                        caps.push("STARTTLS".into());
                    }
                    if secure {
                        caps.push("AUTH PLAIN LOGIN".into());
                    }
                    let n = caps.len();
                    let mut out = String::new();
                    for (i, c) in caps.iter().enumerate() {
                        out.push_str(&format!("250{}{c}\r\n", if i + 1 == n { ' ' } else { '-' }));
                    }
                    r.get_mut().write_all(out.as_bytes()).await?;
                    r.get_mut().flush().await?;
                }
                "STARTTLS" => {
                    if secure {
                        Self::reply(r.get_mut(), "503 5.5.1 TLS already active").await?;
                    } else if !self.tls_available() {
                        Self::reply(r.get_mut(), "454 4.7.0 TLS not available").await?;
                    } else {
                        // Anything pipelined after STARTTLS must not survive into the TLS session.
                        if !r.buffer().is_empty() {
                            Self::reply(r.get_mut(), "501 5.5.4 No commands may follow STARTTLS").await?;
                            return Ok((End::Closed, r.into_inner()));
                        }
                        Self::reply(r.get_mut(), "220 2.0.0 Ready to start TLS").await?;
                        return Ok((End::StartTls, r.into_inner()));
                    }
                }
                "AUTH" => {
                    if !secure {
                        Self::reply(r.get_mut(), "538 5.7.11 Encryption required: use STARTTLS or port 465").await?;
                        continue;
                    }
                    if key.is_some() {
                        Self::reply(r.get_mut(), "503 5.5.1 Already authenticated").await?;
                        continue;
                    }
                    if self.limiter.blocked(ip) {
                        Self::reply(r.get_mut(), "421 4.7.0 Too many failed logins; try again later").await?;
                        return Ok((End::Closed, r.into_inner()));
                    }
                    let (mech, initial) = rest.split_once(' ').unwrap_or((rest, ""));
                    let creds = match mech.to_ascii_uppercase().as_str() {
                        "PLAIN" => {
                            let data = if initial.is_empty() {
                                Self::reply(r.get_mut(), "334 ").await?;
                                match read_line(&mut r, 4096).await? {
                                    Some(l) => trim_eol(&l),
                                    None => break,
                                }
                            } else {
                                initial.to_string()
                            };
                            decode_plain(&data)
                        }
                        "LOGIN" => {
                            let user = if initial.is_empty() {
                                Self::reply(r.get_mut(), "334 VXNlcm5hbWU6").await?;
                                match read_line(&mut r, 4096).await? {
                                    Some(l) => trim_eol(&l),
                                    None => break,
                                }
                            } else {
                                initial.to_string()
                            };
                            Self::reply(r.get_mut(), "334 UGFzc3dvcmQ6").await?;
                            let pass = match read_line(&mut r, 4096).await? {
                                Some(l) => trim_eol(&l),
                                None => break,
                            };
                            match (b64(&user), b64(&pass)) {
                                (Some(u), Some(p)) => Some((u, p)),
                                _ => None,
                            }
                        }
                        _ => {
                            Self::reply(r.get_mut(), "504 5.5.4 Use AUTH PLAIN or AUTH LOGIN").await?;
                            continue;
                        }
                    };
                    let Some((user, pass)) = creds else {
                        Self::reply(r.get_mut(), "501 5.5.2 Malformed credentials").await?;
                        continue;
                    };
                    let user_ok = user.eq_ignore_ascii_case(super::SMTP_USERNAME);
                    match (user_ok, self.check_key(ip, &pass).await) {
                        (true, Some(k)) => {
                            key = Some(k);
                            Self::reply(r.get_mut(), "235 2.7.0 Authentication successful").await?;
                        }
                        _ => {
                            Self::reply(
                                r.get_mut(),
                                &format!(
                                    "535 5.7.8 Authentication failed: username is {}, password is an API key",
                                    super::SMTP_USERNAME
                                ),
                            )
                            .await?;
                        }
                    }
                }
                "MAIL" => {
                    let Some(k) = &key else {
                        Self::reply(r.get_mut(), "530 5.7.0 Authentication required").await?;
                        continue;
                    };
                    if !helo {
                        Self::reply(r.get_mut(), "503 5.5.1 Say EHLO first").await?;
                        continue;
                    }
                    let Some((addr, params)) = path_arg(rest, "FROM:") else {
                        Self::reply(r.get_mut(), "501 5.5.4 Syntax: MAIL FROM:<address>").await?;
                        continue;
                    };
                    if let Some(size) = params
                        .split_whitespace()
                        .find_map(|p| p.strip_prefix("SIZE=").or_else(|| p.strip_prefix("size=")))
                        .and_then(|s| s.parse::<usize>().ok())
                    {
                        if size > super::MAX_MESSAGE_BYTES {
                            Self::reply(r.get_mut(), "552 5.3.4 Message too large").await?;
                            continue;
                        }
                    }
                    let mailer = self.mailer.clone();
                    let (k2, a2) = (k.clone(), addr.clone());
                    let checked = tokio::task::spawn_blocking(move || mailer.check_sender(&k2, &a2))
                        .await
                        .unwrap_or_else(|e| Err(SendError::Internal(e.to_string())));
                    match checked {
                        Ok(_) => {
                            txn = Txn {
                                from: Some(addr),
                                rcpts: Vec::new(),
                            };
                            Self::reply(r.get_mut(), "250 2.1.0 OK").await?;
                        }
                        Err(e) => Self::reply(r.get_mut(), &send_error_reply(&e)).await?,
                    }
                }
                "RCPT" => {
                    if txn.from.is_none() {
                        Self::reply(r.get_mut(), "503 5.5.1 Need MAIL first").await?;
                        continue;
                    }
                    let Some((addr, _)) = path_arg(rest, "TO:") else {
                        Self::reply(r.get_mut(), "501 5.5.4 Syntax: RCPT TO:<address>").await?;
                        continue;
                    };
                    if super::domain_of(&addr).is_none() || addr.contains(char::is_whitespace) {
                        Self::reply(r.get_mut(), "501 5.1.3 Invalid recipient").await?;
                    } else if txn.rcpts.len() >= super::MAX_RECIPIENTS {
                        Self::reply(r.get_mut(), "452 4.5.3 Too many recipients").await?;
                    } else {
                        txn.rcpts.push(addr);
                        Self::reply(r.get_mut(), "250 2.1.5 OK").await?;
                    }
                }
                "DATA" => {
                    let (Some(from), false) = (txn.from.clone(), txn.rcpts.is_empty()) else {
                        Self::reply(r.get_mut(), "503 5.5.1 Need MAIL and RCPT first").await?;
                        continue;
                    };
                    Self::reply(r.get_mut(), "354 End data with <CR><LF>.<CR><LF>").await?;
                    let mut data = Vec::new();
                    let mut too_big = false;
                    loop {
                        let Some(l) = read_line(&mut r, MAX_LINE * 64).await? else {
                            return Ok((End::Closed, r.into_inner()));
                        };
                        if l == b".\r\n" || l == b".\n" {
                            break;
                        }
                        let l = if l.starts_with(b"..") { &l[1..] } else { &l[..] };
                        if data.len() + l.len() > super::MAX_MESSAGE_BYTES {
                            too_big = true;
                        } else if !too_big {
                            data.extend_from_slice(l);
                        }
                    }
                    let rcpts = std::mem::take(&mut txn.rcpts);
                    txn = Txn::default();
                    if too_big {
                        Self::reply(r.get_mut(), "552 5.3.4 Message too large").await?;
                        continue;
                    }
                    let k = key.clone().expect("MAIL needs a key");
                    let mailer = self.mailer.clone();
                    let res = tokio::task::spawn_blocking(move || mailer.send(&k, Source::Smtp, &from, &rcpts, data))
                        .await
                        .unwrap_or_else(|e| Err(SendError::Internal(e.to_string())));
                    match res {
                        Ok(id) => Self::reply(r.get_mut(), &format!("250 2.0.0 OK id={id}")).await?,
                        Err(e) => Self::reply(r.get_mut(), &send_error_reply(&e)).await?,
                    }
                }
                "RSET" => {
                    txn = Txn::default();
                    Self::reply(r.get_mut(), "250 2.0.0 OK").await?;
                }
                "NOOP" => Self::reply(r.get_mut(), "250 2.0.0 OK").await?,
                "VRFY" => Self::reply(r.get_mut(), "252 2.5.0 Cannot verify").await?,
                "QUIT" => {
                    Self::reply(r.get_mut(), "221 2.0.0 Bye").await?;
                    return Ok((End::Closed, r.into_inner()));
                }
                _ => {
                    errors += 1;
                    if errors > 10 {
                        Self::reply(r.get_mut(), "421 4.7.0 Too many errors").await?;
                        return Ok((End::Closed, r.into_inner()));
                    }
                    Self::reply(r.get_mut(), "502 5.5.2 Command not recognized").await?;
                }
            }
        }
        Ok((End::Closed, r.into_inner()))
    }

    async fn handle(self: Arc<Self>, stream: TcpStream, peer: SocketAddr, implicit_tls: bool) {
        let tls = self.tls.read().unwrap_or_else(|e| e.into_inner()).clone();
        let result = async {
            if implicit_tls {
                let Some(cfg) = tls else { return Ok(()) };
                let s = tokio_rustls::TlsAcceptor::from(cfg).accept(stream).await?;
                self.session(s, peer, true, true).await.map(|_| ())
            } else {
                let (end, plain) = self.session(stream, peer, false, true).await?;
                if let (End::StartTls, Some(cfg)) = (end, tls) {
                    let s = tokio_rustls::TlsAcceptor::from(cfg).accept(plain).await?;
                    self.session(s, peer, true, false).await?;
                }
                Ok(())
            }
        }
        .await;
        if let Err(e) = result {
            tracing::debug!("smtp session from {peer} ended: {e}");
        }
    }

    /// Accept connections on `addr` forever.
    pub async fn listen(self: Arc<Self>, addr: String, implicit_tls: bool) -> Result<(), String> {
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| format!("Cannot listen on {addr}: {e}"))?;
        tracing::info!("SMTP listening on {addr}{}", if implicit_tls { " (TLS)" } else { "" });
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                let mut s = stream;
                let _ = s.write_all(b"421 4.3.2 Too busy, try again later\r\n").await;
                continue;
            };
            let me = self.clone();
            tokio::spawn(async move {
                me.handle(stream, peer, implicit_tls).await;
                drop(permit);
            });
        }
    }
}

fn b64(s: &str) -> Option<String> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(s.trim()).ok()?;
    String::from_utf8(bytes).ok()
}

/// AUTH PLAIN: base64 of `authzid NUL authcid NUL password`.
fn decode_plain(s: &str) -> Option<(String, String)> {
    let decoded = b64(s)?;
    let mut parts = decoded.split('\0');
    let _authz = parts.next()?;
    let user = parts.next()?.to_string();
    let pass = parts.next()?.to_string();
    Some((user, pass))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mail::send::tests::fixture;
    use tokio::io::AsyncReadExt;

    fn server() -> (
        Arc<Server>,
        Arc<crate::mail::send::tests::Captured>,
        String,
        tempfile::TempDir,
    ) {
        let (m, cap, _key, full, dir) = fixture();
        let s = Arc::new(Server {
            mailer: Arc::new(m),
            tls: Arc::new(RwLock::new(None)),
            limiter: AuthLimiter::default(),
            hostname: "mail.example.com".into(),
        });
        (s, cap, full, dir)
    }

    /// Run a scripted conversation over an in-memory pipe as if TLS were on (`secure`).
    async fn talk(s: Arc<Server>, secure: bool, script: &str) -> String {
        let (client, srv) = tokio::io::duplex(1 << 20);
        let peer: SocketAddr = "203.0.113.5:40000".parse().unwrap();
        let task = tokio::spawn(async move { s.session(srv, peer, secure, true).await.map(|_| ()) });
        let (mut rd, mut wr) = tokio::io::split(client);
        wr.write_all(script.replace('\n', "\r\n").as_bytes()).await.unwrap();
        wr.shutdown().await.unwrap();
        let mut out = String::new();
        rd.read_to_string(&mut out).await.unwrap();
        let _ = task.await;
        out
    }

    fn plain(user: &str, pass: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0{pass}"))
    }

    #[tokio::test]
    async fn sends_after_auth() {
        let (s, cap, key, _d) = server();
        let script = format!(
            "EHLO client\nAUTH PLAIN {}\nMAIL FROM:<me@example.com> SIZE=100\nRCPT TO:<you@example.org>\nDATA\nFrom: Me <me@example.com>\nTo: you@example.org\nSubject: Hi\n\n..dot line\nbody\n.\nQUIT\n",
            plain("cloudpanel", &key)
        );
        let out = talk(s, true, &script).await;
        assert!(
            out.contains("250-AUTH PLAIN LOGIN") || out.contains("250 AUTH PLAIN LOGIN"),
            "{out}"
        );
        assert!(out.contains("235 2.7.0"), "{out}");
        assert!(out.contains("250 2.0.0 OK id="), "{out}");
        assert!(out.ends_with("221 2.0.0 Bye\r\n"));
        let sent = cap.0.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "me@example.com");
        assert!(String::from_utf8_lossy(&sent[0].2).contains("\r\n.dot line\r\n"));
    }

    #[tokio::test]
    async fn auth_login_works_too() {
        let (s, cap, key, _d) = server();
        let e = |v: &str| base64::engine::general_purpose::STANDARD.encode(v);
        let script = format!(
            "EHLO c\nAUTH LOGIN\n{}\n{}\nMAIL FROM:<me@example.com>\nRCPT TO:<a@b.org>\nDATA\nFrom: me@example.com\n\nx\n.\nQUIT\n",
            e("cloudpanel"),
            e(&key)
        );
        let out = talk(s, true, &script).await;
        assert!(out.contains("334 VXNlcm5hbWU6") && out.contains("235 "), "{out}");
        assert_eq!(cap.0.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn refuses_without_tls_auth_or_good_key() {
        let (s, cap, key, _d) = server();
        // Plain connection: no AUTH offered or allowed.
        let out = talk(
            s.clone(),
            false,
            &format!(
                "EHLO c\nAUTH PLAIN {}\nMAIL FROM:<me@example.com>\nQUIT\n",
                plain("cloudpanel", &key)
            ),
        )
        .await;
        assert!(!out.contains("AUTH PLAIN LOGIN"));
        assert!(out.contains("538 5.7.11"));
        assert!(out.contains("530 5.7.0"));
        // Wrong key, wrong username.
        let out = talk(
            s.clone(),
            true,
            &format!("EHLO c\nAUTH PLAIN {}\n", plain("cloudpanel", "cp_nope")),
        )
        .await;
        assert!(out.contains("535 5.7.8"));
        let out = talk(
            s.clone(),
            true,
            &format!("EHLO c\nAUTH PLAIN {}\n", plain("someone", &key)),
        )
        .await;
        assert!(out.contains("535 5.7.8"));
        // Authenticated, but not our domain: refused at MAIL FROM (no open relay).
        let out = talk(
            s.clone(),
            true,
            &format!(
                "EHLO c\nAUTH PLAIN {}\nMAIL FROM:<x@gmail.com>\nRCPT TO:<a@b.org>\nDATA\nQUIT\n",
                plain("cloudpanel", &key)
            ),
        )
        .await;
        assert!(out.contains("550 5.7.1"), "{out}");
        assert!(out.contains("503 5.5.1 Need MAIL first"), "{out}");
        // Envelope ours, header From someone else's.
        let out = talk(
            s,
            true,
            &format!("EHLO c\nAUTH PLAIN {}\nMAIL FROM:<me@example.com>\nRCPT TO:<a@b.org>\nDATA\nFrom: ceo@bank.com\n\nx\n.\nQUIT\n", plain("cloudpanel", &key)),
        )
        .await;
        assert!(out.contains("550 5.7.1"), "{out}");
        assert!(cap.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn locks_out_after_repeated_failures() {
        let (s, _cap, _key, _d) = server();
        for _ in 0..MAX_AUTH_FAILURES {
            talk(
                s.clone(),
                true,
                &format!("EHLO c\nAUTH PLAIN {}\n", plain("cloudpanel", "bad")),
            )
            .await;
        }
        let out = talk(s, true, "EHLO c\nAUTH PLAIN x\n").await;
        assert!(out.contains("421 4.7.0"), "{out}");
    }

    #[tokio::test]
    async fn rejects_oversized_and_overlong() {
        let (s, _cap, key, _d) = server();
        let out = talk(
            s.clone(),
            true,
            &format!(
                "EHLO c\nAUTH PLAIN {}\nMAIL FROM:<me@example.com> SIZE=999999999\n",
                plain("cloudpanel", &key)
            ),
        )
        .await;
        assert!(out.contains("552 5.3.4"), "{out}");
        let long = "X".repeat(MAX_LINE + 10);
        let out = talk(s, true, &format!("EHLO c\n{long}\n")).await;
        assert!(!out.contains("502"), "overlong lines end the session");
    }

    #[test]
    fn helpers() {
        assert_eq!(
            path_arg("FROM:<a@b.c> SIZE=10", "FROM:"),
            Some(("a@b.c".into(), "SIZE=10".into()))
        );
        assert_eq!(
            path_arg("from: <a@b.c>", "FROM:"),
            Some(("a@b.c".into(), String::new()))
        );
        assert_eq!(path_arg("TO:a@b.c", "TO:"), None);
        assert_eq!(decode_plain(&plain("u", "p")), Some(("u".into(), "p".into())));
        assert_eq!(decode_plain("!!"), None);
    }
}
