//! `cloudpanel mail-serve`: the long-running service behind `cloudpanel-mail.service`.

use super::send::{Mailer, Sendmail};
use super::smtp::{self, AuthLimiter, Server};
use super::{events, store, MailConfig};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

pub async fn run(config: MailConfig) -> Result<(), String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let conn =
        store::open(&config.db_path()).map_err(|e| format!("Could not open {}: {e}", config.db_path().display()))?;
    let db = Arc::new(Mutex::new(conn));

    let tls: smtp::TlsConfig = Arc::new(RwLock::new(None));
    match smtp::load_tls(&config.tls_cert, &config.tls_key) {
        Ok(c) => *tls.write().unwrap_or_else(|e| e.into_inner()) = Some(c),
        Err(e) => tracing::error!(
            "{e}. SMTP clients can't sign in until a certificate is installed (cloudpanel mail-install)."
        ),
    }

    let mailer = Arc::new(Mailer {
        config: config.clone(),
        db: db.clone(),
        handoff: Arc::new(Sendmail {
            path: config.sendmail.clone(),
        }),
    });
    let server = Arc::new(Server {
        mailer: mailer.clone(),
        tls: tls.clone(),
        limiter: AuthLimiter::default(),
        hostname: config.hostname.clone(),
    });

    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(server.clone().listen(config.smtp_addr.clone(), false));
    tasks.spawn(server.clone().listen(config.smtps_addr.clone(), true));

    let http_addr = config.http_addr.clone();
    let app = super::http::router(mailer.clone());
    tasks.spawn(async move {
        let listener = tokio::net::TcpListener::bind(&http_addr)
            .await
            .map_err(|e| format!("Cannot listen on {http_addr}: {e}"))?;
        tracing::info!("Email API listening on http://{http_addr}");
        axum::serve(listener, app).await.map_err(|e| e.to_string())
    });

    tokio::spawn(events::run_webhooks(db.clone()));
    if cfg!(target_os = "linux") {
        let (db2, cursor) = (db.clone(), config.cursor_path());
        std::thread::spawn(move || events::follow_journal(db2, cursor));
    }

    // Prune old logs every hour.
    let db3 = db.clone();
    tokio::spawn(async move {
        loop {
            {
                let c = db3.lock().unwrap_or_else(|e| e.into_inner());
                if let Ok(n) = store::prune(&c, super::LOG_RETENTION_DAYS) {
                    if n > 0 {
                        tracing::info!("pruned {n} message logs older than {} days", super::LOG_RETENTION_DAYS);
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });

    // certbot's deploy hook reloads the unit with SIGHUP after renewing the certificate.
    #[cfg(unix)]
    {
        let (tls2, cert, key) = (tls.clone(), config.tls_cert.clone(), config.tls_key.clone());
        tokio::spawn(async move {
            let Ok(mut hup) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) else {
                return;
            };
            while hup.recv().await.is_some() {
                match smtp::load_tls(&cert, &key) {
                    Ok(c) => {
                        *tls2.write().unwrap_or_else(|e| e.into_inner()) = Some(c);
                        tracing::info!("TLS certificate reloaded");
                    }
                    Err(e) => tracing::error!("TLS reload failed, keeping the old certificate: {e}"),
                }
            }
        });
    }

    // Any listener failing (port taken) stops the service, so systemd shows and retries it.
    match tasks.join_next().await {
        Some(Ok(Err(e))) => Err(e),
        Some(Err(e)) => Err(e.to_string()),
        _ => Ok(()),
    }
}
