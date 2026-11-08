mod api;
mod audit;
mod auth;
mod authz;
mod config;
mod db;
mod fsutil;
mod jobs;
mod scheduler;
mod secrets;
mod services;
mod state;
mod validate;
mod web;

use auth::{hash_password, random_password, LoginLimiter};
use clap::{Parser, Subcommand};
use config::Config;
use db::{count_users, create_user, init_db, list_sites, set_user_password};
use services::sites::{provision, SiteInput};
use services::MetricsCollector;
use state::AppState;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tower_http::compression::CompressionLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Parser, Debug)]
#[command(
    name = "cloudpanel",
    version,
    about = "Ultra-lightweight, secure server control panel"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Listen address, e.g. 0.0.0.0:8443
    #[arg(short, long, env = "CLOUDPANEL_BIND", global = true)]
    bind: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the CloudPanel server (default)
    Server,
    /// Create a new control panel user (prompts for the password if omitted)
    #[command(alias = "user:add")]
    UserAdd {
        #[arg(short, long)]
        username: String,
        #[arg(short, long)]
        email: String,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(short, long, default_value = "admin", value_parser = ["admin", "site_manager"])]
        role: String,
    },
    /// Reset a user's password and sign out all their sessions
    #[command(alias = "user:reset-password")]
    UserResetPassword {
        #[arg(short, long)]
        username: String,
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Add a new site and apply its nginx configuration
    #[command(alias = "site:add")]
    SiteAdd {
        #[arg(short, long)]
        domain: String,
        #[arg(short, long, default_value = "nodejs")]
        site_type: String,
        #[arg(short, long)]
        port: Option<u16>,
        /// Don't handle www.<domain> at all (by default it redirects to the naked domain)
        #[arg(long, conflicts_with = "www_alias")]
        no_www: bool,
        /// Serve the site on www.<domain> as well, instead of redirecting it
        #[arg(long)]
        www_alias: bool,
    },
    /// List all managed sites
    #[command(alias = "site:list")]
    SiteList,
    /// Turn off two-factor authentication for a user (e.g. lost phone and recovery codes)
    #[command(name = "user-disable-2fa", alias = "user:disable-2fa")]
    UserDisable2fa {
        #[arg(short, long)]
        username: String,
    },
    /// Reopen the panel's own port after it was closed in Settings (e.g. its hostname broke)
    PanelAccessOpen,
    /// Run a cron job by id and record its output (used by /etc/cron.d/cloudpanel)
    CronRun { id: i64 },
    /// Import sites, databases and users from a CloudPanel CE database (used by migrate-from-ce.sh)
    ImportCe {
        /// A copy of CE's panel database (/home/clp/htdocs/app/data/db.sq3)
        #[arg(long)]
        source: std::path::PathBuf,
        /// Check and report without saving anything
        #[arg(long)]
        dry_run: bool,
        /// Where to write the passwords of panel accounts created by the import (mode 600)
        #[arg(long)]
        credentials_file: Option<std::path::PathBuf>,
    },
}

fn read_password(given: Option<String>) -> AnyResult<String> {
    let pw = match given {
        Some(p) => p,
        None => {
            let p = rpassword::prompt_password("New password: ")?;
            if p != rpassword::prompt_password("Repeat password: ")? {
                return Err("Passwords do not match".into());
            }
            p
        }
    };
    validate::password(&pw)?;
    Ok(pw)
}

/// JWT signing key: `CLOUDPANEL_JWT_SECRET` or a random key persisted in the data dir.
/// The secret nginx sends to vouch for a client address. Letters and digits only, because it
/// is written into an nginx config.
fn load_proxy_secret(config: &Config) -> AnyResult<String> {
    let path = config.data_dir.join("proxy.secret");
    if let Ok(s) = std::fs::read_to_string(&path) {
        let s = s.trim();
        if s.len() >= 32 && s.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Ok(s.to_string());
        }
    }
    let secret = random_password(48);
    fsutil::write_atomic(&path, secret.as_bytes(), 0o600)?;
    Ok(secret)
}

fn load_jwt_secret(config: &Config) -> AnyResult<Vec<u8>> {
    if let Ok(s) = std::env::var("CLOUDPANEL_JWT_SECRET") {
        if s.len() < 32 {
            return Err("CLOUDPANEL_JWT_SECRET must be at least 32 characters".into());
        }
        return Ok(s.into_bytes());
    }
    let path = config.data_dir.join("jwt.secret");
    if let Ok(s) = std::fs::read_to_string(&path) {
        let s = s.trim();
        if s.len() >= 32 {
            return Ok(s.as_bytes().to_vec());
        }
    }
    let secret = random_password(64);
    fsutil::write_atomic(&path, secret.as_bytes(), 0o600)?;
    info!("Generated new JWT signing key at {}", path.display());
    Ok(secret.into_bytes())
}

fn seed_admin(config: &Config, pool: &db::DbPool) -> AnyResult<()> {
    let conn = pool.get()?;
    if count_users(&conn)? > 0 {
        return Ok(());
    }
    let password = random_password(20);
    create_user(&conn, "admin", &hash_password(&password)?, "admin@localhost", "admin")?;
    let file = config.data_dir.join("initial_admin_password");
    fsutil::write_atomic(&file, format!("{password}\n").as_bytes(), 0o600)?;
    println!("\n  Created administrator account");
    println!("  Username : admin");
    println!("  Password : {password}");
    println!(
        "  (also saved to {}; it is removed when you change the password)\n",
        file.display()
    );
    Ok(())
}

/// One `kind: value` line per finding, which migrate-from-ce.sh shows and keeps in its report.
fn print_import_report(r: &services::ce_import::Report, dry_run: bool) {
    let verb = if dry_run { "would import" } else { "imported" };
    for s in &r.sites_imported {
        println!("{verb} site: {s}");
    }
    for s in &r.sites_existing {
        println!("already imported: {s}");
    }
    for s in &r.php_skipped {
        println!("php site left unmanaged: {s} (it keeps running; add --with-php to manage it)");
    }
    for (u, _) in &r.users_created {
        println!("{verb} panel user: {u} (new password, CE's can't be reused; 2FA must be set up again)");
    }
    for u in &r.users_existing {
        println!("panel user already exists: {u}");
    }
    println!(
        "{verb}: {} database(s), {} database user(s), {} extra SSH user(s)",
        r.databases, r.database_users, r.ssh_users
    );
    for n in &r.notes {
        println!("note: {n}");
    }
    for p in &r.problems {
        println!("problem: {p}");
    }
}

async fn shutdown_signal(handle: axum_server::Handle) {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();

    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
    info!("Shutting down");
    handle.graceful_shutdown(Some(Duration::from_secs(10)));
}

#[tokio::main]
async fn main() -> AnyResult<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cloudpanel=info,tower_http=warn".into()),
        )
        .with(tracing_subscriber::fmt::layer().with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout())))
        .init();

    let cli = Cli::parse();
    let mut config = Config::from_env();
    if let Some(bind) = cli.bind {
        config.bind_addr = bind;
    }

    fsutil::create_private_dir(&config.data_dir, 0o700)?;
    let pool = init_db(&config.db_path)?;

    let conn = pool.get()?;
    match cli.command {
        Some(Commands::UserAdd {
            username,
            email,
            password,
            role,
        }) => {
            let username = validate::username(&username)?;
            let email = validate::email(&email)?;
            let hash = hash_password(&read_password(password)?)?;
            let id = create_user(&conn, &username, &hash, &email, &role)?;
            println!("User '{username}' created (id {id})");
            return Ok(());
        }
        Some(Commands::UserResetPassword { username, password }) => {
            let hash = hash_password(&read_password(password)?)?;
            match set_user_password(&conn, &username, &hash)? {
                Some(_) => {
                    let _ = std::fs::remove_file(config.data_dir.join("initial_admin_password"));
                    println!("Password for '{username}' updated; existing sessions were signed out.");
                }
                None => return Err(format!("User '{username}' not found").into()),
            }
            return Ok(());
        }
        Some(Commands::SiteAdd {
            domain,
            site_type,
            port,
            no_www,
            www_alias,
        }) => {
            let site = provision(
                &config,
                &conn,
                SiteInput {
                    domain,
                    site_type,
                    target_port: port,
                    document_root: None,
                    system_user: None,
                    include_www: !no_www,
                    www_redirect: !no_www && !www_alias,
                    app_command: None,
                    app_manager: None,
                    create_user: true,
                },
            )
            .map_err(|e| format!("{e:?}"))?;
            println!(
                "Site '{}' ({}) created with id {}",
                site.domain, site.site_type, site.id
            );
            if site.site_type == "nodejs" && services::runtimes::node_needed(&config) {
                println!("Node.js is not installed; installing it now...");
                services::runtimes::ensure_nodejs(&config, &|l| println!("{l}"))?;
            }
            if site.uses_pm2() && !services::pm2::installed() && services::runtimes::can_install(&config) {
                services::pm2::ensure(&config, &|l| println!("{l}"))?;
            }
            return Ok(());
        }
        Some(Commands::SiteList) => {
            println!("{:<6} {:<32} {:<14} {:<7} SSL", "ID", "DOMAIN", "TYPE", "PORT");
            for s in list_sites(&conn)? {
                let port = s.target_port.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
                println!(
                    "{:<6} {:<32} {:<14} {:<7} {}",
                    s.id,
                    s.domain,
                    s.site_type,
                    port,
                    if s.ssl_enabled { "yes" } else { "no" }
                );
            }
            return Ok(());
        }
        Some(Commands::UserDisable2fa { username }) => {
            let user =
                db::find_user_by_username(&conn, &username)?.ok_or_else(|| format!("User '{username}' not found"))?;
            db::disable_totp(&conn, user.id)?;
            db::bump_token_version(&conn, user.id)?;
            audit::record_system(&conn, Some(&username), None, "user.2fa_reset", None, Some("cli"));
            println!("Two-factor authentication disabled for '{username}'; their sessions were signed out.");
            return Ok(());
        }
        Some(Commands::PanelAccessOpen) => {
            services::panel_cert::set_direct_closed(&conn, false)?;
            audit::record_system(&conn, None, None, "panel.direct_open", None, Some("cli"));
            services::panel_cert::allow_in_firewall(&config, &conn);
            if services::panel_cert::restart_panel() {
                println!("The panel's port is opening again.");
            } else {
                println!("Saved. Restart CloudPanel to open the panel's port again: systemctl restart cloudpanel");
            }
            return Ok(());
        }
        Some(Commands::CronRun { id }) => {
            let code = services::cron::run_job(&config, &conn, id)?;
            std::process::exit(code);
        }
        Some(Commands::ImportCe {
            source,
            dry_run,
            credentials_file,
        }) => {
            // Exit codes for migrate-from-ce.sh: 0 is clean, 1 is imported but with problems to look
            // at, and 2 is failed with nothing saved. Returning an error from `main` would exit 1.
            let mut conn = conn;
            // Checked first: new accounts' passwords exist only in this run, so they can't be lost.
            if !dry_run && credentials_file.is_none() {
                eprintln!("--credentials-file is needed to save the passwords of imported users");
                std::process::exit(2);
            }
            let report = match services::ce_import::run(&config, &mut conn, &source, dry_run) {
                Ok(report) => report,
                Err(e) => {
                    eprintln!("Import failed, nothing was saved: {e}");
                    std::process::exit(2);
                }
            };
            print_import_report(&report, dry_run);
            if let (false, false, Some(file)) = (dry_run, report.users_created.is_empty(), &credentials_file) {
                let previous = std::fs::read_to_string(file).unwrap_or_default();
                let added: String = report
                    .users_created
                    .iter()
                    .map(|(user, password)| format!("{user}\t{password}\n"))
                    .collect();
                if let Err(e) = fsutil::write_atomic(file, format!("{previous}{added}").as_bytes(), 0o600) {
                    // The accounts exist, so reset their passwords with `user-reset-password`.
                    eprintln!("Could not save the new passwords to {}: {e}", file.display());
                    std::process::exit(1);
                }
            }
            std::process::exit(i32::from(!report.problems.is_empty()));
        }
        Some(Commands::Server) | None => {}
    }
    drop(conn);

    seed_admin(&config, &pool)?;
    db::fail_stale_jobs(&*pool.get()?)?;
    {
        let conn = pool.get()?;
        let f2b: services::fail2ban::Fail2banSettings = db::get_setting(&conn, services::fail2ban::SETTING)?
            .and_then(|v| serde_json::from_str(&v).ok())
            .unwrap_or_default();
        services::fail2ban::ensure(&config, &f2b);
    }
    let jwt_secret = load_jwt_secret(&config)?;
    let stored_tls = services::panel_cert::load(&*pool.get()?);
    let tls_paths = services::panel_cert::effective_paths(&config, stored_tls.as_ref());
    let tls = tls_paths.is_some();
    let proxy_secret = load_proxy_secret(&config)?;
    let cloudflare = services::cloudflare::Ranges::load(&*pool.get()?);
    let vhost_ready = services::panel_cert::sync_vhost(&config, &*pool.get()?, tls, &proxy_secret, &cloudflare);
    // A closed port needs the hostname to work, or nobody could get in. Otherwise open it.
    let mut direct_closed = false;
    if services::panel_cert::direct_closed(&*pool.get()?) {
        match services::panel_cert::loopback_bind(&config.bind_addr) {
            Some(local) if vhost_ready && services::panel_cert::wait_for_nginx(30) => {
                config.bind_addr = local;
                direct_closed = true;
                // A panel bound to one address reaches it through a different upstream now.
                services::panel_cert::sync_vhost(&config, &*pool.get()?, tls, &proxy_secret, &cloudflare);
            }
            _ => tracing::warn!(
                "the panel's port stays open for now, although it is set to closed: its hostname is not being served"
            ),
        }
    }
    let addr: SocketAddr = config
        .bind_addr
        .parse()
        .map_err(|_| format!("Invalid bind address '{}'", config.bind_addr))?;

    let state = Arc::new(AppState {
        pool,
        config: config.clone(),
        jwt_secret,
        proxy_secret,
        cloudflare: RwLock::new(cloudflare),
        direct_closed,
        limiter: LoginLimiter::default(),
        metrics: Arc::new(Mutex::new(MetricsCollector::default())),
        tls: Mutex::new(None),
    });
    scheduler::start(state.clone());
    services::cloudflare::start(state.clone());
    services::panel_update::start(state.clone());

    let app = web::with_security_headers(api::create_app(state.clone()), tls).layer(CompressionLayer::new());
    let service = app.into_make_service_with_connect_info::<SocketAddr>();

    let handle = axum_server::Handle::new();
    tokio::spawn(shutdown_signal(handle.clone()));

    // Bind up front so a busy port fails with a clear error before we claim to be listening.
    let listener = std::net::TcpListener::bind(addr).map_err(|e| format!("Cannot listen on {addr}: {e}"))?;
    listener.set_nonblocking(true)?;

    if let Some((cert, key)) = &tls_paths {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
            .await
            .map_err(|e| format!("Failed to load TLS certificate {}: {e}", cert.display()))?;
        *state.tls.lock().unwrap_or_else(|e| e.into_inner()) = Some(tls_config.clone());
        info!("CloudPanel listening on https://{addr}");
        axum_server::from_tcp_rustls(listener, tls_config)
            .handle(handle)
            .serve(service)
            .await?;
    } else {
        tracing::warn!("TLS is not configured; serving plain HTTP. Set CLOUDPANEL_TLS_CERT and CLOUDPANEL_TLS_KEY.");
        info!("CloudPanel listening on http://{addr}");
        axum_server::from_tcp(listener).handle(handle).serve(service).await?;
    }
    Ok(())
}
