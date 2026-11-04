// Temporary while features land phase by phase; removed once every helper is wired up.
#![allow(dead_code)]
mod api;
mod audit;
mod auth;
mod authz;
mod config;
mod db;
mod fsutil;
mod jobs;
mod scheduler;
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
use std::sync::{Arc, Mutex};
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
        /// Also serve www.<domain>
        #[arg(long)]
        www: bool,
    },
    /// List all managed sites
    #[command(alias = "site:list")]
    SiteList,
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
            www,
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
                    include_www: www,
                },
            )
            .map_err(|e| format!("{e:?}"))?;
            println!(
                "Site '{}' ({}) created with id {}",
                site.domain, site.site_type, site.id
            );
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
        Some(Commands::Server) | None => {}
    }
    drop(conn);

    seed_admin(&config, &pool)?;
    db::fail_stale_jobs(&*pool.get()?)?;
    let jwt_secret = load_jwt_secret(&config)?;
    let tls = config.tls_enabled();
    let addr: SocketAddr = config
        .bind_addr
        .parse()
        .map_err(|_| format!("Invalid bind address '{}'", config.bind_addr))?;

    let state = Arc::new(AppState {
        pool,
        config: config.clone(),
        jwt_secret,
        limiter: LoginLimiter::default(),
        metrics: Arc::new(Mutex::new(MetricsCollector::default())),
        tls: Mutex::new(None),
    });
    scheduler::start(state.clone());

    let app = api::create_api_router(state.clone()).fallback(web::static_handler);
    let app = web::with_security_headers(app, tls).layer(CompressionLayer::new());
    let service = app.into_make_service_with_connect_info::<SocketAddr>();

    let handle = axum_server::Handle::new();
    tokio::spawn(shutdown_signal(handle.clone()));

    // Bind up front so a busy port fails with a clear error before we claim to be listening.
    let listener = std::net::TcpListener::bind(addr).map_err(|e| format!("Cannot listen on {addr}: {e}"))?;
    listener.set_nonblocking(true)?;

    if let (Some(cert), Some(key)) = (&config.tls_cert, &config.tls_key) {
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
