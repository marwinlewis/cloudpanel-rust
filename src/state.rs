use crate::api::error::{ApiError, ApiResult};
use crate::auth::LoginLimiter;
use crate::config::Config;
use crate::db::DbPool;
use crate::services::MetricsCollector;
use rusqlite::Connection;
use std::sync::{Arc, Mutex};

pub struct AppState {
    pub pool: DbPool,
    pub config: Config,
    pub jwt_secret: Vec<u8>,
    /// Sent by the panel's nginx site, to vouch for the client address it forwards.
    pub proxy_secret: String,
    pub limiter: LoginLimiter,
    pub metrics: Arc<Mutex<MetricsCollector>>,
    /// Live TLS config of the panel listener, for hot-reloading its certificate.
    pub tls: Mutex<Option<axum_server::tls_rustls::RustlsConfig>>,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    /// Run a database closure on the blocking thread pool.
    pub async fn db<T, F>(&self, f: F) -> ApiResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> ApiResult<T> + Send + 'static,
    {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool.get()?;
            f(&conn)
        })
        .await?
    }
}

/// Run blocking work (process spawning, hashing, file IO) off the async runtime.
pub async fn blocking<T, F>(f: F) -> ApiResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> ApiResult<T> + Send + 'static,
{
    tokio::task::spawn_blocking(f).await.map_err(ApiError::from)?
}
