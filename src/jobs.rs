//! Background jobs for long-running work (apt upgrades, image pulls, backups). The
//! handler returns a job id immediately and the UI polls `GET /api/jobs/:id`.

use crate::db::{self, DbPool};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const OUTPUT_CAP: usize = 256 * 1024;

/// Handle passed to a job closure for streaming log lines.
#[derive(Clone)]
pub struct JobLog {
    pool: DbPool,
    id: i64,
    buf: Arc<Mutex<(String, Instant)>>,
}

impl JobLog {
    /// Append a line. Writes are batched to the database every ~500ms.
    pub fn line(&self, line: &str) {
        let mut guard = self.buf.lock().unwrap_or_else(|e| e.into_inner());
        guard.0.push_str(line);
        guard.0.push('\n');
        if guard.1.elapsed() > Duration::from_millis(500) || guard.0.len() > 16 * 1024 {
            let chunk = std::mem::take(&mut guard.0);
            guard.1 = Instant::now();
            drop(guard);
            self.write(&chunk);
        }
    }

    pub fn flush(&self) {
        let chunk = {
            let mut guard = self.buf.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut guard.0)
        };
        if !chunk.is_empty() {
            self.write(&chunk);
        }
    }

    fn write(&self, chunk: &str) {
        if let Ok(conn) = self.pool.get() {
            let _ = db::append_job_output(&conn, self.id, chunk, OUTPUT_CAP);
        }
    }
}

/// Start `work` on the blocking pool and return the job id. `work` returns Ok(()) on
/// success or Err(message), which is appended to the log.
pub fn spawn<F>(pool: &DbPool, kind: &str, target: Option<&str>, user_id: Option<i64>, work: F) -> Result<i64, String>
where
    F: FnOnce(&JobLog) -> Result<(), String> + Send + 'static,
{
    let conn = pool.get().map_err(|e| e.to_string())?;
    let id = db::create_job(&conn, kind, target, user_id).map_err(|e| e.to_string())?;
    drop(conn);
    let log = JobLog {
        pool: pool.clone(),
        id,
        buf: Arc::new(Mutex::new((String::new(), Instant::now()))),
    };
    let kind = kind.to_string();
    tokio::task::spawn_blocking(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(&log)))
            .unwrap_or_else(|_| Err("job panicked".into()));
        if let Err(e) = &result {
            log.line(&format!("ERROR: {e}"));
            tracing::warn!("job {id} ({kind}) failed: {e}");
        }
        log.flush();
        if let Ok(conn) = log.pool.get() {
            let _ = db::finish_job(&conn, id, result.is_ok());
        }
    });
    Ok(id)
}
