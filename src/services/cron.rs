use crate::db::models::CronJob;
use crate::fsutil::write_atomic;
use std::path::Path;
use tracing::info;

pub struct CronService;

impl CronService {
    /// Render `/etc/cron.d/cloudpanel`. Fields are validated on input; `%` is escaped
    /// because cron turns unescaped `%` into newlines.
    pub fn render(jobs: &[CronJob]) -> String {
        let mut out = String::from(
            "# Managed by CloudPanel - do not edit, changes will be overwritten\n\
             SHELL=/bin/sh\n\
             PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n\n",
        );
        for job in jobs.iter().filter(|j| j.is_active) {
            out.push_str(&format!("# job {}\n", job.id));
            out.push_str(&format!(
                "{} {} {}\n",
                job.schedule,
                job.user,
                job.command.replace('%', "\\%")
            ));
        }
        out
    }

    pub fn apply(cron_file: &Path, jobs: &[CronJob]) -> Result<(), String> {
        write_atomic(cron_file, Self::render(jobs).as_bytes(), 0o644)
            .map_err(|e| format!("Failed to write {}: {e}", cron_file.display()))?;
        info!("Wrote {} cron job(s) to {}", jobs.len(), cron_file.display());
        Ok(())
    }

    /// Check that a local account exists (so cron doesn't silently ignore the line).
    pub fn user_exists(user: &str) -> bool {
        if cfg!(windows) {
            return true;
        }
        std::fs::read_to_string("/etc/passwd")
            .map(|p| p.lines().any(|l| l.split(':').next() == Some(user)))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn renders_and_escapes() {
        let jobs = vec![
            CronJob {
                id: 1,
                site_id: None,
                name: None,
                schedule: "0 3 * * *".into(),
                command: "date +%F >> /tmp/x".into(),
                user: "root".into(),
                is_active: true,
                created_at: Utc::now(),
            },
            CronJob {
                id: 2,
                site_id: None,
                name: None,
                schedule: "@hourly".into(),
                command: "true".into(),
                user: "www-data".into(),
                is_active: false,
                created_at: Utc::now(),
            },
        ];
        let out = CronService::render(&jobs);
        assert!(out.contains("0 3 * * * root date +\\%F >> /tmp/x\n"));
        assert!(!out.contains("www-data"));
    }
}
