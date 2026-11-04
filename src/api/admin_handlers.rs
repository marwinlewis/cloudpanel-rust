use crate::api::error::{ApiError, ApiResult};
use crate::auth::{AdminUser, AuthUser};
use crate::db::{self, EventFilter};
use crate::state::SharedState;
use axum::{
    extract::{Path, Query, State},
    http::header,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;

pub async fn get_job(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let job = state
        .db(move |conn| Ok(db::find_job(conn, id)?))
        .await?
        .ok_or(ApiError::NotFound("Job"))?;
    if !user.is_admin() && job.user_id != Some(user.id) {
        return Err(ApiError::NotFound("Job"));
    }
    Ok(Json(job))
}

pub async fn list_jobs(_admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let mut jobs = state.db(|conn| Ok(db::list_jobs(conn, 50)?)).await?;
    for j in &mut jobs {
        // The list only needs a preview; the detail endpoint returns full output.
        j.output = crate::services::cmd::tail(&j.output, 400).to_string();
    }
    Ok(Json(jobs))
}

#[derive(Deserialize)]
pub struct EventQuery {
    pub username: Option<String>,
    pub action: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub before: Option<i64>,
    pub limit: Option<i64>,
    pub format: Option<String>,
}

pub async fn list_events(
    _admin: AdminUser,
    Query(q): Query<EventQuery>,
    State(state): State<SharedState>,
) -> ApiResult<axum::response::Response> {
    let csv = q.format.as_deref() == Some("csv");
    let filter = EventFilter {
        username: q.username.filter(|s| !s.trim().is_empty()),
        action: q.action.filter(|s| !s.trim().is_empty()),
        since: q.since,
        until: q.until,
        before_id: q.before,
        limit: if csv {
            100_000
        } else {
            q.limit.unwrap_or(50).clamp(1, 500)
        },
    };
    let events = state.db(move |conn| Ok(db::list_events(conn, &filter)?)).await?;
    if !csv {
        return Ok(Json(events).into_response());
    }
    let mut out = String::from("id,time,user,ip,action,target,detail\n");
    for e in events {
        let row = [
            e.id.to_string(),
            e.created_at.to_rfc3339(),
            e.username.unwrap_or_default(),
            e.ip.unwrap_or_default(),
            e.action,
            e.target.unwrap_or_default(),
            e.detail.unwrap_or_default(),
        ];
        out.push_str(&row.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"cloudpanel-events.csv\"",
            ),
        ],
        out,
    )
        .into_response())
}

/// Quote a CSV field and neutralize spreadsheet formula injection.
fn csv_field(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    format!("\"{}\"", s.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    #[test]
    fn csv_escaping() {
        assert_eq!(super::csv_field("a\"b"), "\"a\"\"b\"");
        assert_eq!(super::csv_field("=cmd()"), "\"'=cmd()\"");
    }
}
