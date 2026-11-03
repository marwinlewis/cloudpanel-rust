use crate::api::error::ApiResult;
use crate::auth::AdminUser;
use crate::state::{blocking, SharedState};
use axum::{extract::State, response::IntoResponse, Json};

pub async fn get_system_metrics(_admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let metrics = state.metrics.clone();
    let data = blocking(move || {
        let mut collector = metrics.lock().unwrap_or_else(|e| e.into_inner());
        Ok(collector.collect())
    })
    .await?;
    Ok(Json(data))
}
