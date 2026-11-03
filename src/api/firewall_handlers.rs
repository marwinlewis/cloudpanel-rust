use crate::api::error::{ApiError, ApiResult};
use crate::auth::AdminUser;
use crate::db::{
    create_firewall_rule, delete_firewall_rule, find_firewall_rule, firewall_rule_exists, list_firewall_rules,
};
use crate::services::firewall::{Action, Protocol};
use crate::services::FirewallService;
use crate::state::SharedState;
use crate::validate;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct CreateRuleRequest {
    pub port: u16,
    pub protocol: Option<String>,
    pub action: Option<String>,
    pub comment: Option<String>,
}

pub async fn get_rules(_admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    Ok(Json(state.db(|conn| Ok(list_firewall_rules(conn)?)).await?))
}

pub async fn add_rule(
    _admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<CreateRuleRequest>,
) -> ApiResult<impl IntoResponse> {
    let port = validate::port(Some(p.port)).map_err(ApiError::BadRequest)?;
    let protocol = Protocol::parse(p.protocol.as_deref().unwrap_or("tcp"))
        .ok_or_else(|| ApiError::BadRequest("Protocol must be tcp, udp or any".into()))?;
    let action = Action::parse(p.action.as_deref().unwrap_or("allow"))
        .ok_or_else(|| ApiError::BadRequest("Action must be allow or deny".into()))?;
    let comment = validate::short_text(p.comment.as_deref(), 120).map_err(ApiError::BadRequest)?;

    if action == Action::Deny && (Some(port) == state.config.panel_port() || port == 22) {
        return Err(ApiError::BadRequest(
            "Refusing to block the SSH or control panel port; you would lock yourself out".into(),
        ));
    }

    let rule = state
        .db(move |conn| {
            if firewall_rule_exists(conn, port, protocol.as_str(), action.as_str())? {
                return Err(ApiError::Conflict("That rule already exists".into()));
            }
            FirewallService::add(port, protocol, action).map_err(ApiError::Unprocessable)?;
            let id = create_firewall_rule(conn, port, protocol.as_str(), action.as_str(), comment.as_deref())?;
            Ok(find_firewall_rule(conn, id)?)
        })
        .await?;
    Ok((StatusCode::CREATED, Json(rule)))
}

pub async fn delete_rule(
    Path(id): Path<i64>,
    _admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    state
        .db(move |conn| {
            let rule = find_firewall_rule(conn, id)?.ok_or(ApiError::NotFound("Rule"))?;
            let protocol = Protocol::parse(&rule.protocol).unwrap_or(Protocol::Tcp);
            let action = Action::parse(&rule.action).unwrap_or(Action::Allow);
            FirewallService::delete(rule.port, protocol, action).map_err(ApiError::Unprocessable)?;
            delete_firewall_rule(conn, id)?;
            Ok(())
        })
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
