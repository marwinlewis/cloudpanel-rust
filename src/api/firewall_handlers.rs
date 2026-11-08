use crate::api::error::{ApiError, ApiResult};
use crate::audit;
use crate::auth::AdminUser;
use crate::db::{self, models::FirewallRule, NewRule};
use crate::services::fail2ban::{self, Fail2banSettings};
use crate::services::firewall::{cidr_contains, Action, FirewallService, Protocol, Rule};
use crate::state::{blocking, SharedState};
use crate::validate;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct CreateRuleRequest {
    /// "port" (default) or "block".
    #[serde(default)]
    pub kind: Option<String>,
    /// Port or range "6000:6010" (as a string) for port rules.
    pub port: Option<serde_json::Value>,
    pub protocol: Option<String>,
    pub action: Option<String>,
    pub source: Option<String>,
    pub comment: Option<String>,
}

fn to_rule(r: &FirewallRule) -> Rule {
    Rule {
        action: Action::parse(&r.action).unwrap_or(Action::Allow),
        port: r.port,
        port_end: r.port_end,
        protocol: Protocol::parse(&r.protocol).unwrap_or(Protocol::Tcp),
        source: r.source.clone(),
    }
}

pub async fn get_rules(_admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    Ok(Json(state.db(|conn| Ok(db::list_firewall_rules(conn)?)).await?))
}

pub async fn firewall_status(_admin: AdminUser) -> ApiResult<impl IntoResponse> {
    let (status, ssh) = blocking(|| Ok((FirewallService::status(), FirewallService::ssh_ports()))).await?;
    let active = status.as_deref().map(|s| s.contains("Status: active"));
    Ok(Json(
        json!({ "installed": status.is_some(), "active": active, "raw": status, "ssh_ports": ssh }),
    ))
}

pub async fn add_rule(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<CreateRuleRequest>,
) -> ApiResult<impl IntoResponse> {
    let block = p.kind.as_deref() == Some("block");
    let source = match p
        .source
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "any")
    {
        Some(s) => Some(validate::cidr(s).map_err(ApiError::BadRequest)?),
        None => None,
    };
    let comment = validate::short_text(p.comment.as_deref(), 120).map_err(ApiError::BadRequest)?;
    let rule = if block {
        Rule {
            action: Action::Deny,
            port: None,
            port_end: None,
            protocol: Protocol::Any,
            source: Some(
                source
                    .clone()
                    .ok_or_else(|| ApiError::BadRequest("Enter the IP or network to block".into()))?,
            ),
        }
    } else {
        let port_s = match &p.port {
            Some(serde_json::Value::Number(n)) => n.to_string(),
            Some(serde_json::Value::String(s)) => s.clone(),
            _ => return Err(ApiError::BadRequest("A port or port range is required".into())),
        };
        let (port, port_end) = validate::port_range(&port_s).map_err(ApiError::BadRequest)?;
        let protocol = Protocol::parse(p.protocol.as_deref().unwrap_or("tcp"))
            .ok_or_else(|| ApiError::BadRequest("Protocol must be tcp, udp or any".into()))?;
        if port_end.is_some() && protocol == Protocol::Any {
            return Err(ApiError::BadRequest("Port ranges need a protocol (TCP or UDP)".into()));
        }
        Rule {
            action: Action::parse(p.action.as_deref().unwrap_or("allow"))
                .ok_or_else(|| ApiError::BadRequest("Action must be allow or deny".into()))?,
            port: Some(port),
            port_end,
            protocol,
            source: source.clone(),
        }
    };

    // Lockout protection.
    if rule.action == Action::Deny {
        let ssh = blocking(|| Ok(FirewallService::ssh_ports())).await?;
        let my_ip = admin.0.ip.as_deref().and_then(|i| i.parse().ok());
        let hits_me = match (&rule.source, my_ip) {
            (None, _) => true,
            (Some(src), Some(ip)) => cidr_contains(src, ip),
            (Some(_), None) => false,
        };
        if hits_me && ssh.iter().any(|p| rule.covers_port(*p)) {
            return Err(ApiError::BadRequest(
                "Refusing a rule that would block SSH for your own connection".into(),
            ));
        }
        // Nothing outside can reach a closed panel port, so a rule there can't lock anyone out.
        let panel = state.config.panel_port().filter(|_| !state.direct_closed);
        if hits_me && panel.is_some_and(|p| rule.covers_port(p)) {
            return Err(ApiError::BadRequest(
                "Refusing a rule that would block the control panel for your own connection. To stop direct access \
                 to the panel's port, set up a panel hostname and close the port in Settings → Panel certificate."
                    .into(),
            ));
        }
    }

    let created = state
        .db(move |conn| {
            let new = NewRule {
                port: rule.port,
                port_end: rule.port_end,
                protocol: rule.protocol.as_str(),
                action: rule.action.as_str(),
                source: rule.source.as_deref(),
                comment: comment.as_deref(),
            };
            if db::firewall_rule_exists(conn, &new)? {
                return Err(ApiError::Conflict("That rule already exists".into()));
            }
            FirewallService::add(&rule, comment.as_deref()).map_err(ApiError::Unprocessable)?;
            // Adding it removed a rule with the same match and the other action from ufw.
            db::delete_firewall_rule_with_action(conn, &new, rule.action.opposite().as_str())?;
            let id = db::create_firewall_rule(conn, &new)?;
            let desc = format!("{} {}", rule.action.as_str(), rule.spec().join(" "));
            audit::record(conn, &admin.0, "firewall.add", None, Some(&desc));
            Ok(db::find_firewall_rule(conn, id)?)
        })
        .await?;
    Ok((StatusCode::CREATED, Json(created)))
}

pub async fn delete_rule(
    Path(id): Path<i64>,
    admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    state
        .db(move |conn| {
            let r = db::find_firewall_rule(conn, id)?.ok_or(ApiError::NotFound("Rule"))?;
            let rule = to_rule(&r);
            FirewallService::delete(&rule).map_err(ApiError::Unprocessable)?;
            db::delete_firewall_rule(conn, id)?;
            let desc = format!("{} {}", rule.action.as_str(), rule.spec().join(" "));
            audit::record(conn, &admin.0, "firewall.delete", None, Some(&desc));
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "ok": true })))
}

// ---------- fail2ban ----------

pub async fn get_fail2ban(_admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let settings: Fail2banSettings = state
        .db(|conn| {
            Ok(db::get_setting(conn, fail2ban::SETTING)?
                .and_then(|v| serde_json::from_str(&v).ok())
                .unwrap_or_default())
        })
        .await?;
    let (installed, jails) = blocking(|| Ok((fail2ban::installed(), fail2ban::status()))).await?;
    Ok(Json(
        json!({ "installed": installed, "settings": settings, "jails": jails }),
    ))
}

pub async fn set_fail2ban(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(mut s): Json<Fail2banSettings>,
) -> ApiResult<impl IntoResponse> {
    s.ignoreip = s
        .ignoreip
        .iter()
        .map(|i| i.trim().to_string())
        .filter(|i| !i.is_empty())
        .collect();
    s.validate().map_err(ApiError::BadRequest)?;
    for i in s.ignoreip.iter_mut() {
        *i = validate::cidr(i).map_err(ApiError::BadRequest)?;
    }
    let config = state.config.clone();
    let applied = s.clone();
    blocking(move || fail2ban::apply(&config, &applied).map_err(ApiError::Unprocessable)).await?;
    state
        .db(move |conn| {
            db::set_json(conn, fail2ban::SETTING, &s)?;
            audit::record(conn, &admin.0, "fail2ban.configure", None, None);
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "message": "fail2ban settings applied" })))
}

#[derive(Deserialize)]
pub struct BanRequest {
    pub jail: String,
    pub ip: String,
}

pub async fn fail2ban_ban(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<BanRequest>,
) -> ApiResult<impl IntoResponse> {
    ban_or_unban(admin, state, p, true).await
}

pub async fn fail2ban_unban(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<BanRequest>,
) -> ApiResult<impl IntoResponse> {
    ban_or_unban(admin, state, p, false).await
}

async fn ban_or_unban(admin: AdminUser, state: SharedState, p: BanRequest, ban: bool) -> ApiResult<impl IntoResponse> {
    if !fail2ban::JAILS.contains(&p.jail.as_str()) {
        return Err(ApiError::BadRequest("Unknown jail".into()));
    }
    let ip = validate::cidr(&p.ip).map_err(ApiError::BadRequest)?;
    if ip.contains('/') {
        return Err(ApiError::BadRequest("Enter a single IP address".into()));
    }
    if ban && admin.0.ip.as_deref() == Some(ip.as_str()) {
        return Err(ApiError::BadRequest("Refusing to ban your own IP address".into()));
    }
    if ban && p.jail == fail2ban::PANEL_JAIL && ip.parse::<std::net::IpAddr>().is_ok_and(|a| state.is_cloudflare(a)) {
        return Err(ApiError::BadRequest(
            "That is a Cloudflare address, used by many visitors. Ban the visitor's own address.".into(),
        ));
    }
    let (jail, addr) = (p.jail.clone(), ip.clone());
    blocking(move || {
        if ban {
            fail2ban::ban(&jail, &addr)
        } else {
            fail2ban::unban(&jail, &addr)
        }
        .map_err(ApiError::Unprocessable)
    })
    .await?;
    state
        .db(move |conn| {
            audit::record(
                conn,
                &admin.0,
                if ban { "fail2ban.ban" } else { "fail2ban.unban" },
                Some(&p.jail),
                Some(&ip),
            );
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "ok": true })))
}
