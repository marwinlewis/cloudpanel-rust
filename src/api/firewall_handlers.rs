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
    /// One address or network. May also hold several, separated by commas or spaces.
    pub source: Option<String>,
    /// Several addresses or networks; each becomes its own ufw rule.
    #[serde(default)]
    pub sources: Option<Vec<String>>,
    pub comment: Option<String>,
}

/// Most sources one request may name.
const MAX_SOURCES: usize = 50;

/// The sources a request names: validated, normalised and de-duplicated, in the order given.
/// Blanks and `any` are dropped, so an empty list means "from anywhere".
fn parse_sources(single: Option<&str>, many: Option<&[String]>) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    let items = single
        .into_iter()
        .chain(many.unwrap_or_default().iter().map(String::as_str));
    for item in items.flat_map(|s| s.split(|c: char| c == ',' || c.is_whitespace())) {
        let s = item.trim();
        if s.is_empty() || s == "any" {
            continue;
        }
        let v = validate::cidr(s)?;
        if !out.contains(&v) {
            out.push(v);
        }
    }
    if out.len() > MAX_SOURCES {
        return Err(format!("At most {MAX_SOURCES} addresses per request"));
    }
    Ok(out)
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
    let sources = parse_sources(p.source.as_deref(), p.sources.as_deref()).map_err(ApiError::BadRequest)?;
    let comment = validate::short_text(p.comment.as_deref(), 120).map_err(ApiError::BadRequest)?;
    // Every rule in a request is this one with a different source: ufw takes one source per rule.
    let template = if block {
        if sources.is_empty() {
            return Err(ApiError::BadRequest("Enter the IP or network to block".into()));
        }
        Rule {
            action: Action::Deny,
            port: None,
            port_end: None,
            protocol: Protocol::Any,
            source: None,
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
            source: None,
        }
    };
    let rules: Vec<Rule> = if sources.is_empty() {
        vec![template]
    } else {
        sources
            .into_iter()
            .map(|s| Rule {
                source: Some(s),
                ..template.clone()
            })
            .collect()
    };

    // Lockout protection.
    if rules[0].action == Action::Deny {
        let ssh = blocking(|| Ok(FirewallService::ssh_ports())).await?;
        let my_ip = admin.0.ip.as_deref().and_then(|i| i.parse().ok());
        // Nothing outside can reach a closed panel port, so a rule there can't lock anyone out.
        let panel = state.config.panel_port().filter(|_| !state.direct_closed);
        for rule in &rules {
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
            if hits_me && panel.is_some_and(|p| rule.covers_port(p)) {
                return Err(ApiError::BadRequest(
                    "Refusing a rule that would block the control panel for your own connection. To stop direct \
                     access to the panel's port, set up a panel hostname and close the port in Settings → Panel \
                     certificate."
                        .into(),
                ));
            }
        }
    }

    let created = state
        .db(move |conn| {
            let mut created = Vec::new();
            let mut applied: Vec<String> = Vec::new();
            for rule in &rules {
                let new = NewRule {
                    port: rule.port,
                    port_end: rule.port_end,
                    protocol: rule.protocol.as_str(),
                    action: rule.action.as_str(),
                    source: rule.source.as_deref(),
                    comment: comment.as_deref(),
                };
                // Already there: nothing to do for this source.
                if db::firewall_rule_exists(conn, &new)? {
                    continue;
                }
                // Rules added before a failure stay: each has its own row, matching ufw.
                if let Err(e) = FirewallService::add(rule, comment.as_deref()) {
                    return Err(ApiError::Unprocessable(if applied.is_empty() {
                        e
                    } else {
                        format!("{e} (rules for {} were added)", applied.join(", "))
                    }));
                }
                // Adding it removed a rule with the same match and the other action from ufw.
                db::delete_firewall_rule_with_action(conn, &new, rule.action.opposite().as_str())?;
                let id = db::create_firewall_rule(conn, &new)?;
                let desc = format!("{} {}", rule.action.as_str(), rule.spec().join(" "));
                audit::record(conn, &admin.0, "firewall.add", None, Some(&desc));
                applied.push(rule.source.clone().unwrap_or_else(|| "anywhere".into()));
                created.extend(db::find_firewall_rule(conn, id)?);
            }
            if created.is_empty() {
                return Err(ApiError::Conflict(
                    if rules.len() == 1 {
                        "That rule already exists"
                    } else {
                        "Those rules already exist"
                    }
                    .into(),
                ));
            }
            Ok(created)
        })
        .await?;
    // A list of the rules added, one per source.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources_are_split_normalised_and_deduplicated() {
        let many = vec!["10.0.0.1, 192.168.1.0/24".to_string(), " 10.0.0.1 ".to_string()];
        assert_eq!(
            parse_sources(Some("203.0.113.9\n2001:db8::1"), Some(&many)).unwrap(),
            vec!["203.0.113.9", "2001:db8::1", "10.0.0.1", "192.168.1.0/24"]
        );
        assert!(parse_sources(Some(" any "), Some(&[String::new()])).unwrap().is_empty());
        assert!(parse_sources(None, None).unwrap().is_empty());
    }

    #[test]
    fn one_bad_source_rejects_the_request() {
        let err = parse_sources(Some("10.0.0.1, 10.0.0.999"), None).unwrap_err();
        assert!(err.contains("10.0.0.999"), "{err}");
        assert!(parse_sources(Some("10.0.0.0/33"), None).is_err());
    }

    #[test]
    fn too_many_sources_are_refused() {
        let many: Vec<String> = (1..=MAX_SOURCES + 1)
            .map(|i| format!("10.0.{}.{}", i / 250, i % 250))
            .collect();
        assert!(parse_sources(None, Some(&many)).is_err());
        assert_eq!(
            parse_sources(None, Some(&many[..MAX_SOURCES])).unwrap().len(),
            MAX_SOURCES
        );
    }
}
