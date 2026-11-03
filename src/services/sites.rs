use super::NginxService;
use crate::api::error::{ApiError, ApiResult};
use crate::config::Config;
use crate::db::{self, models::Site, models::SiteType, NewSite};
use crate::validate;
use rusqlite::Connection;
use std::fs;
use std::path::{Path, PathBuf};

pub struct SiteInput {
    pub domain: String,
    pub site_type: String,
    pub target_port: Option<u16>,
    pub document_root: Option<String>,
    pub system_user: Option<String>,
    pub include_www: bool,
}

/// Validate input, store the site and apply its nginx vhost. Rolls back the DB row if
/// nginx rejects the configuration.
pub fn provision(config: &Config, conn: &Connection, input: SiteInput) -> ApiResult<Site> {
    let domain = validate::domain(&input.domain).map_err(ApiError::BadRequest)?;
    let site_type =
        SiteType::parse(&input.site_type).ok_or_else(|| ApiError::BadRequest("Unknown site type".into()))?;
    let system_user =
        validate::system_user(input.system_user.as_deref().unwrap_or("cloudpanel")).map_err(ApiError::BadRequest)?;

    let (target_port, document_root) = if site_type == SiteType::Static {
        let root = static_root(config, &domain, input.document_root.as_deref())?;
        (None, Some(root))
    } else {
        let port = validate::port(input.target_port).map_err(ApiError::BadRequest)?;
        if Some(port) == config.panel_port() {
            return Err(ApiError::BadRequest(
                "That port is used by the control panel itself".into(),
            ));
        }
        (Some(port), None)
    };

    let new = NewSite {
        domain: &domain,
        site_type: site_type.as_str(),
        target_port,
        document_root: document_root.as_deref(),
        system_user: &system_user,
        include_www: input.include_www,
    };
    let id = db::create_site(conn, &new).map_err(|e| {
        if db::is_unique_violation(&e) {
            ApiError::Conflict(format!("{domain} already exists"))
        } else {
            e.into()
        }
    })?;
    let site = db::find_site_by_id(conn, id)?.ok_or(ApiError::NotFound("Site"))?;

    if let Err(e) = NginxService::write_and_apply(config, &site) {
        db::delete_site(conn, id)?;
        return Err(ApiError::Unprocessable(e));
    }
    Ok(site)
}

/// Resolve (and create) the document root for a static site, confined to `sites_dir`.
fn static_root(config: &Config, domain: &str, requested: Option<&str>) -> ApiResult<String> {
    let base = validate::absolute(&config.sites_dir);
    let root: PathBuf = match requested.map(str::trim).filter(|s| !s.is_empty()) {
        Some(p) => validate::path_within(p, &base).map_err(ApiError::BadRequest)?,
        None => base.join(domain).join("public"),
    };

    fs::create_dir_all(&root).map_err(|e| ApiError::internal(format!("create {}: {e}", root.display())))?;
    // Re-check after resolving symlinks so a link inside sites_dir can't point elsewhere.
    let canon_base = fs::canonicalize(&base).map_err(ApiError::internal)?;
    let canon_root = fs::canonicalize(&root).map_err(ApiError::internal)?;
    if !canon_root.starts_with(&canon_base) {
        return Err(ApiError::BadRequest(
            "Document root must be inside the sites directory".into(),
        ));
    }

    let index = root.join("index.html");
    if !index.exists() {
        let page = format!(
            "<!doctype html><meta charset=\"utf-8\"><title>{domain}</title>\
             <body style=\"font-family:system-ui;display:grid;place-items:center;height:100vh;margin:0\">\
             <p>{domain} is ready. Upload your files to <code>{}</code>.</p>",
            root.display()
        );
        let _ = fs::write(&index, page);
    }
    Ok(display_path(&canon_root))
}

/// Strip the Windows verbatim prefix so dev paths stay readable.
fn display_path(p: &Path) -> String {
    let s = p.to_string_lossy();
    s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
}
