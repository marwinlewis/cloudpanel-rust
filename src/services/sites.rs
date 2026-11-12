use super::{apps, pm2, sysusers, NginxService};
use crate::api::error::{ApiError, ApiResult};
use crate::config::Config;
use crate::db::models::{Site, SiteType, MANAGER_PM2, MANAGER_SYSTEMD};
use crate::db::{self, NewSite};
use crate::validate;
use rusqlite::Connection;
use std::fs;
use std::path::{Path, PathBuf};

pub struct SiteInput {
    pub domain: String,
    pub site_type: String,
    pub target_port: Option<u16>,
    pub document_root: Option<String>,
    /// Linux user to create for the site; derived from the domain when omitted.
    pub system_user: Option<String>,
    pub include_www: bool,
    /// With `include_www`: redirect www to the naked domain instead of serving both.
    pub www_redirect: bool,
    /// Start command for app sites (optional; can be set later).
    pub app_command: Option<String>,
    /// `systemd` or `pm2`. Node.js sites default to PM2.
    pub app_manager: Option<String>,
    /// Docker proxies point at a container and get no Linux user.
    pub create_user: bool,
    /// Start behind the maintenance page, the default for new sites, so nobody sees a
    /// half-built site or a placeholder before the admin is ready.
    pub maintenance_mode: bool,
}

/// Resolve the two www request fields, where omitted means redirect, the default for new sites.
pub fn www_choice(include_www: Option<bool>, www_redirect: Option<bool>) -> (bool, bool) {
    let include = include_www.unwrap_or(true);
    (include, include && www_redirect.unwrap_or(true))
}

/// Validate input, create the site's Linux user and home, store the site and apply its
/// nginx vhost. Rolls back the DB row if nginx rejects the configuration.
pub fn provision(config: &Config, conn: &Connection, input: SiteInput) -> ApiResult<Site> {
    let domain = validate::domain(&input.domain).map_err(ApiError::BadRequest)?;
    let site_type =
        SiteType::parse(&input.site_type).ok_or_else(|| ApiError::BadRequest("Unknown site type".into()))?;
    let app_command = match input.app_command.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
        Some(c) if site_type.has_app() => Some(validate::app_command(c).map_err(ApiError::BadRequest)?),
        _ => None,
    };

    // PHP is chosen when installing the panel. Check before anything is created.
    let php_version = if site_type == SiteType::Php {
        if !config.php_enabled {
            return Err(ApiError::BadRequest(
                "PHP isn't enabled on this server. Re-run the installer with --with-php to add it.".into(),
            ));
        }
        Some(
            super::php::installed_versions()
                .into_iter()
                .next()
                .ok_or_else(|| ApiError::Unprocessable("PHP-FPM is not installed on this server".into()))?,
        )
    } else {
        None
    };

    let target_port = if site_type.has_document_root() {
        None
    } else {
        let port = validate::port(input.target_port).map_err(ApiError::BadRequest)?;
        if Some(port) == config.panel_port() {
            return Err(ApiError::BadRequest(
                "That port is used by the control panel itself".into(),
            ));
        }
        Some(port)
    };

    let existing = db::list_sites(conn)?;
    if existing.iter().any(|s| s.domain == domain) {
        return Err(ApiError::Conflict(format!("{domain} already exists")));
    }
    let panel_hostname = super::panel_cert::load(conn).map(|p| p.hostname);
    if panel_hostname.as_deref() == Some(domain.as_str()) {
        return Err(ApiError::Conflict(format!(
            "{domain} is the control panel's own hostname"
        )));
    }
    // www belongs to the naked domain's site unless a separate site already claims it.
    if let Some(naked) = domain.strip_prefix("www.") {
        if existing.iter().any(|s| s.domain == naked && s.include_www) {
            return Err(ApiError::Conflict(format!(
                "{domain} is already handled by the site for {naked}"
            )));
        }
    }
    let www_name = format!("www.{domain}");
    let www_available = !domain.starts_with("www.")
        && !existing.iter().any(|s| s.domain == www_name)
        && panel_hostname.as_deref() != Some(www_name.as_str());
    let include_www = input.include_www && www_available;
    let www_redirect = include_www && input.www_redirect;

    // Linux user + home directory.
    let create_user = input.create_user && site_type != SiteType::DockerProxy;
    let app_manager = match input.app_manager.as_deref() {
        Some(MANAGER_SYSTEMD) => MANAGER_SYSTEMD,
        Some(MANAGER_PM2) if site_type == SiteType::Nodejs && create_user => MANAGER_PM2,
        Some(MANAGER_PM2) => return Err(ApiError::BadRequest("PM2 is only available for Node.js sites".into())),
        Some(_) => return Err(ApiError::BadRequest("Process manager must be systemd or pm2".into())),
        None if site_type == SiteType::Nodejs && create_user => MANAGER_PM2,
        None => MANAGER_SYSTEMD,
    };
    let (system_user, home) = if create_user {
        let requested = input
            .system_user
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|u| validate::system_user(u).map_err(ApiError::BadRequest))
            .transpose()?;
        let user = match requested {
            Some(u) => {
                if sysusers::name_in_use(&u) || ssh_user_taken(conn, &u) {
                    return Err(ApiError::Conflict(format!("The system user '{u}' already exists")));
                }
                u
            }
            None => {
                let base = validate::site_user_from_domain(&domain);
                sysusers::unique_name(&base, |n| ssh_user_taken(conn, n))
            }
        };
        let layout = sysusers::create_site_user(config, &user, &domain).map_err(ApiError::Unprocessable)?;
        (user, Some(layout))
    } else {
        ("cloudpanel".to_string(), None)
    };

    let document_root = if site_type.has_document_root() {
        Some(static_root(
            config,
            &domain,
            input.document_root.as_deref(),
            home.as_ref().map(|h| h.htdocs.as_path()),
        )?)
    } else {
        None
    };
    if let (Some(h), Some(_)) = (&home, &document_root) {
        let _ = sysusers::chown_recursive(&h.htdocs, &system_user, &system_user);
    }
    let home_dir = home.as_ref().map(|h| display_path(&h.home));

    let new = NewSite {
        domain: &domain,
        site_type: site_type.as_str(),
        target_port,
        document_root: document_root.as_deref(),
        system_user: &system_user,
        include_www,
        www_redirect,
        home_dir: home_dir.as_deref(),
        app_command: app_command.as_deref(),
        app_manager,
        php_version: php_version.as_deref(),
        maintenance_mode: input.maintenance_mode,
    };
    let id = db::create_site(conn, &new).map_err(|e| {
        if db::is_unique_violation(&e) {
            ApiError::Conflict(format!("{domain} already exists"))
        } else {
            e.into()
        }
    })?;
    if home.is_some() {
        db::create_ssh_user(conn, id, &system_user, false, true)?;
    }
    let mut site = db::find_site_by_id(conn, id)?.ok_or(ApiError::NotFound("Site"))?;

    // The pool goes first: nginx must not point at a socket that nothing is listening on yet.
    let applied = if site_type == SiteType::Php {
        super::php::apply(&site)
    } else {
        Ok(())
    }
    .and_then(|()| NginxService::write_and_apply(config, &site));
    if let Err(e) = applied {
        let _ = super::php::remove(&site);
        db::delete_site(conn, id)?;
        if home.is_some() {
            let _ = sysusers::delete_user(&system_user, true);
        }
        return Err(ApiError::Unprocessable(e));
    }

    if site.app_command.is_some() {
        site.app_enabled = true;
        db::save_site(conn, &site)?;
        // Without PM2 yet, the job that installs it (see `create_new_site`) starts the app.
        if !site.uses_pm2() || pm2::installed() {
            if let Err(e) = apps::apply(config, &site) {
                tracing::warn!("app unit for {domain}: {e}");
            }
        }
    }
    Ok(site)
}

fn ssh_user_taken(conn: &Connection, name: &str) -> bool {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ssh_users WHERE username = ?1)",
        [name],
        |r| r.get::<_, bool>(0),
    )
    .unwrap_or(true)
}

/// Remove everything a site owns on the system. Returns warnings for parts that failed.
pub fn deprovision(config: &Config, conn: &Connection, site: &Site, delete_files: bool) -> ApiResult<Vec<String>> {
    let mut warnings = Vec::new();
    if let Err(e) = NginxService::remove_site(config, &site.domain) {
        warnings.push(format!("nginx: {e}"));
    }
    apps::remove(config, site);
    if let Err(e) = super::php::remove(site) {
        warnings.push(format!("php: {e}"));
    }
    // Databases go with the files; when files are kept, the databases are kept too
    // (but no longer listed in the panel).
    for d in db::list_databases(conn, Some(site.id))? {
        let Some(engine) = super::databases::Engine::parse(&d.engine) else {
            continue;
        };
        if delete_files {
            if let Err(e) = super::databases::drop_db(config, engine, site, &d.name, &d.users) {
                warnings.push(format!("database {}: {e}", d.name));
            }
        } else if engine != super::databases::Engine::Sqlite {
            warnings.push(format!("{} database '{}' was kept", engine.label(), d.name));
        }
    }
    for u in db::list_ssh_users(conn, site.id)? {
        sysusers::remove_authorized_keys(config, &u.username);
        if !u.is_owner {
            if let Err(e) = sysusers::delete_user(&u.username, false) {
                warnings.push(format!("user {}: {e}", u.username));
            }
        }
    }
    if site.home_dir.is_some() {
        if delete_files {
            if let Err(e) = sysusers::delete_user(&site.system_user, true) {
                warnings.push(format!("user {}: {e}", site.system_user));
            }
            // userdel --remove leaves the directory in dev; clean it up explicitly.
            if let Some(h) = &site.home_dir {
                let p = Path::new(h);
                if p.starts_with(validate::absolute(&config.home_dir)) && p.exists() {
                    let _ = fs::remove_dir_all(p);
                }
            }
        } else if let Err(e) = sysusers::delete_user(&site.system_user, false) {
            warnings.push(format!("user {}: {e}", site.system_user));
        }
    }
    db::delete_site(conn, site.id)?;
    Ok(warnings)
}

/// Resolve (and create) the document root for a static site. New sites keep it inside
/// the site user's htdocs; legacy sites without a user stay confined to `sites_dir`.
fn static_root(config: &Config, domain: &str, requested: Option<&str>, htdocs: Option<&Path>) -> ApiResult<String> {
    let base = match htdocs {
        Some(h) => h.to_path_buf(),
        None => validate::absolute(&config.sites_dir),
    };
    let root: PathBuf = match requested.map(str::trim).filter(|s| !s.is_empty()) {
        Some(p) => {
            let parent = base.parent().unwrap_or(&base).to_path_buf();
            validate::path_within(p, &parent).map_err(ApiError::BadRequest)?
        }
        None if htdocs.is_some() => base.clone(),
        None => base.join(domain).join("public"),
    };

    fs::create_dir_all(&root).map_err(|e| ApiError::internal(format!("create {}: {e}", root.display())))?;
    // Re-check after resolving symlinks so a link can't point elsewhere.
    let allowed = base.parent().unwrap_or(&base);
    let canon_base = fs::canonicalize(allowed).map_err(ApiError::internal)?;
    let canon_root = fs::canonicalize(&root).map_err(ApiError::internal)?;
    if !canon_root.starts_with(&canon_base) {
        return Err(ApiError::BadRequest(
            "Document root must be inside the site's directory".into(),
        ));
    }

    let index = root.join("index.html");
    if !index.exists() {
        let page = format!(
            "<!doctype html><meta charset=\"utf-8\"><title>{domain}</title>\
             <body style=\"font-family:system-ui;display:grid;place-items:center;height:100vh;margin:0\">\
             <p>{domain} is ready. Upload your files to <code>{}</code>.</p>",
            display_path(&canon_root)
        );
        let _ = fs::write(&index, page);
    }
    Ok(display_path(&canon_root))
}

/// Strip the Windows verbatim prefix so dev paths stay readable.
pub fn display_path(p: &Path) -> String {
    let s = p.to_string_lossy();
    s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
}
