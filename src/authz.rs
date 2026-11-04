//! Authorization helpers: admins can access every site, site managers only the sites
//! assigned to them.

use crate::api::error::{ApiError, ApiResult};
use crate::auth::AuthUser;
use crate::db::{self, models::Site};
use rusqlite::Connection;

/// Load a site the user is allowed to manage. Unassigned sites look like missing ones
/// so site managers can't probe for other domains.
pub fn require_site(conn: &Connection, user: &AuthUser, site_id: i64) -> ApiResult<Site> {
    let site = db::find_site_by_id(conn, site_id)?.ok_or(ApiError::NotFound("Site"))?;
    if user.is_admin() || db::user_has_site(conn, user.id, site_id)? {
        Ok(site)
    } else {
        Err(ApiError::NotFound("Site"))
    }
}

pub fn require_admin(user: &AuthUser) -> ApiResult<()> {
    if user.is_admin() {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

pub fn visible_sites(conn: &Connection, user: &AuthUser) -> ApiResult<Vec<Site>> {
    Ok(if user.is_admin() {
        db::list_sites(conn)?
    } else {
        db::list_sites_for_user(conn, user.id)?
    })
}
