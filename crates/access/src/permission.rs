//! Permission reference table access and role-permission lookups.
//!
//! Neither function takes an `actor` (§5 p.5 exceptions):
//! - `list_permissions` — the `(resource, action)` reference is public to
//!   authenticated users; it is not an action, not sensitive.
//! - `get_permissions_for_role` — helper, called after `require` in a caller
//!   (e.g. `saas::access::assign_role`); returns the raw
//!   `(resource, action)` pairs that `authz.grant_role` needs.

use uuid::Uuid;

use crate::role::get_permissions_for_role_id;
use crate::{AccessError, AccessState, Permission, RoleKey};

/// Returns the whole `permissions` reference table, ordered by
/// `(resource, action)`.
///
/// **No `actor`** (§5 p.5 exception): the reference is not sensitive.
pub async fn list_permissions(state: &AccessState) -> Result<Vec<Permission>, AccessError> {
    let rows = sqlx::query_as::<_, (String, String, String)>(
        r#"
        select resource, action, description
        from permissions
        order by resource, action
        "#,
    )
    .fetch_all(state.pool())
    .await?;

    Ok(rows
        .into_iter()
        .map(|(resource, action, description)| Permission {
            resource,
            action,
            description,
        })
        .collect())
}

/// Returns `(resource, action)` pairs for `(domain, role_key)`, or an empty
/// vector if the role does not exist.
///
/// **No `actor`** (§5 p.5 exception): helper, called after `require` in a
/// caller. The result is passed directly to
/// `authz.grant_role(user_id, domain, role_key, permissions)`.
pub async fn get_permissions_for_role(
    state: &AccessState,
    domain: &str,
    role_key: &RoleKey,
) -> Result<Vec<(String, String)>, AccessError> {
    let role_id: Option<Uuid> =
        sqlx::query_scalar("select id from roles where domain = $1 and key = $2")
            .bind(domain)
            .bind(role_key.as_str())
            .fetch_optional(state.pool())
            .await?;

    let Some(role_id) = role_id else {
        return Ok(Vec::new());
    };

    let permissions = get_permissions_for_role_id(state.pool(), role_id).await?;
    Ok(permissions
        .into_iter()
        .map(|p| (p.resource, p.action))
        .collect())
}
