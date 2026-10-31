//! Platform administration pages.
//!
//! `PlatformTenantListPage` (route `/platform`) — create a tenant (as its
//! owner via `saas::platform::provision_tenant`), list every tenant on the
//! platform, and suspend or activate each. `PlatformAuditListPage`
//! (route `/platform/audit`) — read-only view of the most recent audit
//! rows.
//!
//! Stage 3h: `PlatformTenantListPage` reads `my_permissions("platform")`
//! through `PermsCache` (TTL 30s) for consistency with other pages.
//!
//! **Naming.** The component is `PlatformTenantListPage`, not
//! `PlatformPage` (Stage 3f). The route stays `/platform`; the second page
//! lives at `/platform/audit`.
//!
//! **`create_tenant` vs `provision_tenant`.** The `#[server]` keeps the
//! name `create_tenant` (URL/contract unchanged from Stage 1.1) but
//! delegates to `saas::platform::provision_tenant` with `actor == owner`:
//! the UI scenario "created → became owner" is preserved through an
//! explicit call. `saas::platform::create_tenant` (container-only) remains
//! available to library consumers who do not want an implicit owner.
//!
//! **`list_tenants` / `suspend_tenant` / `activate_tenant`** delegate to
//! `saas::platform::*` (Stage 3f). They require `(tenants, list)` /
//! `(tenants, manage)` in `PLATFORM_DOMAIN`; a non-platform-admin gets
//! HTTP 403 (`CoreError::Forbidden`).
//!
//! **`list_audit`** is the only `#[server]` that does not have a
//! `saas::*` wrapper: the `AuditLogger` trait is a single-method write
//! interface (by design — see `crates/audit/src/lib.rs`), and `list` is a
//! `PgAuditLogger`-specific read helper (Stage 3f). The permission check
//! `(audit, read)` in `PLATFORM_DOMAIN` is performed in the `#[server]`
//! via `saas::access::my_permissions` (the same read-only UX helper the
//! UI uses for button gating); `saas::access::my_permissions` is itself a
//! §5 p.5 exception, so no direct `authz.require` is called from the
//! example. `AuditRowView` is a client-side mirror of
//! `audit_pg::AuditRow` (which is SSR-only, like `access::Role` /
//! `RoleView`).
//!
//! **Hydrate-safety.** Client-side code (`#[component]` bodies) must not
//! reference `crate::state::AppState`, `crate::extract::CurrentUser`, or
//! `saas::*` directly — those modules are gated behind `#[cfg(feature =
//! "ssr")]`. The `PlatformTenantListPage` effect therefore obtains
//! effective permissions by calling the existing
//! [`crate::pages::member::my_permissions`] `#[server]` function (which
//! resolves the actor and calls `saas::access::my_permissions` server-side).

use domain::{Tenant, TenantStatus};
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::perms_cache::PermsCache;

// ─── Client-side DTO for audit rows ────────────────────────────────────────

/// Client-side mirror of `audit_pg::AuditRow`.
///
/// `audit_pg` is SSR-only (`sqlx` dependency), so the return type of
/// `list_audit` cannot reference it directly in a component compiled for
/// `hydrate`. Same pattern as `RoleView` (`pages/role.rs`):
/// `From<audit_pg::AuditRow>` is implemented under `ssr` only, and the
/// server function converts on its way out.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditRowView {
    pub id: Uuid,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    pub actor_id: Option<Uuid>,
    pub actor_email: Option<String>,
    pub event_type: String,
    pub target_type: Option<String>,
    pub target_id: Option<Uuid>,
    pub metadata: serde_json::Value,
}

#[cfg(feature = "ssr")]
impl From<audit_pg::AuditRow> for AuditRowView {
    fn from(r: audit_pg::AuditRow) -> Self {
        AuditRowView {
            id: r.id,
            occurred_at: r.occurred_at,
            actor_id: r.actor_id,
            actor_email: r.actor_email,
            event_type: r.event_type,
            target_type: r.target_type,
            target_id: r.target_id,
            metadata: r.metadata,
        }
    }
}

// ─── Server functions ──────────────────────────────────────────────────────

/// Creates a tenant and assigns the current user as its owner.
///
/// Delegates to `saas::platform::provision_tenant` with
/// `RoleKey::parse("owner")`. Name kept as `create_tenant` for the Leptos
/// endpoint (URL/contract unchanged from Stage 1.1).
#[server]
pub async fn create_tenant(name: String) -> Result<Tenant, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();

    let user = crate::extract::CurrentUser::from_request().await?.require()?;
    let owner_key =
        access::RoleKey::parse("owner").map_err(|e| ServerFnError::new(e.to_string()))?;

    let tenant = saas::platform::provision_tenant(&state.saas, &user, name, &user, &owner_key)
        .await
        .map_err(crate::error::core_error_to_server_fn)?;

    Ok(tenant)
}

/// Lists every tenant on the platform. Requires `(tenants, list)` in
/// `PLATFORM_DOMAIN`.
#[server]
pub async fn list_tenants() -> Result<Vec<Tenant>, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;
    saas::platform::list_tenants(&state.saas, &user)
        .await
        .map_err(crate::error::core_error_to_server_fn)
}

/// Suspends a tenant. Idempotent; emits `tenant.suspended` only on a
/// transition (`active` → `suspended`). Requires `(tenants, manage)` in
/// `PLATFORM_DOMAIN`.
#[server]
pub async fn suspend_tenant(tenant_id: Uuid) -> Result<Tenant, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;
    saas::platform::suspend_tenant(&state.saas, &user, tenant_id)
        .await
        .map_err(crate::error::core_error_to_server_fn)
}

/// Activates a suspended tenant. Idempotent; emits `tenant.activated` only
/// on a transition (`suspended` → `active`). Requires `(tenants, manage)`
/// in `PLATFORM_DOMAIN`.
#[server]
pub async fn activate_tenant(tenant_id: Uuid) -> Result<Tenant, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;
    saas::platform::activate_tenant(&state.saas, &user, tenant_id)
        .await
        .map_err(crate::error::core_error_to_server_fn)
}

/// Lists the most recent audit rows, newest first.
///
/// Permission `(audit, read)` in `PLATFORM_DOMAIN` is enforced via
/// `saas::access::my_permissions` — a read-only UX helper (also used by
/// the UI to gate navigation links). No direct `authz.require`: the
/// example never calls `authz.require` (handoff §4). `limit` is clamped to
/// `[1, 200]`; the audit table is append-only and unbounded in Stage 3f,
/// so a UI-side cap prevents accidental large reads before pagination
/// (Stage 4).
#[server]
pub async fn list_audit(limit: i64) -> Result<Vec<AuditRowView>, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;

    let perms = saas::access::my_permissions(&state.saas, &user, domain::PLATFORM_DOMAIN)
        .await
        .map_err(crate::error::core_error_to_server_fn)?;
    if !perms.iter().any(|(r, a)| r == "audit" && a == "read") {
        return Err(crate::error::core_error_to_server_fn(
            saas::CoreError::Forbidden,
        ));
    }

    let clamped = limit.clamp(1, 200);
    let logger = audit_pg::PgAuditLogger::from_pool(state.saas.pool().clone());
    let rows = logger
        .list(clamped)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(rows.into_iter().map(AuditRowView::from).collect())
}

// ─── `/platform` — tenant list ──────────────────────────────────────────────

/// `/platform` — create a tenant (as its owner) and manage the platform
/// tenant list (suspend / activate).
#[component]
pub fn PlatformTenantListPage() -> impl IntoView {
    let tenants = RwSignal::new(Vec::<Tenant>::new());
    let perms = RwSignal::new(std::collections::HashSet::<(String, String)>::new());
    let refresh = RwSignal::new(0u32);
    let name = RwSignal::new(String::new());
    let created = RwSignal::new(None::<Tenant>);
    let error = RwSignal::new(None::<String>);
    let cache = use_context::<PermsCache>().expect("PermsCache in context");

    Effect::new(move |_| {
        let _ = refresh.get();
        // `PermsCache` is `Clone` but not `Copy`. Clone per invocation so
        // `Effect::new`'s `move |_|` remains `FnMut`: the async block below
        // consumes the clone, not the captured `cache`.
        let cache = cache.clone();
        spawn_local(async move {
            match list_tenants().await {
                Ok(list) => {
                    tenants.set(list);
                    error.set(None);
                }
                Err(e) => error.set(Some(e.to_string())),
            }

            // Effective permissions for UI gating. `my_permissions` is the
            // existing `#[server]` from `pages/member.rs`; it resolves the
            // actor and calls `saas::access::my_permissions` server-side
            // (SSR-only modules never leak into this hydrate-compiled
            // component). Read through `PermsCache` for consistency with
            // the member/role pages (Stage 3h).
            let perms_vec = cache
                .get_or_fetch(domain::PLATFORM_DOMAIN.to_string(), |d| async move {
                    crate::pages::member::my_permissions(d)
                        .await
                        .unwrap_or_default()
                })
                .await;
            perms.set(perms_vec.into_iter().collect());
        });
    });

    let can_manage = move || {
        perms.with(|p| p.contains(&("tenants".to_string(), "manage".to_string())))
    };

    let submit = move |_| {
        spawn_local(async move {
            match create_tenant(name.get()).await {
                Ok(t) => {
                    created.set(Some(t));
                    name.set(String::new());
                    error.set(None);
                    refresh.update(|n| *n += 1);
                }
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    };

    view! {
        <main class="mx-auto max-w-2xl p-8">
            <div class="flex items-center justify-between">
                <h1 class="text-2xl font-bold">"Platform administration"</h1>
                <a class="text-sm text-neutral-400" href="/platform/audit">
                    "Audit log →"
                </a>
            </div>

            <div class="card mt-6">
                <h2 class="text-lg font-semibold">"Create tenant"</h2>
                <p class="mt-1 text-sm text-neutral-400">
                    "The current user becomes the tenant owner."
                </p>
                <input class="input mt-2" placeholder="Tenant name" bind:value=name />
                <button class="btn mt-4" on:click=submit>"Create tenant"</button>

                {move || error.get().map(|e| view! { <p class="mt-4 text-red-400">{e}</p> })}
                {move || created.get().map(|t| view! {
                    <p class="mt-4 text-green-400">
                        "Created tenant: " {t.name}
                    </p>
                })}
            </div>

            <div class="mt-8">
                <h2 class="text-xl font-semibold">"Tenants"</h2>
                <ul class="mt-3 divide-y divide-neutral-800">
                    {move || {
                        let list = tenants.get();
                        if list.is_empty() {
                            view! {
                                <li class="py-2 text-neutral-500">"No tenants yet."</li>
                            }
                                .into_any()
                        } else {
                            list.into_iter()
                                .map(|t| {
                                    let id = t.id;
                                    let name = t.name.clone();
                                    let status = t.status;
                                    let can_manage = can_manage();
                                    let is_active = status == TenantStatus::Active;
                                    let status_label = match status {
                                        TenantStatus::Active => "active",
                                        TenantStatus::Suspended => "suspended",
                                    };
                                    let status_class = if is_active {
                                        "text-green-400"
                                    } else {
                                        "text-yellow-400"
                                    };
                                    view! {
                                        <li class="py-3 flex items-center justify-between gap-4">
                                            <div>
                                                <p class="font-medium">{name}</p>
                                                <p class="text-sm text-neutral-400">
                                                    <span>{format!("id: {id} · status: ")}</span>
                                                    <span class=status_class>{status_label}</span>
                                                </p>
                                            </div>
                                            <div class="flex gap-2">
                                                <a
                                                    class="btn text-sm"
                                                    href=format!("/tenants/{id}")
                                                >
                                                    "Open"
                                                </a>
                                                {if can_manage {
                                                    let label = if is_active { "Suspend" } else { "Activate" };
                                                    Some(view! {
                                                        <button
                                                            class="btn text-sm"
                                                            on:click=move |_| {
                                                                spawn_local(async move {
                                                                    let result = if is_active {
                                                                        suspend_tenant(id).await
                                                                    } else {
                                                                        activate_tenant(id).await
                                                                    };
                                                                    match result {
                                                                        Ok(_) => {
                                                                            error.set(None);
                                                                            refresh.update(|n| *n += 1);
                                                                        }
                                                                        Err(e) => error.set(Some(e.to_string())),
                                                                    }
                                                                });
                                                            }
                                                        >
                                                            {label}
                                                        </button>
                                                    })
                                                } else {
                                                    None
                                                }}
                                            </div>
                                        </li>
                                    }
                                })
                                .collect_view()
                                .into_any()
                        }
                    }}
                </ul>
            </div>
        </main>
    }
}

// ─── `/platform/audit` — audit view ─────────────────────────────────────────

/// `/platform/audit` — the most recent audit rows, newest first.
///
/// Read-only; permission `(audit, read)` in `PLATFORM_DOMAIN` enforced in
/// the `list_audit` server function. A single `limit` input (default 100;
/// clamped server-side to `[1, 200]`) is the MVP filter set; richer
/// filtering (`actor`, `event_type`, `target`) and pagination are Stage 4
/// (Appendix B §IV).
///
/// The `limit` input is bound to `RwSignal<String>` — Leptos 0.8's
/// `bind:value` implements `FromEventTarget` / `GetValue` only for `String`
/// and `bool`, not numeric types. The string is parsed
/// (`trim().parse::<i64>()`) to `i64` inside the effect; invalid input
/// falls back to `100`.
#[component]
pub fn PlatformAuditListPage() -> impl IntoView {
    let rows = RwSignal::new(Vec::<AuditRowView>::new());
    let limit = RwSignal::new("100".to_string());
    let refresh = RwSignal::new(0u32);
    let error = RwSignal::new(None::<String>);

    Effect::new(move |_| {
        let _ = refresh.get();
        let lim_raw = limit.get();
        let lim = lim_raw.trim().parse::<i64>().unwrap_or(100);
        spawn_local(async move {
            match list_audit(lim).await {
                Ok(list) => {
                    rows.set(list);
                    error.set(None);
                }
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    });

    view! {
        <main class="mx-auto max-w-4xl p-8">
            <div class="flex items-center justify-between">
                <h1 class="text-2xl font-bold">"Audit log"</h1>
                <a class="text-sm text-neutral-400" href="/platform">
                    "← Back to platform"
                </a>
            </div>

            <div class="card mt-6">
                <label class="text-sm text-neutral-400" for="audit-limit">
                    "Limit (1–200)"
                </label>
                <input
                    id="audit-limit"
                    class="input mt-2"
                    type="number"
                    min="1"
                    max="200"
                    bind:value=limit
                />
                <button
                    class="btn mt-3"
                    on:click=move |_| refresh.update(|n| *n += 1)
                >
                    "Refresh"
                </button>
            </div>

            {move || error.get().map(|e| view! { <p class="mt-4 text-red-400">{e}</p> })}

            <div class="mt-8">
                <ul class="divide-y divide-neutral-800">
                    {move || {
                        let list = rows.get();
                        if list.is_empty() {
                            view! {
                                <li class="py-2 text-neutral-500">"No audit rows yet."</li>
                            }
                                .into_any()
                        } else {
                            list.into_iter()
                                .map(|r| {
                                    let when = r.occurred_at.to_rfc3339();
                                    let event_type = r.event_type.clone();
                                    let actor = r
                                        .actor_email
                                        .clone()
                                        .unwrap_or_else(|| "—".to_string());
                                    let target = match (r.target_type, r.target_id) {
                                        (Some(t), Some(id)) => format!("{t}:{id}"),
                                        (Some(t), None) => t,
                                        _ => "—".to_string(),
                                    };
                                    let metadata = serde_json::to_string(&r.metadata)
                                        .unwrap_or_else(|_| "{}".into());
                                    view! {
                                        <li class="py-3">
                                            <p class="text-sm text-neutral-400">{when}</p>
                                            <p class="font-medium">{event_type}</p>
                                            <p class="text-sm text-neutral-400">
                                                {format!("actor: {actor}")}
                                            </p>
                                            <p class="text-sm text-neutral-400">
                                                {format!("target: {target}")}
                                            </p>
                                            <p class="text-xs text-neutral-500 mt-1 break-all">
                                                {metadata}
                                            </p>
                                        </li>
                                    }
                                })
                                .collect_view()
                                .into_any()
                        }
                    }}
                </ul>
            </div>
        </main>
    }
}