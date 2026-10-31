//! Client-side route guards.
//!
//! **UX-only, not a security boundary.** A guard hides pages the actor
//! cannot use, but the backend `authz.require` / `resolve_active_tenant`
//! calls in `saas::*` remain authoritative. A client that bypasses the
//! guard still gets HTTP 401/403 from the server functions.
//!
//! **Architecture.** A single [`GuardRoute`] sits in front of every
//! private route. The *policy* — which permission a route requires — is
//! declared next to the route in `src/lib.rs` via the [`RouteGuard`] enum,
//! not inside `pages/*.rs`. Adding a new guarded route is a one-line
//! change in `lib.rs`; changing a policy (e.g. adding an
//! `OrPlatformAdmin` escape hatch later) is a one-line change in this
//! module, not in twenty page files.
//!
//! `RouteGuard::Public` routes bypass the guard entirely (`/`, `/login`,
//! `/register`, `/verify/:token`, `/forgot-password`,
//! `/reset-password/:token`, `/invitations/:token`). `RouteGuard::Auth`
//! requires an authenticated actor. The `Platform`, `Tenant`,
//! `Workspace` variants additionally require a specific `(resource,
//! action)` in the corresponding domain; the `*Any` variants pass if the
//! actor holds at least one of the listed pairs.
//!
//! **Why monolithic.** A first version tried `RouteGuard::Tenant { … } =>
//! view! { <RequirePermission>{children()}</RequirePermission> }`. That
//! fails to compile: `children()` inside nested `view!` turns the outer
//! `move ||` into `FnOnce` (`children` gets moved out of its
//! environment). Storing `children` in a `StoredValue` and calling
//! `children.with_value(|c| c())` sidesteps the problem: `with_value`
//! borrows `&self`, so the outer closure stays `Fn`.
//!
//! **SSR note.** `Effect` does not run on the server, so an SSR response
//! for a guarded route contains the loading placeholder (or whatever the
//! page renders before hydration). The guard runs on hydration and either
//! renders `children` or redirects. A fully SSR-correct version would use
//! `Resource`/`Suspense`; tracked as an enhancement, not part of this
//! follow-up.
//!
//! **Server-side per-route middleware is deliberately deferred to Stage
//! 4** (defense in depth). It would duplicate the logic below and belongs
//! in a general `AuthLayer`, not in the reference consumer. See
//! `handoff.md` §16 and Appendix B §2.49 / §IV.40.

use leptos::children::ChildrenFn;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::{use_location, use_navigate, use_params};
use leptos_router::params::Params;
use uuid::Uuid;

use crate::pages::invitation::{who_am_i, SessionUser};
use crate::pages::member::my_permissions;

// ─── Route policy ──────────────────────────────────────────────────────────

/// Declarative policy for one route. Placed next to `<Route>` in `lib.rs`;
/// [`GuardRoute`] turns it into the matching check.
#[derive(Clone)]
pub enum RouteGuard {
    /// No guard at all — public page.
    Public,
    /// Requires an authenticated actor, no specific permission.
    Auth,
    /// `platform` domain, a single `(resource, action)`.
    Platform {
        resource: &'static str,
        action: &'static str,
    },
    /// `tenant:{id}` domain, a single `(resource, action)`.
    Tenant {
        resource: &'static str,
        action: &'static str,
    },
    /// `tenant:{id}` domain, at least one of the `(resource, action)`
    /// pairs.
    TenantAny(Vec<(&'static str, &'static str)>),
    /// `workspace:{id}` domain, a single `(resource, action)`.
    Workspace {
        resource: &'static str,
        action: &'static str,
    },
    /// `workspace:{id}` domain, at least one of the `(resource, action)`
    /// pairs.
    WorkspaceAny(Vec<(&'static str, &'static str)>),
}

// ─── URL params for guard ──────────────────────────────────────────────────

/// Route params for `/tenants/:tenant_id/...` pages. Same shape as the
/// per-page structs in `pages/*.rs`; defined locally so the guard module is
/// self-contained (no cross-page `pub(crate)` visibility churn).
#[derive(Params, PartialEq)]
struct TenantIdParams {
    tenant_id: Uuid,
}

/// Route params for `/workspaces/:workspace_id/...` pages.
#[derive(Params, PartialEq)]
struct WorkspaceIdParams {
    workspace_id: Uuid,
}

// ─── GuardRoute — monolithic ───────────────────────────────────────────────

/// Route component. Enforces `guard` before rendering `children`. All
/// permission checks are inline — no nested `view!` with `children()`
/// (that would turn the outer closure into `FnOnce`).
#[component]
pub fn GuardRoute(guard: RouteGuard, children: ChildrenFn) -> impl IntoView {
    let children = StoredValue::new(children);
    let guard = StoredValue::new(guard);

    let session = RwSignal::new(None::<Option<SessionUser>>);
    let perms: RwSignal<Option<Result<Vec<(String, String)>, String>>> = RwSignal::new(None);
    let error = RwSignal::new(None::<String>);

    let navigate = use_navigate();
    let location = use_location();
    let params_t = use_params::<TenantIdParams>();
    let params_w = use_params::<WorkspaceIdParams>();

    // Domain for the permission check. `None` for Public/Auth (no permission
    // check) or for a Tenant/Workspace route whose id failed to parse.
    let domain_memo = Memo::new(move |_| {
        let g = guard.get_value();
        match g {
            RouteGuard::Public | RouteGuard::Auth => None,
            RouteGuard::Platform { .. } => Some(domain::PLATFORM_DOMAIN.to_string()),
            RouteGuard::Tenant { .. } | RouteGuard::TenantAny(..) => params_t.with(|r| {
                r.as_ref()
                    .ok()
                    .map(|p| domain::tenant_domain(p.tenant_id))
            }),
            RouteGuard::Workspace { .. } | RouteGuard::WorkspaceAny(..) => params_w.with(|r| {
                r.as_ref()
                    .ok()
                    .map(|p| domain::workspace_domain(p.workspace_id))
            }),
        }
    });

    // Auth check (skipped for Public).
    Effect::new(move |_| {
        let g = guard.get_value();
        if matches!(&g, RouteGuard::Public) {
            return;
        }
        let nav = navigate.clone();
        let loc = location.clone();
        spawn_local(async move {
            match who_am_i().await {
                Ok(Some(u)) => session.set(Some(Some(u))),
                Ok(None) => {
                    let path = loc.pathname.get_untracked();
                    if !path.is_empty() {
                        let _ = crate::auth::set_return_url(path).await;
                    }
                    nav("/login", Default::default());
                    session.set(Some(None));
                }
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    });

    // Permission check (skipped for Public/Auth or when domain is None).
    Effect::new(move |_| {
        let Some(d) = domain_memo.get() else {
            return;
        };
        spawn_local(async move {
            match my_permissions(d).await {
                Ok(p) => perms.set(Some(Ok(p))),
                Err(e) => perms.set(Some(Err(e.to_string()))),
            }
        });
    });

    view! {
        {move || {
            if let Some(e) = error.get() {
                return view! { <p class="text-red-400">{e}</p> }.into_any();
            }

            let g = guard.get_value();

            if matches!(&g, RouteGuard::Public) {
                return children.with_value(|c| c());
            }

            match session.get() {
                None => view! {
                    <p class="text-neutral-400">"Loading…"</p>
                }
                .into_any(),
                Some(None) => view! {
                    <p class="text-neutral-400">"Redirecting to /login…"</p>
                }
                .into_any(),
                Some(Some(_)) => {
                    if matches!(&g, RouteGuard::Auth) {
                        return children.with_value(|c| c());
                    }
                    if domain_memo.get().is_none() {
                        return view! {
                            <p class="text-red-400">"Invalid id in the URL."</p>
                        }
                        .into_any();
                    }
                    match perms.get() {
                        None => view! {
                            <p class="text-neutral-400">"Checking permissions…"</p>
                        }
                        .into_any(),
                        Some(Err(e)) => view! {
                            <p class="text-red-400">{e}</p>
                        }
                        .into_any(),
                        Some(Ok(p)) => {
                            let ok = match &g {
                                RouteGuard::Platform { resource, action } => p
                                    .iter()
                                    .any(|(r, a)| r.as_str() == *resource && a.as_str() == *action),
                                RouteGuard::Tenant { resource, action } => p
                                    .iter()
                                    .any(|(r, a)| r.as_str() == *resource && a.as_str() == *action),
                                RouteGuard::TenantAny(req) => req.iter().any(|(rr, ra)| {
                                    p.iter().any(|(r, a)| r.as_str() == *rr && a.as_str() == *ra)
                                }),
                                RouteGuard::Workspace { resource, action } => p
                                    .iter()
                                    .any(|(r, a)| r.as_str() == *resource && a.as_str() == *action),
                                RouteGuard::WorkspaceAny(req) => req.iter().any(|(rr, ra)| {
                                    p.iter().any(|(r, a)| r.as_str() == *rr && a.as_str() == *ra)
                                }),
                                _ => false,
                            };
                            if ok {
                                children.with_value(|c| c())
                            } else {
                                forbidden_view()
                            }
                        }
                    }
                }
            }
        }}
    }
}

// ─── Standalone building blocks ────────────────────────────────────────────
//
// Kept for callers that pass static children (no `children()` inside
// nested `view!`). The reference app's `/platform` and `/platform/audit`
// routes use them directly; `GuardRoute` does not.

/// Renders `children` for an authenticated actor; otherwise stores the
/// current pathname in `return_url` and redirects to `/login`.
///
/// `ChildrenFn` (not `Children`): the reactive branch calls `children()`
/// on every re-render, so it must be `Fn`.
#[component]
pub fn RequireAuth(children: ChildrenFn) -> impl IntoView {
    let session = RwSignal::new(None::<Option<SessionUser>>);
    let error = RwSignal::new(None::<String>);
    let navigate = use_navigate();
    let location = use_location();

    Effect::new(move |_| {
        let nav = navigate.clone();
        let loc = location.clone();
        spawn_local(async move {
            match who_am_i().await {
                Ok(Some(user)) => session.set(Some(Some(user))),
                Ok(None) => {
                    let path = loc.pathname.get_untracked();
                    if !path.is_empty() {
                        let _ = crate::auth::set_return_url(path).await;
                    }
                    nav("/login", Default::default());
                    session.set(Some(None));
                }
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    });

    view! {
        {move || {
            if let Some(e) = error.get() {
                return view! { <p class="text-red-400">{e}</p> }.into_any();
            }
            match session.get() {
                None => view! {
                    <p class="text-neutral-400">"Loading…"</p>
                }
                .into_any(),
                Some(Some(_)) => children(),
                Some(None) => view! {
                    <p class="text-neutral-400">"Redirecting to /login…"</p>
                }
                .into_any(),
            }
        }}
    }
}

/// Renders `children` only if the actor has `(resource, action)` in
/// `domain`; otherwise renders a 403 placeholder.
#[component]
pub fn RequirePermission(
    domain: String,
    resource: &'static str,
    action: &'static str,
    children: ChildrenFn,
) -> impl IntoView {
    let allowed = RwSignal::new(None::<bool>);
    let error = RwSignal::new(None::<String>);

    Effect::new(move |_| {
        let d = domain.clone();
        spawn_local(async move {
            match my_permissions(d).await {
                Ok(perms) => {
                    let ok = perms
                        .iter()
                        .any(|(r, a)| r.as_str() == resource && a.as_str() == action);
                    allowed.set(Some(ok));
                }
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    });

    view! {
        {move || {
            if let Some(e) = error.get() {
                return view! { <p class="text-red-400">{e}</p> }.into_any();
            }
            match allowed.get() {
                None => view! {
                    <p class="text-neutral-400">"Checking permissions…"</p>
                }
                .into_any(),
                Some(false) => forbidden_view(),
                Some(true) => children(),
            }
        }}
    }
}

/// Renders `children` only if the actor has **at least one** of the
/// `required` `(resource, action)` pairs in `domain`; otherwise renders a
/// 403 placeholder.
#[component]
pub fn RequireAnyPermission(
    domain: String,
    required: Vec<(&'static str, &'static str)>,
    children: ChildrenFn,
) -> impl IntoView {
    let allowed = RwSignal::new(None::<bool>);
    let error = RwSignal::new(None::<String>);

    Effect::new(move |_| {
        let d = domain.clone();
        let req = required.clone();
        spawn_local(async move {
            match my_permissions(d).await {
                Ok(perms) => {
                    let ok = perms.iter().any(|(r, a)| {
                        req.iter()
                            .any(|(rr, ra)| r.as_str() == *rr && a.as_str() == *ra)
                    });
                    allowed.set(Some(ok));
                }
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    });

    view! {
        {move || {
            if let Some(e) = error.get() {
                return view! { <p class="text-red-400">{e}</p> }.into_any();
            }
            match allowed.get() {
                None => view! {
                    <p class="text-neutral-400">"Checking permissions…"</p>
                }
                .into_any(),
                Some(false) => forbidden_view(),
                Some(true) => children(),
            }
        }}
    }
}

fn forbidden_view() -> AnyView {
    view! {
        <div class="p-8 text-center">
            <h1 class="text-2xl font-bold text-red-400">"403 — Forbidden"</h1>
            <p class="mt-2 text-neutral-400">
                "You do not have permission to view this page."
            </p>
            <a class="btn mt-4 inline-block" href="/">"Back to home"</a>
        </div>
    }
    .into_any()
}