//! Workspace pages: the list of workspaces the current user belongs to, a
//! single-workspace page (documents + links to invitations/members/roles),
//! and a single-document page.

use domain::Document;
use leptos::callback::Callback;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::components::A;
use leptos_router::hooks::use_params;
use leptos_router::params::Params;
use uuid::Uuid;

use crate::pages::member::my_permissions;

// ─── Server functions ───────────────────────────────────────────────────────

/// Lists workspaces the current user is a member of.
#[server]
pub async fn list_my_workspaces() -> Result<Vec<domain::Workspace>, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;
    saas::workspace::list_memberships(&state.saas, &user)
        .await
        .map_err(crate::error::core_error_to_server_fn)
}

/// Creates a document in a workspace.
#[server]
pub async fn create_document(workspace_id: Uuid, title: String) -> Result<Document, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;
    saas::workspace::create_document(&state.saas, &user, workspace_id, title)
        .await
        .map_err(crate::error::core_error_to_server_fn)
}

/// Lists documents in a workspace.
#[server]
pub async fn list_documents(workspace_id: Uuid) -> Result<Vec<Document>, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;
    saas::workspace::list_documents(&state.saas, &user, workspace_id)
        .await
        .map_err(crate::error::core_error_to_server_fn)
}

/// Gets a single document.
#[server]
pub async fn get_document(
    workspace_id: Uuid,
    document_id: Uuid,
) -> Result<Document, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;
    saas::workspace::get_document(&state.saas, &user, workspace_id, document_id)
        .await
        .map_err(crate::error::core_error_to_server_fn)
}

// ─── Document list (nested) ─────────────────────────────────────────────────

/// Nested document list for a workspace. Refetches whenever `refresh`
/// changes; `WorkspacePage` bumps `refresh` after creating a document.
#[component]
pub fn DocumentListPage(workspace_id: Uuid, refresh: ReadSignal<u32>) -> impl IntoView {
    let documents = RwSignal::new(Vec::<Document>::new());
    let error = RwSignal::new(None::<String>);

    Effect::new(move |_| {
        let _ = refresh.get();
        spawn_local(async move {
            match list_documents(workspace_id).await {
                Ok(docs) => {
                    documents.set(docs);
                    error.set(None);
                }
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    });

    view! {
        <div class="mt-8">
            <h2 class="text-xl font-semibold">"Documents"</h2>
            {move || error.get().map(|e| view! { <p class="mt-4 text-red-400">{e}</p> })}
            <ul class="mt-3 divide-y divide-neutral-800">
                {move || {
                    let docs = documents.get();
                    if docs.is_empty() {
                        view! {
                            <li class="py-2 text-neutral-500">"No documents yet."</li>
                        }
                            .into_any()
                    } else {
                        docs.into_iter()
                            .map(|d| {
                                let ws_id = d.workspace_id;
                                let doc_id = d.id;
                                view! {
                                    <li class="py-3">
                                        <A
                                            href=format!("/workspaces/{ws_id}/documents/{doc_id}")
                                            attr:class="font-medium text-blue-400 hover:underline text-lg block"
                                        >
                                            {d.title}
                                        </A>
                                    </li>
                                }
                            })
                            .collect_view()
                            .into_any()
                    }
                }}
            </ul>
        </div>
    }
}

// ─── Document form (nested) ─────────────────────────────────────────────────

/// Nested document-creation form. Calls `on_created` after a successful
/// server call; the parent bumps its refresh signal.
#[component]
pub fn DocumentFormPage(workspace_id: Uuid, on_created: Callback<()>) -> impl IntoView {
    let title = RwSignal::new(String::new());
    let error = RwSignal::new(None::<String>);

    let submit = move |_| {
        let t = title.get();
        spawn_local(async move {
            match create_document(workspace_id, t).await {
                Ok(_) => {
                    title.set(String::new());
                    error.set(None);
                    on_created.run(());
                }
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    };

    view! {
        <div class="card mt-6 border p-4 rounded">
            <h2 class="text-lg font-semibold">"Create document"</h2>
            <input
                class="input mt-2 border p-2 w-full"
                placeholder="Document title"
                bind:value=title
            />
            <button class="btn mt-3 border p-2 rounded" on:click=submit>
                "Create document"
            </button>
            {move || error.get().map(|e| view! { <p class="mt-4 text-red-400">{e}</p> })}
        </div>
    }
}

// ─── Workspace list (`/workspaces`) ─────────────────────────────────────────

/// `/workspaces` — list of workspaces the current user belongs to.
#[component]
pub fn WorkspaceListPage() -> impl IntoView {
    let workspaces = RwSignal::new(Vec::<domain::Workspace>::new());
    let error = RwSignal::new(None::<String>);

    Effect::new(move |_| {
        spawn_local(async move {
            match list_my_workspaces().await {
                Ok(list) => workspaces.set(list),
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    });

    view! {
        <main class="mx-auto max-w-2xl p-8">
            <h1 class="text-2xl font-bold">"My workspaces"</h1>
            <p class="mt-2 text-sm text-neutral-400">
                "Workspaces you are a member of. To create one, open a tenant page."
            </p>
            <A href="/tenants" attr:class="btn mt-4 inline-block">"My tenants"</A>

            {move || error.get().map(|e| view! { <p class="mt-4 text-red-400">{e}</p> })}

            <ul class="mt-8 divide-y divide-neutral-800">
                {move || {
                    let list = workspaces.get();
                    if list.is_empty() {
                        view! {
                            <li class="py-2 text-neutral-500">"No workspaces yet."</li>
                        }
                            .into_any()
                    } else {
                        list.into_iter()
                            .map(|w| {
                                let id = w.id;
                                let tid = w.tenant_id;
                                view! {
                                    <li class="py-3 flex items-center justify-between gap-4">
                                        <div>
                                            <A
                                                href=format!("/workspaces/{id}")
                                                attr:class="font-medium text-blue-400 hover:underline text-lg block"
                                            >
                                                {w.name.clone()}
                                            </A>
                                            <p class="text-sm text-neutral-400 mt-1">
                                                {format!("id: {id} · tenant: {tid}")}
                                            </p>
                                        </div>
                                        <div class="flex gap-2">
                                            <A
                                                href=format!("/workspaces/{id}")
                                                attr:class="btn text-sm"
                                            >
                                                "Open"
                                            </A>
                                            <A
                                                href=format!("/workspaces/{id}/invitations")
                                                attr:class="btn text-sm"
                                            >
                                                "Invitations"
                                            </A>
                                        </div>
                                    </li>
                                }
                            })
                            .collect_view()
                            .into_any()
                    }
                }}
            </ul>
        </main>
    }
}

// ─── Single workspace (`/workspaces/:workspace_id`) ─────────────────────────

#[derive(Params, PartialEq)]
struct WorkspaceParams {
    workspace_id: Uuid,
}

/// `/workspaces/:workspace_id` — single workspace page: document list, create
/// form (only when permitted), and links to invitations/members/roles (only
/// when permitted).
#[component]
pub fn WorkspacePage() -> impl IntoView {
    let params = use_params::<WorkspaceParams>();
    let workspace_id = move || params.with(|r| r.as_ref().ok().map(|p| p.workspace_id));

    let can_write = RwSignal::new(false);
    let can_members = RwSignal::new(false);
    let can_roles = RwSignal::new(false);
    let can_invitations = RwSignal::new(false);
    let refresh = RwSignal::new(0u32);

    Effect::new(move |_| {
        let Some(id) = workspace_id() else { return };
        let domain = domain::workspace_domain(id);
        spawn_local(async move {
            match my_permissions(domain).await {
                Ok(perms) => {
                    let has = |r: &str, a: &str| {
                        perms.iter().any(|(pr, pa)| pr == r && pa == a)
                    };
                    can_write.set(has("documents", "write"));
                    can_members.set(has("members", "list"));
                    can_roles.set(has("roles", "list"));
                    can_invitations.set(has("invitations", "list"));
                }
                Err(_) => {
                    can_write.set(false);
                    can_members.set(false);
                    can_roles.set(false);
                    can_invitations.set(false);
                }
            }
        });
    });

    let on_created = Callback::new(move |_| refresh.update(|n| *n += 1));

    view! {
        <main class="mx-auto max-w-2xl p-8">
            <A href="/workspaces" attr:class="text-sm text-neutral-400">"← All workspaces"</A>

            <h1 class="mt-2 text-2xl font-bold">"Workspace"</h1>
            <p class="mt-2 text-sm text-neutral-400">
                {move || workspace_id()
                    .map(|id| format!("id: {id}"))
                    .unwrap_or_else(|| "invalid workspace id".into())}
            </p>

            <div class="mt-4 flex gap-2 flex-wrap">
                {move || {
                    let Some(id) = workspace_id() else { return None };
                    let mut links = Vec::new();
                    if can_invitations.get() {
                        links.push(view! {
                            <A href=format!("/workspaces/{id}/invitations") attr:class="btn text-sm">
                                "Invitations"
                            </A>
                        });
                    }
                    if can_members.get() {
                        links.push(view! {
                            <A href=format!("/workspaces/{id}/members") attr:class="btn text-sm">
                                "Members"
                            </A>
                        });
                    }
                    if can_roles.get() {
                        links.push(view! {
                            <A href=format!("/workspaces/{id}/roles") attr:class="btn text-sm">
                                "Roles"
                            </A>
                        });
                    }
                    Some(links)
                }}
            </div>

            {move || {
                let Some(id) = workspace_id() else { return None };
                can_write.get().then(|| view! {
                    <DocumentFormPage workspace_id=id on_created=on_created />
                })
            }}

            {move || workspace_id().map(|id| view! {
                <DocumentListPage workspace_id=id refresh=refresh.read_only() />
            })}
        </main>
    }
}

// ─── Single document (`/workspaces/:workspace_id/documents/:document_id`) ───

#[derive(Params, PartialEq)]
struct DocumentParams {
    workspace_id: Uuid,
    document_id: Uuid,
}

/// `/workspaces/:workspace_id/documents/:document_id` — single document page.
#[component]
pub fn DocumentPage() -> impl IntoView {
    let params = use_params::<DocumentParams>();
    let ids = move || params.with(|r| r.as_ref().ok().map(|p| (p.workspace_id, p.document_id)));

    let document = RwSignal::new(None::<Document>);
    let error = RwSignal::new(None::<String>);

    Effect::new(move |_| {
        let Some((ws_id, doc_id)) = ids() else { return };
        spawn_local(async move {
            match get_document(ws_id, doc_id).await {
                Ok(doc) => document.set(Some(doc)),
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    });

    view! {
        <main class="mx-auto max-w-2xl p-8">
            {move || ids().map(|(ws_id, _)| view! {
                <A href=format!("/workspaces/{ws_id}") attr:class="text-sm text-neutral-400">
                    "← Back to workspace"
                </A>
            })}

            {move || error.get().map(|e| view! { <p class="mt-4 text-red-400">{e}</p> })}

            {move || document.get().map(|doc| view! {
                <article class="mt-6">
                    <h1 class="text-3xl font-bold">{doc.title}</h1>
                    <p class="text-sm text-neutral-400 mt-2">
                        {format!("Created: {}", doc.created_at)}
                    </p>
                    <div class="mt-6 whitespace-pre-wrap text-lg">
                        {doc.body}
                    </div>
                </article>
            })}
        </main>
    }
}