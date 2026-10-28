//! Workspace pages: the list of workspaces the current user belongs to, and
//! a single-workspace page (documents + open invitations).

use domain::Document;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::use_params;
use leptos_router::params::Params;
use uuid::Uuid;

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

// ─── Workspace list (`/workspaces`) ─────────────────────────────────────────

/// `/workspaces` — list of workspaces the current user belongs to.
#[component]
pub fn WorkspacesListPage() -> impl IntoView {
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
            <a class="btn mt-4 inline-block" href="/tenants">"My tenants"</a>

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
                                            <p class="font-medium">{w.name.clone()}</p>
                                            <p class="text-sm text-neutral-400">
                                                {format!("id: {id} · tenant: {tid}")}
                                            </p>
                                        </div>
                                        <div class="flex gap-2">
                                            <a
                                                class="btn text-sm"
                                                href=format!("/workspaces/{id}")
                                            >
                                                "Open"
                                            </a>
                                            <a
                                                class="btn text-sm"
                                                href=format!("/workspaces/{id}/invitations")
                                            >
                                                "Invitations"
                                            </a>
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

/// `/workspaces/:workspace_id` — single workspace page: documents + link to
/// invitations.
#[component]
pub fn WorkspacePage() -> impl IntoView {
    let params = use_params::<WorkspaceParams>();
    let workspace_id = move || params.with(|r| r.as_ref().ok().map(|p| p.workspace_id));

    let title = RwSignal::new(String::new());
    let documents = RwSignal::new(Vec::<Document>::new());
    let error = RwSignal::new(None::<String>);
    let refresh = RwSignal::new(0u32);

    Effect::new(move |_| {
        let _ = refresh.get();
        let id = workspace_id();
        spawn_local(async move {
            let Some(id) = id else {
                return;
            };
            match list_documents(id).await {
                Ok(docs) => {
                    documents.set(docs);
                    error.set(None);
                }
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    });

    let submit = move |_| {
        let id = workspace_id();
        spawn_local(async move {
            let Some(id) = id else {
                return;
            };
            match create_document(id, title.get()).await {
                Ok(_) => {
                    title.set(String::new());
                    error.set(None);
                    refresh.update(|n| *n += 1);
                }
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    };

    view! {
        <main class="mx-auto max-w-2xl p-8">
            <a class="text-sm text-neutral-400" href="/workspaces">"← All workspaces"</a>

            <h1 class="mt-2 text-2xl font-bold">"Workspace"</h1>
            <p class="mt-2 text-sm text-neutral-400">
                {move || workspace_id()
                    .map(|id| format!("id: {id}"))
                    .unwrap_or_else(|| "invalid workspace id".into())}
            </p>

            <div class="mt-4 flex gap-2">
                {move || workspace_id().map(|id| view! {
                    <a
                        class="btn text-sm"
                        href=format!("/workspaces/{id}/invitations")
                    >
                        "Invitations"
                    </a>
                })}
            </div>

            <div class="card mt-6">
                <h2 class="text-lg font-semibold">"Create document"</h2>
                <input class="input mt-2" placeholder="Document title" bind:value=title />
                <button class="btn mt-3" on:click=submit>"Create document"</button>
                {move || error.get().map(|e| view! { <p class="mt-4 text-red-400">{e}</p> })}
            </div>

            <div class="mt-8">
                <h2 class="text-xl font-semibold">"Documents"</h2>
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
                                .map(|d| view! {
                                    <li class="py-3">
                                        <p class="font-medium">{d.title}</p>
                                        <p class="text-sm text-neutral-400">{d.body}</p>
                                    </li>
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