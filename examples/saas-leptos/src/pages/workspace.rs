use domain::Document;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::use_params;
use leptos_router::params::Params;
use uuid::Uuid;

#[derive(Params, PartialEq)]
struct WorkspaceParams {
    workspace_id: Uuid,
}

#[server]
pub async fn create_document(workspace_id: Uuid, title: String) -> Result<Document, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();

    let user = crate::extract::CurrentUser::from_request().await?.require()?;

    let document = saas::workspace::create_document(&state.saas, &user, workspace_id, title)
        .await
        .map_err(crate::error::core_error_to_server_fn)?;

    Ok(document)
}

#[server]
pub async fn list_documents(workspace_id: Uuid) -> Result<Vec<Document>, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();

    let user = crate::extract::CurrentUser::from_request().await?.require()?;

    let documents = saas::workspace::list_documents(&state.saas, &user, workspace_id)
        .await
        .map_err(crate::error::core_error_to_server_fn)?;

    Ok(documents)
}

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
            <h1 class="text-2xl font-bold">"Workspace"</h1>
            <p class="mt-2 text-sm text-neutral-400">
                {move || workspace_id()
                    .map(|id| format!("id: {id}"))
                    .unwrap_or_else(|| "invalid workspace id".into())}
            </p>

            <div class="card mt-6">
                <input class="input" placeholder="Document title" bind:value=title />
                <button class="btn mt-4" on:click=submit>"Create document"</button>
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
                            }.into_any()
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