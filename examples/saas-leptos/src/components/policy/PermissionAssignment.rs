use leptos::*;
use serde_json::Value;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionEntry {
    pub subject: String,
    pub permission: String,
    pub resource: String,
    pub context: Option<Value>,
    pub created_at: String,
}

#[derive(Serialize, Deserialize)]
pub struct PermissionQuery {
    pub subject: Option<String>,
    pub permission: Option<String>,
    pub resource: Option<String>,
}

#[component]
pub fn PermissionAssignment(cx: Scope) -> impl IntoView {
    let (query, set_query) = create_signal(cx, PermissionQuery {
        subject: None,
        permission: None,
        resource: None,
    });
    
    let (permissions, set_permissions) = create_signal(cx, Vec::<PermissionEntry>::new());
    let (is_loading, set_is_loading) = create_signal(cx, false);
    let (error, set_error) = create_signal(cx, None);
    let (count, set_count) = create_signal(cx, 0);
    
    // Action to search permissions
    let search_action = create_action(cx, |query: &PermissionQuery| {
        let q = query.clone();
        async move {
            set_is_loading(true);
            set_error(None);
            
            let result = search_permissions(q).await;
            
            set_is_loading(false);
            
            match result {
                Ok(perms) => {
                    set_permissions(perms.clone());
                    // Update count
                    count_permissions(
                        query.subject.clone(),
                        query.permission.clone(),
                        query.resource.clone(),
                    ).await.map(|c| set_count(c)).ok();
                    Ok(perms)
                }
                Err(e) => {
                    set_error(Some(e.to_string()));
                    Err(e)
                }
            }
        }
    });
    
    // Action to check a specific permission
    let check_action = create_action(cx, |input: &(String, String, String, Option<Value>)| {
        let (sub, perm, res, ctx) = input.clone();
        async move {
            has_permission(sub, perm, res, ctx).await
        }
    });
    
    // Load all permissions on mount
    create_effect(cx, move |_| {
        search_action.dispatch(query.get());
    });
    
    // Handle search form submission
    let on_search = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        search_action.dispatch(query.get());
    };
    
    // Handle permission check
    let on_check = move |subject: String, permission: String, resource: String, context: Option<Value>| {
        check_action.dispatch((subject, permission, resource, context));
    };
    
    // Subscribe to search results
    create_effect(cx, move |_| {
        if let Some(result) = search_action.value().get() {
            match result {
                Ok(perms) => {
                    set_permissions(perms.clone());
                }
                Err(_) => {}
            }
        }
    });
    
    // Subscribe to check results
    create_effect(cx, move |_| {
        if let Some(result) = check_action.value().get() {
            match result {
                Ok(has) => {
                    if *has {
                        set_error(Some("Permission granted".to_string()));
                    } else {
                        set_error(Some("Permission not granted".to_string()));
                    }
                }
                Err(e) => {
                    set_error(Some(format!("Error checking permission: {}", e)));
                }
            }
        }
    });
    
    view! { cx,
        <div class="permission-assignment">
            <h2>"Permission Assignment"</h2>
            
            <div class="search-section">
                <form on:submit=on_search>
                    <div class="form-row">
                        <div class="form-group">
                            <label>"Subject:"</label>
                            <input 
                                type="text" 
                                prop:value={move || query.get().subject.clone().unwrap_or_default()}
                                on:input=move |ev| {
                                    let val = event_target_value(&ev);
                                    set_query.update(|q| q.subject = if val.is_empty() { None } else { Some(val) });
                                }
                                placeholder="Filter by subject"
                            />
                        </div>
                        
                        <div class="form-group">
                            <label>"Permission:"</label>
                            <input 
                                type="text" 
                                prop:value={move || query.get().permission.clone().unwrap_or_default()}
                                on:input=move |ev| {
                                    let val = event_target_value(&ev);
                                    set_query.update(|q| q.permission = if val.is_empty() { None } else { Some(val) });
                                }
                                placeholder="Filter by permission"
                            />
                        </div>
                        
                        <div class="form-group">
                            <label>"Resource:"</label>
                            <input 
                                type="text" 
                                prop:value={move || query.get().resource.clone().unwrap_or_default()}
                                on:input=move |ev| {
                                    let val = event_target_value(&ev);
                                    set_query.update(|q| q.resource = if val.is_empty() { None } else { Some(val) });
                                }
                                placeholder="Filter by resource"
                            />
                        </div>
                        
                        <div class="form-group">
                            <button type="submit" disabled=is_loading>
                                {move || if is_loading.get() { "Searching..." } else { "Search" }}
                            </button>
                        </div>
                    </div>
                </form>
                
                <div class="count-info">
                    "Found " <strong>{count}</strong> " permission" {move || if count.get() != 1 { "s" } else { "" }} " matching the criteria"
                </div>
            </div>
            
            <div class="results-section">
                {move || {
                    let error_val = error.get();
                    if let Some(err) = error_val {
                        view! { cx, 
                            <div class="alert alert-info">
                                {err}
                            </div>
                        }.into_view(cx)
                    } else {
                        view! { cx, <></> }.into_view(cx)
                    }
                }}
                
                {move || {
                    if is_loading.get() {
                        view! { cx, 
                            <div class="loading">
                                "Loading permissions..."
                            </div>
                        }.into_view(cx)
                    } else {
                        let perms = permissions.get();
                        if perms.is_empty() {
                            view! { cx, 
                                <div class="empty-state">
                                    "No permissions found matching the criteria"
                                </div>
                            }.into_view(cx)
                        } else {
                            view! { cx, 
                                <table class="permissions-table">
                                    <thead>
                                        <tr>
                                            <th>"Subject"</th>
                                            <th>"Permission"</th>
                                            <th>"Resource"</th>
                                            <th>"Context"</th>
                                            <th>"Created"</th>
                                            <th>"Actions"</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {perms.into_iter().map(|entry| {
                                            let entry_clone = entry.clone();
                                            view! { cx, 
                                                <tr>
                                                    <td>{entry.subject}</td>
                                                    <td>{entry.permission}</td>
                                                    <td>{entry.resource}</td>
                                                    <td>
                                                        {match entry.context {
                                                            Some(ctx) => {
                                                                match serde_json::to_string_pretty(&ctx) {
                                                                    Ok(s) => s,
                                                                    Err(_) => "Invalid JSON".to_string(),
                                                                }
                                                            }
                                                            None => "—".to_string(),
                                                        }}
                                                    </td>
                                                    <td>{entry.created_at}</td>
                                                    <td>
                                                        <button 
                                                            class="btn btn-sm btn-info"
                                                            on:click=move |_| {
                                                                on_check(
                                                                    entry_clone.subject.clone(),
                                                                    entry_clone.permission.clone(),
                                                                    entry_clone.resource.clone(),
                                                                    entry_clone.context.clone(),
                                                                );
                                                            }
                                                        >
                                                            "Check"
                                                        </button>
                                                    </td>
                                                </tr>
                                            }
                                        }).collect_view(cx)}
                                    </tbody>
                                </table>
                            }.into_view(cx)
                        }
                    }
                }}
            </div>
        </div>
    }
}

// Import the server functions
#[server]
extern "C" {
    async fn search_permissions(query: PermissionQuery) -> Result<Vec<PermissionEntry>, ServerFnError>;
    
    async fn has_permission(
        subject: String,
        permission: String,
        resource: String,
        context: Option<Value>,
    ) -> Result<bool, ServerFnError>;
    
    async fn count_permissions(
        subject: Option<String>,
        permission: Option<String>,
        resource: Option<String>,
    ) -> Result<usize, ServerFnError>;
}
