use leptos::*;
use serde_json::Value;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Relationship {
    pub from: String,
    pub relation: String,
    pub to: String,
    pub context: Option<Value>,
    pub created_at: String,
}

#[derive(Serialize, Deserialize)]
pub struct RelationshipQuery {
    pub from: Option<String>,
    pub relation: Option<String>,
    pub to: Option<String>,
}

#[component]
pub fn RelationshipManagement(cx: Scope) -> impl IntoView {
    let (query, set_query) = create_signal(cx, RelationshipQuery {
        from: None,
        relation: None,
        to: None,
    });
    
    let (relationships, set_relationships) = create_signal(cx, Vec::<Relationship>::new());
    let (is_loading, set_is_loading) = create_signal(cx, false);
    let (error, set_error) = create_signal(cx, None);
    let (count, set_count) = create_signal(cx, 0);
    let (is_adding, set_is_adding) = create_signal(cx, false);
    
    // Form fields for adding a new relationship
    let (new_from, set_new_from) = create_signal(cx, "");
    let (new_relation, set_new_relation) = create_signal(cx, "");
    let (new_to, set_new_to) = create_signal(cx, "");
    let (new_context, set_new_context) = create_signal(cx, "");
    
    // Action to search relationships
    let search_action = create_action(cx, |query: &RelationshipQuery| {
        let q = query.clone();
        async move {
            set_is_loading(true);
            set_error(None);
            
            let result = search_relationships(q).await;
            
            set_is_loading(false);
            
            match result {
                Ok(rels) => {
                    set_relationships(rels.clone());
                    // Update count
                    count_relationships(
                        query.from.clone(),
                        query.relation.clone(),
                        query.to.clone(),
                    ).await.map(|c| set_count(c)).ok();
                    Ok(rels)
                }
                Err(e) => {
                    set_error(Some(e.to_string()));
                    Err(e)
                }
            }
        }
    });
    
    // Action to add a new relationship
    let add_action = create_action(cx, |input: &(String, String, String, Option<Value>)| {
        let (from, relation, to, ctx) = input.clone();
        async move {
            add_relationship(from, relation, to, ctx).await
        }
    });
    
    // Action to check if a relationship exists
    let check_action = create_action(cx, |input: &(String, String, String)| {
        let (from, relation, to) = input.clone();
        async move {
            has_relationship(from, relation, to).await
        }
    });
    
    // Load all relationships on mount
    create_effect(cx, move |_| {
        search_action.dispatch(query.get());
    });
    
    // Handle search form submission
    let on_search = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        search_action.dispatch(query.get());
    };
    
    // Handle adding a new relationship
    let on_add = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        
        let ctx = if new_context.get().is_empty() {
            None
        } else {
            match serde_json::from_str(&new_context.get()) {
                Ok(v) => Some(v),
                Err(e) => {
                    set_error(Some(format!("Invalid JSON context: {}", e)));
                    return;
                }
            }
        };
        
        set_is_adding(true);
        add_action.dispatch((new_from.get(), new_relation.get(), new_to.get(), ctx));
    };
    
    // Handle relationship check
    let on_check = move |from: String, relation: String, to: String| {
        check_action.dispatch((from, relation, to));
    };
    
    // Subscribe to search results
    create_effect(cx, move |_| {
        if let Some(result) = search_action.value().get() {
            match result {
                Ok(rels) => {
                    set_relationships(rels.clone());
                }
                Err(_) => {}
            }
        }
    });
    
    // Subscribe to add results
    create_effect(cx, move |_| {
        if let Some(result) = add_action.value().get() {
            set_is_adding(false);
            
            match result {
                Ok(success) => {
                    if *success {
                        set_error(Some("Relationship added successfully".to_string()));
                        // Reset form
                        set_new_from("");
                        set_new_relation("");
                        set_new_to("");
                        set_new_context("");
                        // Refresh list
                        search_action.dispatch(query.get());
                    } else {
                        set_error(Some("Failed to add relationship".to_string()));
                    }
                }
                Err(e) => {
                    set_is_adding(false);
                    set_error(Some(format!("Error adding relationship: {}", e)));
                }
            }
        }
    });
    
    // Subscribe to check results
    create_effect(cx, move |_| {
        if let Some(result) = check_action.value().get() {
            match result {
                Ok(has) => {
                    if *has {
                        set_error(Some("Relationship exists".to_string()));
                    } else {
                        set_error(Some("Relationship does not exist".to_string()));
                    }
                }
                Err(e) => {
                    set_error(Some(format!("Error checking relationship: {}", e)));
                }
            }
        }
    });
    
    view! { cx,
        <div class="relationship-management">
            <h2>"Relationship Management"</h2>
            
            <div class="add-relationship-form">
                <h3>"Add New Relationship"</h3>
                <form on:submit=on_add>
                    <div class="form-row">
                        <div class="form-group">
                            <label>"From:"</label>
                            <input 
                                type="text" 
                                prop:value={new_from}
                                on:input=move |ev| set_new_from(event_target_value(&ev))
                                placeholder="Subject (user, group, etc.)"
                                required=true
                            />
                        </div>
                        
                        <div class="form-group">
                            <label>"Relation:"</label>
                            <input 
                                type="text" 
                                prop:value={new_relation}
                                on:input=move |ev| set_new_relation(event_target_value(&ev))
                                placeholder="member, owner, editor, etc."
                                required=true
                            />
                        </div>
                        
                        <div class="form-group">
                            <label>"To:"</label>
                            <input 
                                type="text" 
                                prop:value={new_to}
                                on:input=move |ev| set_new_to(event_target_value(&ev))
                                placeholder="Resource (workspace, document, etc.)"
                                required=true
                            />
                        </div>
                        
                        <div class="form-group">
                            <button type="submit" disabled=is_adding>
                                {move || if is_adding.get() { "Adding..." } else { "Add Relationship" }}
                            </button>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label>"Context (JSON, optional):"</label>
                        <textarea 
                            prop:value={new_context}
                            on:input=move |ev| set_new_context(event_target_value(&ev))
                            placeholder="{\"since\": \"2023-01-01\", \"reason\": \"project_lead\"}"
                            rows="2"
                        ></textarea>
                    </div>
                </form>
            </div>
            
            <div class="search-section">
                <h3>"Find Relationships"</h3>
                <form on:submit=on_search>
                    <div class="form-row">
                        <div class="form-group">
                            <label>"From:"</label>
                            <input 
                                type="text" 
                                prop:value={move || query.get().from.clone().unwrap_or_default()}
                                on:input=move |ev| {
                                    let val = event_target_value(&ev);
                                    set_query.update(|q| q.from = if val.is_empty() { None } else { Some(val) });
                                }
                                placeholder="Filter by subject"
                            />
                        </div>
                        
                        <div class="form-group">
                            <label>"Relation:"</label>
                            <input 
                                type="text" 
                                prop:value={move || query.get().relation.clone().unwrap_or_default()}
                                on:input=move |ev| {
                                    let val = event_target_value(&ev);
                                    set_query.update(|q| q.relation = if val.is_empty() { None } else { Some(val) });
                                }
                                placeholder="Filter by relation"
                            />
                        </div>
                        
                        <div class="form-group">
                            <label>"To:"</label>
                            <input 
                                type="text" 
                                prop:value={move || query.get().to.clone().unwrap_or_default()}
                                on:input=move |ev| {
                                    let val = event_target_value(&ev);
                                    set_query.update(|q| q.to = if val.is_empty() { None } else { Some(val) });
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
                    "Found " <strong>{count}</strong> " relationship" {move || if count.get() != 1 { "s" } else { "" }} " matching the criteria"
                </div>
            </div>
            
            <div class="results-section">
                {move || {
                    let error_val = error.get();
                    if let Some(err) = error_val {
                        view! { cx, 
                            <div class={move || if err.contains("successfully") { "alert alert-success" } else { "alert alert-info" }}>
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
                                "Loading relationships..."
                            </div>
                        }.into_view(cx)
                    } else {
                        let rels = relationships.get();
                        if rels.is_empty() {
                            view! { cx, 
                                <div class="empty-state">
                                    "No relationships found matching the criteria"
                                </div>
                            }.into_view(cx)
                        } else {
                            view! { cx, 
                                <table class="relationships-table">
                                    <thead>
                                        <tr>
                                            <th>"From"</th>
                                            <th>"Relation"</th>
                                            <th>"To"</th>
                                            <th>"Context"</th>
                                            <th>"Created"</th>
                                            <th>"Actions"</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {rels.into_iter().map(|rel| {
                                            let rel_clone = rel.clone();
                                            view! { cx, 
                                                <tr>
                                                    <td>{rel.from}</td>
                                                    <td>{rel.relation}</td>
                                                    <td>{rel.to}</td>
                                                    <td>
                                                        {match rel.context {
                                                            Some(ctx) => {
                                                                match serde_json::to_string_pretty(&ctx) {
                                                                    Ok(s) => s,
                                                                    Err(_) => "Invalid JSON".to_string(),
                                                                }
                                                            }
                                                            None => "—".to_string(),
                                                        }}
                                                    </td>
                                                    <td>{rel.created_at}</td>
                                                    <td>
                                                        <button 
                                                            class="btn btn-sm btn-info"
                                                            on:click=move |_| {
                                                                on_check(
                                                                    rel_clone.from.clone(),
                                                                    rel_clone.relation.clone(),
                                                                    rel_clone.to.clone(),
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
    async fn search_relationships(query: RelationshipQuery) -> Result<Vec<Relationship>, ServerFnError>;
    
    async fn add_relationship(
        from: String,
        relation: String,
        to: String,
        context: Option<Value>,
    ) -> Result<bool, ServerFnError>;
    
    async fn has_relationship(
        from: String,
        relation: String,
        to: String,
    ) -> Result<bool, ServerFnError>;
    
    async fn count_relationships(
        from: Option<String>,
        relation: Option<String>,
        to: Option<String>,
    ) -> Result<usize, ServerFnError>;
}
