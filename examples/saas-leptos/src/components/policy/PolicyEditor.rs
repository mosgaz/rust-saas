use leptos::*;
use serde_json::Value;

#[component]
pub fn PolicyEditor(cx: Scope) -> impl IntoView {
    let (subject, set_subject) = create_signal(cx, "");
    let (permission, set_permission) = create_signal(cx, "");
    let (resource, set_resource) = create_signal(cx, "");
    let (context, set_context) = create_signal(cx, "");
    let (result, set_result) = create_signal(cx, "");
    let (is_granting, set_is_granting) = create_signal(cx, false);
    let (is_revoking, set_is_revoking) = create_signal(cx, false);
    
    let grant_action = create_action(cx, |input: &(String, String, String, Option<Value>)| {
        let (sub, perm, res, ctx) = input.clone();
        async move {
            set_is_granting(true);
            let result = grant_permission(sub, perm, res, ctx).await;
            set_is_granting(false);
            result
        }
    });
    
    let revoke_action = create_action(cx, |input: &(String, String, String, Option<Value>)| {
        let (sub, perm, res, ctx) = input.clone();
        async move {
            set_is_revoking(true);
            let result = revoke_permission(sub, perm, res, ctx).await;
            set_is_revoking(false);
            result
        }
    });
    
    let on_grant = move |_| {
        let ctx = if context.get().is_empty() {
            None
        } else {
            match serde_json::from_str(&context.get()) {
                Ok(v) => Some(v),
                Err(e) => {
                    set_result(format!("Invalid JSON context: {}", e));
                    return;
                }
            }
        };
        
        grant_action.dispatch((subject.get(), permission.get(), resource.get(), ctx));
    };
    
    let on_revoke = move |_| {
        let ctx = if context.get().is_empty() {
            None
        } else {
            match serde_json::from_str(&context.get()) {
                Ok(v) => Some(v),
                Err(e) => {
                    set_result(format!("Invalid JSON context: {}", e));
                    return;
                }
            }
        };
        
        revoke_action.dispatch((subject.get(), permission.get(), resource.get(), ctx));
    };
    
    // Subscribe to action results
    create_effect(cx, move |_| {
        if let Some(result) = grant_action.value().get() {
            match result {
                Ok(success) => {
                    if *success {
                        set_result("Permission granted successfully".to_string());
                    } else {
                        set_result("Failed to grant permission".to_string());
                    }
                }
                Err(e) => {
                    set_result(format!("Error granting permission: {}", e));
                }
            }
        }
    });
    
    create_effect(cx, move |_| {
        if let Some(result) = revoke_action.value().get() {
            match result {
                Ok(success) => {
                    if *success {
                        set_result("Permission revoked successfully".to_string());
                    } else {
                        set_result("Failed to revoke permission".to_string());
                    }
                }
                Err(e) => {
                    set_result(format!("Error revoking permission: {}", e));
                }
            }
        }
    });
    
    view! { cx,
        <div class="policy-editor">
            <h2>"Policy Editor"</h2>
            
            <div class="form-group">
                <label>"Subject:"</label>
                <input 
                    type="text" 
                    prop:value={subject}
                    on:input=move |ev| set_subject(event_target_value(&ev))
                    placeholder="User ID, role, etc."
                />
            </div>
            
            <div class="form-group">
                <label>"Permission:"</label>
                <input 
                    type="text" 
                    prop:value={permission}
                    on:input=move |ev| set_permission(event_target_value(&ev))
                    placeholder="read, write, delete, etc."
                />
            </div>
            
            <div class="form-group">
                <label>"Resource:"</label>
                <input 
                    type="text" 
                    prop:value={resource}
                    on:input=move |ev| set_resource(event_target_value(&ev))
                    placeholder="document:123, workspace:456, etc."
                />
            </div>
            
            <div class="form-group">
                <label>"Context (JSON, optional):"</label>
                <textarea 
                    prop:value={context}
                    on:input=move |ev| set_context(event_target_value(&ev))
                    placeholder="{\"department\": \"engineering\", \"region\": \"us-west\"}"
                    rows="3"
                ></textarea>
            </div>
            
            <div class="button-group">
                <button 
                    on:click=on_grant
                    disabled=is_granting
                    class="btn btn-primary"
                >
                    {move || if is_granting.get() { "Granting..." } else { "Grant Permission" }}
                </button>
                
                <button 
                    on:click=on_revoke
                    disabled=is_revoking
                    class="btn btn-danger"
                >
                    {move || if is_revoking.get() { "Revoking..." } else { "Revoke Permission" }}
                </button>
            </div>
            
            {move || {
                let result_val = result.get();
                if result_val.is_empty() {
                    view! { cx, <></> }.into_view(cx)
                } else {
                    view! { cx, 
                        <div class="result">
                            {result_val}
                        </div>
                    }.into_view(cx)
                }
            }}
        </div>
    }
}

// Import the server functions
#[server]
extern "C" {
    async fn grant_permission(
        subject: String,
        permission: String,
        resource: String,
        context: Option<Value>,
    ) -> Result<bool, ServerFnError>;
    
    async fn revoke_permission(
        subject: String,
        permission: String,
        resource: String,
        context: Option<Value>,
    ) -> Result<bool, ServerFnError>;
}
