use leptos::*;

// Import the policy management components
mod components {
    pub mod policy {
        pub use crate::components::policy::PolicyEditor;
        pub use crate::components::policy::PermissionAssignment;
        pub use crate::components::policy::RelationshipManagement;
        pub use crate::components::policy::PolicyTesting;
    }
}

#[component]
pub fn PolicyManagementPage(cx: Scope) -> impl IntoView {
    let (active_tab, set_active_tab) = create_signal(cx, "editor");
    
    view! { cx,
        <div class="policy-management-page">
            <h1>"Policy Management"</h1>
            
            <nav class="policy-tabs">
                <button 
                    class={move || if active_tab.get() == "editor" { "tab active" } else { "tab" }}
                    on:click=move |_| set_active_tab("editor")
                >
                    "Policy Editor"
                </button>
                <button 
                    class={move || if active_tab.get() == "assignment" { "tab active" } else { "tab" }}
                    on:click=move |_| set_active_tab("assignment")
                >
                    "Permission Assignment"
                </button>
                <button 
                    class={move || if active_tab.get() == "relationships" { "tab active" } else { "tab" }}
                    on:click=move |_| set_active_tab("relationships")
                >
                    "Relationship Management"
                </button>
                <button 
                    class={move || if active_tab.get() == "testing" { "tab active" } else { "tab" }}
                    on:click=move |_| set_active_tab("testing")
                >
                    "Testing & Debugging"
                </button>
            </nav>
            
            <div class="tab-content">
                {move || match active_tab.get().as_str() {
                    "editor" => view! { cx, 
                        <div class="tab-pane active">
                            <components::policy::PolicyEditor />
                        </div>
                    }.into_view(cx),
                    
                    "assignment" => view! { cx, 
                        <div class="tab-pane active">
                            <components::policy::PermissionAssignment />
                        </div>
                    }.into_view(cx),
                    
                    "relationships" => view! { cx, 
                        <div class="tab-pane active">
                            <components::policy::RelationshipManagement />
                        </div>
                    }.into_view(cx),
                    
                    "testing" => view! { cx, 
                        <div class="tab-pane active">
                            <components::policy::PolicyTesting />
                        </div>
                    }.into_view(cx),
                    
                    _ => view! { cx, <></> }.into_view(cx)
                }}
            </div>
        </div>
    }
}