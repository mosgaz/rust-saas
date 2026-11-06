use leptos::*;
use serde_json::Value;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct PolicyTest {
    pub subject: String,
    pub permission: String,
    pub resource: String,
    pub context: Option<Value>,
    pub expected: bool,
    pub description: String,
}

#[derive(Serialize, Deserialize)]
pub struct PolicyTestResult {
    pub test: PolicyTest,
    pub actual: bool,
    pub passed: bool,
    pub error: Option<String>,
    pub execution_time_ms: u128,
}

#[component]
pub fn PolicyTesting(cx: Scope) -> impl IntoView {
    let (tests, set_tests) = create_signal(cx, Vec::<PolicyTest>::new());
    let (is_loading, set_is_loading) = create_signal(cx, false);
    let (results, set_results) = create_signal(cx, Vec::<PolicyTestResult>::new());
    let (active_tab, set_active_tab) = create_signal(cx, "create");
    
    // Form fields for creating a new test
    let (new_subject, set_new_subject) = create_signal(cx, "");
    let (new_permission, set_new_permission) = create_signal(cx, "");
    let (new_resource, set_new_resource) = create_signal(cx, "");
    let (new_context, set_new_context) = create_signal(cx, "");
    let (new_expected, set_new_expected) = create_signal(cx, true);
    let (new_description, set_new_description) = create_signal(cx, "");
    
    // Action to run a single test
    let run_test_action = create_action(cx, |test: &PolicyTest| {
        let t = test.clone();
        async move {
            let start = std::time::Instant::now();
            let result = has_permission(
                t.subject.clone(),
                t.permission.clone(),
                t.resource.clone(),
                t.context.clone(),
            ).await;
            let duration = start.elapsed();
            
            match result {
                Ok(actual) => {
                    Ok(PolicyTestResult {
                        test: t,
                        actual,
                        passed: actual == t.expected,
                        error: None,
                        execution_time_ms: duration.as_millis(),
                    })
                }
                Err(e) => {
                    Err(PolicyTestResult {
                        test: t,
                        actual: false,
                        passed: false,
                        error: Some(e.to_string()),
                        execution_time_ms: duration.as_millis(),
                    })
                }
            }
        }
    });
    
    // Action to run all tests
    let run_all_action = create_action(cx, |tests: &Vec<PolicyTest>| {
        let tests_clone = tests.clone();
        async move {
            let mut results = Vec::new();
            
            for test in tests_clone {
                let start = std::time::Instant::now();
                let result = has_permission(
                    test.subject.clone(),
                    test.permission.clone(),
                    test.resource.clone(),
                    test.context.clone(),
                ).await;
                let duration = start.elapsed();
                
                match result {
                    Ok(actual) => {
                        results.push(PolicyTestResult {
                            test: test.clone(),
                            actual,
                            passed: actual == test.expected,
                            error: None,
                            execution_time_ms: duration.as_millis(),
                        });
                    }
                    Err(e) => {
                        results.push(PolicyTestResult {
                            test: test.clone(),
                            actual: false,
                            passed: false,
                            error: Some(e.to_string()),
                            execution_time_ms: duration.as_millis(),
                        });
                    }
                }
            }
            
            Ok(results)
        }
    });
    
    // Action to save tests
    let save_tests_action = create_action(cx, |tests: &Vec<PolicyTest>| {
        let tests_clone = tests.clone();
        async move {
            save_policy_tests(tests_clone).await
        }
    });
    
    // Action to load tests
    let load_tests_action = create_action(cx, |_| {
        async move {
            load_policy_tests().await
        }
    });
    
    // Handle creating a new test
    let on_create_test = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        
        let ctx = if new_context.get().is_empty() {
            None
        } else {
            match serde_json::from_str(&new_context.get()) {
                Ok(v) => Some(v),
                Err(e) => {
                    set_results(vec![PolicyTestResult {
                        test: PolicyTest {
                            subject: "".to_string(),
                            permission: "".to_string(),
                            resource: "".to_string(),
                            context: None,
                            expected: true,
                            description: "".to_string(),
                        },
                        actual: false,
                        passed: false,
                        error: Some(format!("Invalid JSON context: {}", e)),
                        execution_time_ms: 0,
                    }]);
                    return;
                }
            }
        };
        
        let new_test = PolicyTest {
            subject: new_subject.get(),
            permission: new_permission.get(),
            resource: new_resource.get(),
            context: ctx,
            expected: new_expected.get(),
            description: new_description.get(),
        };
        
        set_tests.update(|t| t.push(new_test));
        
        // Reset form
        set_new_subject("");
        set_new_permission("");
        set_new_resource("");
        set_new_context("");
        set_new_description("");
    };
    
    // Handle running a single test
    let on_run_test = move |test: PolicyTest| {
        run_test_action.dispatch(test);
    };
    
    // Handle running all tests
    let on_run_all = move |_| {
        run_all_action.dispatch(tests.get());
    };
    
    // Handle saving tests
    let on_save_tests = move |_| {
        save_tests_action.dispatch(tests.get());
    };
    
    // Handle loading tests
    let on_load_tests = move |_| {
        load_tests_action.dispatch(());
    };
    
    // Subscribe to run test results
    create_effect(cx, move |_| {
        if let Some(result) = run_test_action.value().get() {
            match result {
                Ok(r) => {
                    set_results(vec![r.clone()]);
                }
                Err(r) => {
                    set_results(vec![r.clone()]);
                }
            }
        }
    });
    
    // Subscribe to run all results
    create_effect(cx, move |_| {
        if let Some(result) = run_all_action.value().get() {
            match result {
                Ok(rs) => {
                    set_results(rs.clone());
                }
                Err(_) => {}
            }
        }
    });
    
    // Subscribe to save results
    create_effect(cx, move |_| {
        if let Some(result) = save_tests_action.value().get() {
            match result {
                Ok(_) => {
                    set_results(vec![PolicyTestResult {
                        test: PolicyTest {
                            subject: "".to_string(),
                            permission: "".to_string(),
                            resource: "".to_string(),
                            context: None,
                            expected: true,
                            description: "".to_string(),
                        },
                        actual: true,
                        passed: true,
                        error: Some("Tests saved successfully".to_string()),
                        execution_time_ms: 0,
                    }]);
                }
                Err(e) => {
                    set_results(vec![PolicyTestResult {
                        test: PolicyTest {
                            subject: "".to_string(),
                            permission: "".to_string(),
                            resource: "".to_string(),
                            context: None,
                            expected: true,
                            description: "".to_string(),
                        },
                        actual: false,
                        passed: false,
                        error: Some(format!("Error saving tests: {}", e)),
                        execution_time_ms: 0,
                    }]);
                }
            }
        }
    });
    
    // Subscribe to load results
    create_effect(cx, move |_| {
        if let Some(result) = load_tests_action.value().get() {
            match result {
                Ok(loaded_tests) => {
                    set_tests(loaded_tests);
                    set_results(vec![PolicyTestResult {
                        test: PolicyTest {
                            subject: "".to_string(),
                            permission: "".to_string(),
                            resource: "".to_string(),
                            context: None,
                            expected: true,
                            description: "".to_string(),
                        },
                        actual: true,
                        passed: true,
                        error: Some("Tests loaded successfully".to_string()),
                        execution_time_ms: 0,
                    }]);
                }
                Err(e) => {
                    set_results(vec![PolicyTestResult {
                        test: PolicyTest {
                            subject: "".to_string(),
                            permission: "".to_string(),
                            resource: "".to_string(),
                            context: None,
                            expected: true,
                            description: "".to_string(),
                        },
                        actual: false,
                        passed: false,
                        error: Some(format!("Error loading tests: {}", e)),
                        execution_time_ms: 0,
                    }]);
                }
            }
        }
    });
    
    // Calculate summary statistics
    let passed_count = move || {
        results.get().iter().filter(|r| r.passed).count()
    };
    
    let total_count = move || results.get().len();
    
    let pass_rate = move || {
        let total = total_count();
        if total == 0 {
            0.0
        } else {
            (passed_count() as f64 / total as f64) * 100.0
        }
    };
    
    view! { cx,
        <div class="policy-testing">
            <h2>"Policy Testing & Debugging"</h2>
            
            <div class="tabs">
                <button 
                    class={move || if active_tab.get() == "create" { "tab active" } else { "tab" }}
                    on:click=move |_| set_active_tab("create")
                >
                    "Create Test"
                </button>
                <button 
                    class={move || if active_tab.get() == "run" { "tab active" } else { "tab" }}
                    on:click=move |_| set_active_tab("run")
                >
                    "Run Tests"
                </button>
                <button 
                    class={move || if active_tab.get() == "debug" { "tab active" } else { "tab" }}
                    on:click=move |_| set_active_tab("debug")
                >
                    "Debug"
                </button>
            </div>
            
            <div class="tab-content">
                {move || match active_tab.get().as_str() {
                    "create" => view! { cx, 
                        <div class="create-tab">
                            <h3>"Create New Test Case"</h3>
                            <form on:submit=on_create_test>
                                <div class="form-row">
                                    <div class="form-group">
                                        <label>"Subject:"</label>
                                        <input 
                                            type="text" 
                                            prop:value={new_subject}
                                            on:input=move |ev| set_new_subject(event_target_value(&ev))
                                            placeholder="User ID, role, etc."
                                            required=true
                                        />
                                    </div>
                                    
                                    <div class="form-group">
                                        <label>"Permission:"</label>
                                        <input 
                                            type="text" 
                                            prop:value={new_permission}
                                            on:input=move |ev| set_new_permission(event_target_value(&ev))
                                            placeholder="read, write, delete, etc."
                                            required=true
                                        />
                                    </div>
                                    
                                    <div class="form-group">
                                        <label>"Resource:"</label>
                                        <input 
                                            type="text" 
                                            prop:value={new_resource}
                                            on:input=move |ev| set_new_resource(event_target_value(&ev))
                                            placeholder="document:123, workspace:456, etc."
                                            required=true
                                        />
                                    </div>
                                </div>
                                
                                <div class="form-group">
                                    <label>"Context (JSON, optional):"</label>
                                    <textarea 
                                        prop:value={new_context}
                                        on:input=move |ev| set_new_context(event_target_value(&ev))
                                        placeholder="{\"department\": \"engineering\", \"region\": \"us-west\"}"
                                        rows="3"
                                    ></textarea>
                                </div>
                                
                                <div class="form-group">
                                    <label>"Expected Result:"</label>
                                    <div class="radio-group">
                                        <label>
                                            <input 
                                                type="radio" 
                                                prop:checked={move || new_expected.get()}
                                                on:change=move |_| set_new_expected(true)
                                            />
                                            "Allow (true)"
                                        </label>
                                        <label>
                                            <input 
                                                type="radio" 
                                                prop:checked={move || !new_expected.get()}
                                                on:change=move |_| set_new_expected(false)
                                            />
                                            "Deny (false)"
                                        </label>
                                    </div>
                                </div>
                                
                                <div class="form-group">
                                    <label>"Description:"</label>
                                    <input 
                                        type="text" 
                                        prop:value={new_description}
                                        on:input=move |ev| set_new_description(event_target_value(&ev))
                                        placeholder="Brief description of what this test verifies"
                                    />
                                </div>
                                
                                <div class="form-group">
                                    <button type="submit">"Add Test Case"</button>
                                </div>
                            </form>
                            
                            <div class="test-cases">
                                <h4>"Test Cases ({})" {total_count}</h4>
                                {move || {
                                    let t = tests.get();
                                    if t.is_empty() {
                                        view! { cx, 
                                            <div class="empty-state">
                                                "No test cases defined yet. Create your first test above."
                                            </div>
                                        }.into_view(cx)
                                    } else {
                                        view! { cx, 
                                            <ul class="test-list">
                                                {t.into_iter().map(|test| {
                                                    view! { cx, 
                                                        <li class="test-item">
                                                            <div class="test-header">
                                                                <strong>{&test.description}</strong>
                                                                <span class="test-id">{format!("{} → {} → {}", test.subject, test.permission, test.resource)}</span>
                                                            </div>
                                                            <div class="test-details">
                                                                "Expected: " <code>{if test.expected { "Allow" } else { "Deny" }}</code>
                                                                {match &test.context {
                                                                    Some(ctx) => {
                                                                        view! { cx, 
                                                                            " | Context: " <code>{match serde_json::to_string(ctx) {
                                                                                Ok(s) => s,
                                                                                Err(_) => "Invalid JSON".to_string(),
                                                                            }}</code>
                                                                        }.into_view(cx)
                                                                    }
                                                                    None => view! { cx, <></> }.into_view(cx),
                                                                }}
                                                            </div>
                                                        </li>
                                                    }
                                                }).collect_view(cx)}
                                            </ul>
                                        }.into_view(cx)
                                    }
                                }}
                            </div>
                        </div>
                    }.into_view(cx),
                    
                    "run" => view! { cx, 
                        <div class="run-tab">
                            <div class="action-buttons">
                                <button on:click=on_run_all disabled=is_loading>
                                    {move || if is_loading.get() { "Running..." } else { "Run All Tests" }}
                                </button>
                                <button on:click=on_save_tests disabled=is_loading>
                                    "Save Tests"
                                </button>
                                <button on:click=on_load_tests disabled=is_loading>
                                    "Load Tests"
                                </button>
                            </div>
                            
                            {move || {
                                if is_loading.get() {
                                    view! { cx, 
                                        <div class="loading">
                                            "Executing policy tests..."
                                        </div>
                                    }.into_view(cx)
                                } else {
                                    let r = results.get();
                                    if r.is_empty() {
                                        view! { cx, 
                                            <div class="empty-state">
                                                "Run tests to see results."
                                            </div>
                                        }.into_view(cx)
                                    } else {
                                        view! { cx, 
                                            <div class="results-summary">
                                                <div class="summary-item">
                                                    <strong>{passed_count}</strong> " / " <strong>{total_count}</strong> " tests passed"
                                                </div>
                                                <div class="summary-item">
                                                    "Pass rate: " <strong>{format!("{:.1}%,", pass_rate())}</strong>
                                                </div>
                                            </div>
                                            
                                            <div class="results-list">
                                                {r.into_iter().map(|result| {
                                                    let status_class = if result.passed {
                                                        "result-item passed"
                                                    } else {
                                                        "result-item failed"
                                                    };
                                                    
                                                    view! { cx, 
                                                        <div class={status_class}>
                                                            <div class="result-header">
                                                                <span class="result-status">{if result.passed { "✓" } else { "✗" }}</span>
                                                                <strong>{&result.test.description}</strong>
                                                                <span class="execution-time">{format!("({}ms)", result.execution_time_ms)}</span>
                                                            </div>
                                                            <div class="result-details">
                                                                <div>"Test: " <code>{format!("{} → {} → {}", result.test.subject, result.test.permission, result.test.resource)}</code></div>
                                                                <div>"Expected: " <code>{if result.test.expected { "Allow" } else { "Deny" }}</code> " | " "Actual: " <code>{if result.actual { "Allow" } else { "Deny" }}</code></div>
                                                                {if let Some(err) = &result.error {
                                                                    view! { cx, 
                                                                        <div class="error">"Error: " {err}</div>
                                                                    }.into_view(cx)
                                                                } else {
                                                                    view! { cx, <></> }.into_view(cx)
                                                                }}
                                                            </div>
                                                        </div>
                                                    }
                                                }).collect_view(cx)}
                                            </div>
                                        }.into_view(cx)
                                    }
                                }
                            }}
                        </div>
                    }.into_view(cx),
                    
                    "debug" => view! { cx, 
                        <div class="debug-tab">
                            <h3>"Policy Debugger"</h3>
                            <p>"Use this tool to debug policy decisions by testing individual access requests."
                            </p>
                            
                            <form on:submit=move |ev| {
                                ev.prevent_default();
                                let subject = new_subject.get();
                                let permission = new_permission.get();
                                let resource = new_resource.get();
                                
                                let ctx = if new_context.get().is_empty() {
                                    None
                                } else {
                                    match serde_json::from_str(&new_context.get()) {
                                        Ok(v) => Some(v),
                                        Err(e) => {
                                            set_results(vec![PolicyTestResult {
                                                test: PolicyTest {
                                                    subject: "".to_string(),
                                                    permission: "".to_string(),
                                                    resource: "".to_string(),
                                                    context: None,
                                                    expected: true,
                                                    description: "".to_string(),
                                                },
                                                actual: false,
                                                passed: false,
                                                error: Some(format!("Invalid JSON context: {}", e)),
                                                execution_time_ms: 0,
                                            }]);
                                            return;
                                        }
                                    }
                                };
                                
                                on_run_test(PolicyTest {
                                    subject,
                                    permission,
                                    resource,
                                    context: ctx,
                                    expected: true, // Not used in debugging
                                    description: "Debug request".to_string(),
                                });
                            }}>
                                <div class="form-row">
                                    <div class="form-group">
                                        <label>"Subject:"</label>
                                        <input 
                                            type="text" 
                                            prop:value={new_subject}
                                            on:input=move |ev| set_new_subject(event_target_value(&ev))
                                            placeholder="User ID, role, etc."
                                            required=true
                                        />
                                    </div>
                                    
                                    <div class="form-group">
                                        <label>"Permission:"</label>
                                        <input 
                                            type="text" 
                                            prop:value={new_permission}
                                            on:input=move |ev| set_new_permission(event_target_value(&ev))
                                            placeholder="read, write, delete, etc."
                                            required=true
                                        />
                                    </div>
                                    
                                    <div class="form-group">
                                        <label>"Resource:"</label>
                                        <input 
                                            type="text" 
                                            prop:value={new_resource}
                                            on:input=move |ev| set_new_resource(event_target_value(&ev))
                                            placeholder="document:123, workspace:456, etc."
                                            required=true
                                        />
                                    </div>
                                </div>
                                
                                <div class="form-group">
                                    <label>"Context (JSON, optional):"</label>
                                    <textarea 
                                        prop:value={new_context}
                                        on:input=move |ev| set_new_context(event_target_value(&ev))
                                        placeholder="{\"department\": \"engineering\", \"region\": \"us-west\"}"
                                        rows="3"
                                    ></textarea>
                                </div>
                                
                                <div class="form-group">
                                    <button type="submit">"Test Access"</button>
                                </div>
                            </form>
                            
                            {move || {
                                let r = results.get();
                                if r.is_empty() {
                                    view! { cx, <></> }.into_view(cx)
                                } else {
                                    let result = &r[0];
                                    view! { cx, 
                                        <div class={move || if result.passed { "result-box passed" } else { "result-box failed" }}>
                                            <h4>"Access Decision"</h4>
                                            <div>"Subject: " <code>{&result.test.subject}</code></div>
                                            <div>"Permission: " <code>{&result.test.permission}</code></div>
                                            <div>"Resource: " <code>{&result.test.resource}</code></div>
                                            {if let Some(ctx) = &result.test.context {
                                                view! { cx, 
                                                    <div>"Context: " <code>{match serde_json::to_string_pretty(ctx) {
                                                        Ok(s) => s,
                                                        Err(_) => "Invalid JSON".to_string(),
                                                    }}</code></div>
                                                }.into_view(cx)
                                            } else {
                                                view! { cx, <></> }.into_view(cx)
                                            }}
                                            <div class="decision">
                                                "Decision: " <strong>{if result.actual { "ALLOW" } else { "DENY" }}</strong>
                                            </div>
                                            <div class="execution-time">
                                                "Executed in " {result.execution_time_ms} "ms"
                                            </div>
                                            {if let Some(err) = &result.error {
                                                view! { cx, 
                                                    <div class="error">"Error: " {err}</div>
                                                }.into_view(cx)
                                            } else {
                                                view! { cx, <></> }.into_view(cx)
                                            }}
                                        </div>
                                    }.into_view(cx)
                                }
                            }}
                        </div>
                    }.into_view(cx),
                    
                    _ => view! { cx, <></> }.into_view(cx)
                }}
            </div>
        </div>
    }
}

// Import the server functions
#[server]
extern "C" {
    async fn has_permission(
        subject: String,
        permission: String,
        resource: String,
        context: Option<Value>,
    ) -> Result<bool, ServerFnError>;
    
    async fn save_policy_tests(tests: Vec<PolicyTest>) -> Result<bool, ServerFnError>;
    
    async fn load_policy_tests() -> Result<Vec<PolicyTest>, ServerFnError>;
}
