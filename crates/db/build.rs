// Instructs Cargo to re-run the build script (and thus re-compile `db`)
// whenever a migration file changes. Without this, `sqlx::migrate!`
// captures the migration set at compile time, and stale caches lead to
// "migration previously applied but is missing" errors when switching
// between workspace targets (e.g. `seed`) and example targets
// (`examples/saas-leptos`).
//
// `cargo:warning=` is visible in the terminal (yellow) every time this
// script runs, so a freshly added migration is easy to confirm.
fn main() {
    println!("cargo:rerun-if-changed=migrations");

    let dir = std::path::Path::new("migrations");
    let mut count: usize = 0;
    let mut names: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("sql") {
                if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                    names.push(name.to_string());
                }
                count += 1;
            }
        }
    }
    names.sort();
    println!(
        "cargo:warning=db build.rs: {count} migration file(s) in migrations/",
    );
    for name in &names {
        println!("cargo:warning=db build.rs:   - {name}");
    }
}