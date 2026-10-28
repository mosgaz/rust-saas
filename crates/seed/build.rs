// Instructs Cargo to re-run the build script (and thus re-compile `db`)
// whenever a migration file changes. Without this, `sqlx::migrate!`
// captures the migration set at compile time, and stale caches lead to
// "migration previously applied but is missing" errors when switching
// between workspace targets (e.g. `seed`) and example targets
// (`examples/saas-leptos`).
fn main() {
    println!("cargo:rerun-if-changed=migrations");
}