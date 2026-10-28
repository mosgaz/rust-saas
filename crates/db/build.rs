// Re-run the build script when migrations change: `sqlx::migrate!` embeds the
// migration set at compile time, so without this a stale cache can report
// "migration previously applied but is missing".
fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
