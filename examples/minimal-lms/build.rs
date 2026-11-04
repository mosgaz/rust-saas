// Re-run when migrations change: `sqlx::migrate!` embeds the set at compile time.
fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
