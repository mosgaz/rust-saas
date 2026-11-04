//! HTTP endpoints for `saas-axum` (Stage 5.0-A4.4).
//!
//! Standard consumer-facing endpoints that ship with the adapter. See
//! `crate::router::build_app_full` (added in step 7) for mounting; the
//! public/protected split mirrors `build_app_with_protected`.
//!
//! - `POST /auth/register` — public; rate-limited 3/h per email.
//! - `POST /auth/login`    — public.
//! - `POST /auth/logout`   — public; revokes the refresh-token family,
//!   clears both auth cookies.
//! - `POST /auth/refresh`  — protected; returns the current `AuthUser`
//!   after `auto_refresh` rotated the tokens if needed.
//! - `GET /my_permissions?domain=…`          — protected; flat
//!   `Vec<String>` (`["document:read", …]`), sorted by
//!   `(resource, action)`.
//! - `GET /my_permissions/grouped?domain=…`  — protected; same data as
//!   `HashMap<String, Vec<String>>` with sorted keys + sorted values.
//! - `GET /resource_types`  — protected; the rows of the
//!   `resource_types` registry.
//!
//! **Divergence note (A4.4 → A8 §5.6).** `saas-leptos` returns
//! `my_permissions` as `Vec<(String, String)>`; `saas-axum` (this module)
//! uses flat `Vec<String>`. Unification is tracked as Phase D §D9.
//!
//! **Where mounted.** `build_app_full(state)` mounts:
//! - public:   `auth::{register, login, logout}`;
//! - protected (with `csrf_guard` → `auto_refresh` → `auth_layer`):
//!   `auth::refresh`, `my_permissions::{flat, grouped}`,
//!   `resource_types`.

pub mod auth;
pub mod my_permissions;
pub mod resource_types;

pub use auth::{login, logout, refresh, register};
pub use my_permissions::{my_permissions_flat, my_permissions_grouped};
pub use resource_types::resource_types;
