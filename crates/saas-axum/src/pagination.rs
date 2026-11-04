//! Pagination query parameters (Stage 4.8, ported to `saas-axum`).
//!
//! Same shape as `examples/axum-minimal::pagination::PaginationQuery` and
//! `examples/saas-leptos`'s inline `limit`/`offset` clamp: the wire format
//! is `?limit=&offset=`, both optional, defaults `limit = 50`,
//! `offset = 0`, clamped to `[1, 200]` and `>= 0` respectively.
//!
//! The clamp lives in the HTTP layer, not in the library
//! (`domain::Page<T>` accepts any `i64`; `saas::*`'s `list_*_paged`
//! passes it through to SQL). A `PaginationQuery` with `limit = i64::MAX`
//! is accepted here as `200` — the library caller that wants "all rows"
//! uses `list_*(…, i64::MAX, 0)` directly, not through this query type.

use serde::Deserialize;

/// `?limit=&offset=` query parameters. Both optional; see [`Self::clamp`].
#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl PaginationQuery {
    /// Returns `(limit, offset)`, clamped:
    ///
    /// - `limit` defaults to `50`, clamped to `[1, 200]` (`limit = 0`
    ///   yields `1` — a zero-page request is a UI mistake, not a
    ///   legitimate "give me nothing"; use a 404/400 handler if that
    ///   semantics is needed);
    /// - `offset` defaults to `0`, clamped to `>= 0`.
    pub fn clamp(&self) -> (i64, i64) {
        let limit = self.limit.unwrap_or(50).clamp(1, 200);
        let offset = self.offset.unwrap_or(0).max(0);
        (limit, offset)
    }
}
