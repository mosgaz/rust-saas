#[cfg(feature = "ssr")]
use std::sync::Arc;

#[cfg(feature = "ssr")]
use authn::Authn;
#[cfg(feature = "ssr")]
use leptos::prelude::LeptosOptions;
#[cfg(feature = "ssr")]
use saas::SaasState;

#[cfg(feature = "ssr")]
#[derive(Clone)]
pub struct AppState {
    pub authn: Arc<Authn>,
    pub saas: Arc<SaasState>,
    pub leptos_options: LeptosOptions,
}

#[cfg(feature = "ssr")]
impl axum::extract::FromRef<AppState> for LeptosOptions {
    fn from_ref(state: &AppState) -> Self {
        state.leptos_options.clone()
    }
}