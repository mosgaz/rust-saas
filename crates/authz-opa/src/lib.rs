//
// authz-opa/src/lib.rs
//
// OPA-based PolicyAdmin implementation
//

#![warn(missing_docs)]

use authz::{AuthzError, PolicyAdmin, AuthzRequest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

/// OPA-based policy admin
#[derive(Clone, Debug)]
pub struct OpaPolicyAdmin {
    client: reqwest::Client,
    base_url: Url,
}

/// Error type for OpaPolicyAdmin
#[derive(Debug, Error)]
pub enum OpaError {
    /// Request failed
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    /// OPA returned an error
    #[error("opa error: {code} {message}")]
    Opa { code: u16, message: String },
    /// Invalid response
    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

impl From<OpaError> for AuthzError {
    fn from(err: OpaError) -> Self {
        AuthzError::PolicyAdminError(err.to_string())
    }
}

impl OpaPolicyAdmin {
    /// Create a new OPA policy admin
    pub fn new(base_url: Url) -> Result<Self, url::ParseError> {
        Ok(Self {
            client: reqwest::Client::new(),
            base_url,
        })
    }

    /// Build the URL for a policy query
    fn policy_url(&self, path: &str) -> Url {
        self.base_url.join(path).unwrap()
    }
}

/// Request to OPA
#[derive(Serialize)]
struct OpaRequest {
    input: AuthzRequest,
}

/// Response from OPA
#[derive(Deserialize)]
struct OpaResponse {
    result: Option<bool>,
    #[serde(default)]
    error: Value,
}

#[async_trait::async_trait]
impl PolicyAdmin for OpaPolicyAdmin {
    async fn grant(
        &self,
        _subject: &str,
        _resource: &str,
        _action: &str,
        _context: Option<&Value>,
    ) -> Result<(), AuthzError> {
        // OPA does not support dynamic policy updates in this reference implementation
        // Policies are managed externally
        Err(AuthzError::PolicyAdminError(
            "dynamic grants not supported by OPA reference implementation".to_string(),
        ))
    }

    async fn revoke(
        &self,
        _subject: &str,
        _resource: &str,
        _action: &str,
    ) -> Result<(), AuthzError> {
        Err(AuthzError::PolicyAdminError(
            "dynamic revokes not supported by OPA reference implementation".to_string(),
        ))
    }

    async fn has(
        &self,
        subject: &str,
        resource: &str,
        action: &str,
        context: Option<&Value>,
    ) -> Result<bool, AuthzError> {
        let request = AuthzRequest {
            subject: subject.to_string(),
            resource: resource.to_string(),
            action: action.to_string(),
            context: context.cloned(),
        };

        let opa_request = OpaRequest { input: request };

        let response = self
            .client
            .post(self.policy_url("/v1/data/authz/allow"))
            .json(&opa_request)
            .send()
            .await
            .map_err(OpaError::from)?;

        let status = response.status();
        let text = response.text().await.map_err(OpaError::from)?;

        if !status.is_success() {
            return Err(OpaError::Opa {
                code: status.as_u16(),
                message: text,
            }
            .into());
        }

        let opa_response: OpaResponse =
            serde_json::from_str(&text).map_err(|e| OpaError::InvalidResponse(e.to_string()))?;

        Ok(opa_response.result.unwrap_or(false))
    }

    async fn count(
        &self,
        _subject: &str,
        _action: &str,
    ) -> Result<usize, AuthzError> {
        Err(AuthzError::PolicyAdminError(
            "count not supported by OPA reference implementation".to_string(),
        ))
    }

    async fn purge(&self, _subject: &str) -> Result<(), AuthzError> {
        Err(AuthzError::PolicyAdminError(
            "purge not supported by OPA reference implementation".to_string(),
        ))
    }
}
