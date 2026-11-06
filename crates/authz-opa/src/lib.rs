//! OPA-based PolicyAdmin implementation
//!
//! This crate provides a concrete implementation of the `PolicyAdmin` trait by
//! communicating with an Open Policy Agent (OPA) server via its REST API. It enables
//! dynamic management of authorization policies for Attribute-Based Access Control
//! (ABAC) and Relationship-Based Access Control (ReBAC).
//!
//! The implementation uses policy identifiers in the format
//! `{subject}_{resource}_{action}` and stores simple rules that can include
//! contextual attributes passed via the `context` parameter.

#![warn(missing_docs)]

use authz::{AuthzError, PolicyAdmin, AuthzRequest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use url::Url;

/// OPA-based policy administration client
///
/// This struct implements the `PolicyAdmin` trait by making REST API calls to an OPA
/// server. It is responsible for creating, querying, and deleting policies.
///
/// # Example
///
/// ```
/// use url::Url;
/// use authz_opa::OpaPolicyAdmin;
///
/// let base_url = Url::parse("http://localhost:8181").unwrap();
/// let opa_admin = OpaPolicyAdmin::new(base_url).unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct OpaPolicyAdmin {
    client: reqwest::Client,
    base_url: Url,
}

/// Error type for OpaPolicyAdmin
///
/// This enum represents the different kinds of errors that can occur when
/// interacting with the OPA server.
#[derive(Debug, Error)]
pub enum OpaError {
    /// The HTTP request to the OPA server failed.
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    /// The OPA server responded with an error status code.
    #[error("opa error: {code} {message}")]
    Opa {
        /// HTTP status code of the OPA response
        code: u16,
        /// Error message returned by OPA
        message: String,
    },
    /// The response from the OPA server could not be parsed.
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

/// Request payload for OPA policy evaluation
///
/// This struct is serialized and sent to the OPA server's `/v1/data` endpoint
/// to evaluate a policy decision. The `input` field contains the `AuthzRequest`.
#[derive(Serialize)]
struct OpaRequest {
    input: AuthzRequest,
}

/// Response from OPA policy evaluation
///
/// This struct is deserialized from the OPA server's response. The `result`
/// field contains the policy decision (`true` or `false`). The `error` field is
/// present if the policy evaluation failed.
#[derive(Deserialize)]
struct OpaResponse {
    /// The result of the policy evaluation (`true` or `false`)
    result: Option<bool>,
    /// Error details if the policy evaluation failed
    #[serde(default)]
    error: Value,
}

#[async_trait::async_trait]
impl PolicyAdmin for OpaPolicyAdmin {
    async fn grant(
        &self,
        subject: &str,
        resource: &str,
        action: &str,
        context: Option<&Value>,
    ) -> Result<(), AuthzError> {
        let policy_id = format!("{}_{}_{}", subject, resource, action);
        let mut rule_body = serde_json::json!({
            "allow": true
        });

        if let Some(ctx) = context {
            if let Some(obj) = ctx.as_object() {
                for (key, value) in obj {
                    rule_body[key] = value.clone();
                }
            }
        }

        let policy = serde_json::json!({
            "package": "authz",
            "import": [
                "data.graph"
            ],
            "result": rule_body
        });

        let response = self
            .client
            .put(self.policy_url(&format!("/v1/policies/{}", policy_id)))
            .json(&policy)
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

        Ok(())
    }

    async fn revoke(
        &self,
        subject: &str,
        resource: &str,
        action: &str,
    ) -> Result<(), AuthzError> {
        let policy_id = format!("{}_{}_{}", subject, resource, action);

        let response = self
            .client
            .delete(self.policy_url(&format!("/v1/policies/{}", policy_id)))
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

        Ok(())
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
        subject: &str,
        action: &str,
    ) -> Result<usize, AuthzError> {
        let response = self
            .client
            .get(self.policy_url("/v1/policies"))
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

        let policies: Value = serde_json::from_str(&text).map_err(|e| OpaError::InvalidResponse(e.to_string()))?;

        let count = policies.as_object()
            .map(|obj| {
                obj.keys().filter(|key| {
                    key.starts_with(&format!("{}", subject)) &&
                    key.ends_with(&format!("_{}", action))
                }).count()
            })
            .unwrap_or(0);

        Ok(count)
    }

    async fn purge(&self, subject: &str) -> Result<(), AuthzError> {
        let response = self
            .client
            .get(self.policy_url("/v1/policies"))
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

        let policies: Value = serde_json::from_str(&text).map_err(|e| OpaError::InvalidResponse(e.to_string()))?;

        let policy_ids: Vec<String> = policies
            .as_object()
            .map(|obj| {
                obj.keys()
                    .filter(|key| key.starts_with(&format!("{}", subject)))
                    .map(|key| key.clone())
                    .collect()
            })
            .unwrap_or_default();

        for policy_id in policy_ids {
            let response = self
                .client
                .delete(self.policy_url(&format!("/v1/policies/{}", policy_id)))
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
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::Method::DELETE;
    use httpmock::Method::GET;
    use httpmock::Method::PUT;
    use httpmock::Method::POST;
    use serde_json::json;
    use std::sync::Arc;
    use url::Url;

    /// Helper to create a test OpaPolicyAdmin with a mock server
    async fn setup_test_admin() -> (OpaPolicyAdmin, httpmock::MockServer) {
        let server = httpmock::MockServer::start_async().await;
        let base_url = Url::parse(&server.base_url()).unwrap();
        let admin = OpaPolicyAdmin::new(base_url).unwrap();
        (admin, server)
    }

    #[tokio::test]
    async fn test_grant_success() {
        let (admin, server) = setup_test_admin().await;
        
        // Mock the OPA server response for PUT /v1/policies
        let policy_id = "user1_document_read";
        let mock = server.mock(|when, then| {
            when.method(PUT)
               .path(format!("/v1/policies/{}", policy_id).as_str());
            then.status(200);
        });
        
        // Test the grant method
        let result = admin.grant("user1", "document", "read", None).await;
        
        // Verify the result and the mock
        assert!(result.is_ok());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_grant_with_context() {
        let (admin, server) = setup_test_admin().await;
        
        // Extract the context attributes from the request body
        let policy_id = "user1_document_read";
        let mock = server.mock(|when, then| {
            when.method(PUT)
               .path(format!("/v1/policies/{}", policy_id).as_str());
            then.status(200)
               .expect_body_contains(r#"department": "engineering""#)
               .expect_body_contains(r#"allow": true"#);
        });
        
        // Create context with attributes
        let context = json!({
            "department": "engineering",
            "level": "senior"
        });
        
        // Test the grant method with context
        let result = admin.grant("user1", "document", "read", Some(&context)).await;
        
        // Verify the result and the mock
        assert!(result.is_ok());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_grant_opa_error() {
        let (admin, server) = setup_test_admin().await;
        
        // Mock the OPA server to return an error
        let policy_id = "user1_document_read";
        let mock = server.mock(|when, then| {
            when.method(PUT)
               .path(format!("/v1/policies/{}", policy_id).as_str());
            then.status(500)
               .body("Internal Server Error");
        });
        
        // Test the grant method
        let result = admin.grant("user1", "document", "read", None).await;
        
        // Verify the result is an error and contains the OPA error message
        assert!(result.is_err());
        if let Err(AuthzError::PolicyAdminError(msg)) = result {
            assert!(msg.contains("opa error: 500 Internal Server Error"));
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_revoke_success() {
        let (admin, server) = setup_test_admin().await;
        
        // Mock the OPA server response for DELETE /v1/policies
        let policy_id = "user1_document_read";
        let mock = server.mock(|when, then| {
            when.method(DELETE)
               .path(format!("/v1/policies/{}", policy_id).as_str());
            then.status(200);
        });
        
        // Test the revoke method
        let result = admin.revoke("user1", "document", "read").await;
        
        // Verify the result and the mock
        assert!(result.is_ok());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_revoke_not_found() {
        let (admin, server) = setup_test_admin().await;
        
        // Mock the OPA server to return 404 (which is acceptable for idempotent revoke)
        let policy_id = "user1_document_read";
        let mock = server.mock(|when, then| {
            when.method(DELETE)
               .path(format!("/v1/policies/{}", policy_id).as_str());
            then.status(404);
        });
        
        // Test the revoke method
        let result = admin.revoke("user1", "document", "read").await;
        
        // Verify the result is still Ok (idempotent operation)
        assert!(result.is_ok());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_has_success() {
        let (admin, server) = setup_test_admin().await;
        
        // Mock the OPA server response for POST /v1/data/authz/allow
        let mock = server.mock(|when, then| {
            when.method(POST)
               .path("/v1/data/authz/allow");
            then.status(200)
               .json_body(json!({"result": true}));
        });        
        // Test the has method
        let result = admin.has("user1", "document", "read", None).await;
        
        // Verify the result and the mock
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_has_with_context() {
        let (admin, server) = setup_test_admin().await;
        
        // Extract the context from the request body
        let mock = server.mock(|when, then| {
            when.method(POST)
               .path("/v1/data/authz/allow");
            then.status(200)
               .expect_body_contains(r#"department": "engineering""#)
               .json_body(json!({"result": true}));
        });
        
        // Create context with attributes
        let context = json!({
            "department": "engineering",
            "level": "senior"
        });
        
        // Test the has method with context
        let result = admin.has("user1", "document", "read", Some(&context)).await;
        
        // Verify the result and the mock
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_has_not_found() {
        let (admin, server) = setup_test_admin().await;
        
        // Mock the OPA server to return 404 (no policy found)
        let mock = server.mock(|when, then| {
            when.method(POST)
               .path("/v1/data/authz/allow");
            then.status(404);
        });
        
        // Test the has method
        let result = admin.has("user1", "document", "read", None).await;
        
        // Verify the result is an error
        assert!(result.is_err());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_count_success() {
        let (admin, server) = setup_test_admin().await;
        
        // Mock the OPA server response for GET /v1/policies
        let mock = server.mock(|when, then| {
            when.method(GET)
               .path("/v1/policies");
            then.status(200)
               .json_body(json!({
                   "user1_document_read": {},
                   "user1_document_write": {},
                   "user2_document_read": {},
                   "user1_task_assign": {}
               }));
        });
        
        // Test the count method for user1 with action "read"
        let result = admin.count("user1", "read").await;
        
        // Verify the result and the mock
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1); // Only user1_document_read matches
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_count_no_matches() {
        let (admin, server) = setup_test_admin().await;
        
        // Mock the OPA server response for GET /v1/policies
        let mock = server.mock(|when, then| {
            when.method(GET)
               .path("/v1/policies");
            then.status(200)
               .json_body(json!({
                   "user1_document_read": {},
                   "user2_document_write": {}
               }));
        });
        
        // Test the count method for user3 with action "read" (no matches)
        let result = admin.count("user3", "read").await;
        
        // Verify the result and the mock
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0); // No matches
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_purge_success() {
        let (admin, server) = setup_test_admin().await;
        
        // First mock for GET /v1/policies to list policies
        let get_mock = server.mock(|when, then| {
            when.method(GET)
               .path("/v1/policies");
            then.status(200)
               .json_body(json!({
                   "user1_document_read": {},
                   "user1_document_write": {},
                   "user2_document_read": {}
               }));
        });
        
        // Mocks for DELETE /v1/policies/{id} for each policy to be deleted
        let delete_mock1 = server.mock(|when, then| {
            when.method(DELETE)
               .path("/v1/policies/user1_document_read");
            then.status(200);
        });
        
        let delete_mock2 = server.mock(|when, then| {
            when.method(DELETE)
               .path("/v1/policies/user1_document_write");
            then.status(200);
        });
        
        // Test the purge method
        let result = admin.purge("user1").await;
        
        // Verify the result and all mocks
        assert!(result.is_ok());
        get_mock.assert_async().await;
        delete_mock1.assert_async().await;
        delete_mock2.assert_async().await;
    }

    #[tokio::test]
    async fn test_purge_no_policies() {
        let (admin, server) = setup_test_admin().await;
        
        // Mock the OPA server to return empty policies list
        let get_mock = server.mock(|when, then| {
            when.method(GET)
               .path("/v1/policies");
            then.status(200)
               .json_body(json!({}));
        });
        
        // Test the purge method
        let result = admin.purge("user1").await;
        
        // Verify the result is Ok and no DELETE calls were made
        assert!(result.is_ok());
        get_mock.assert_async().await;
        // No DELETE mocks were created, so we're verifying that only GET was called
    }

    #[tokio::test]
    async fn test_purge_with_error() {
        let (admin, server) = setup_test_admin().await;
        
        // First mock for GET /v1/policies to list policies
        let get_mock = server.mock(|when, then| {
            when.method(GET)
               .path("/v1/policies");
            then.status(200)
               .json_body(json!({
                   "user1_document_read": {},
                   "user1_document_write": {}
               }));
        });
        
        // Mock for DELETE /v1/policies/{id} to return an error on the first delete
        let delete_mock = server.mock(|when, then| {
            when.method(DELETE)
               .path("/v1/policies/user1_document_read");
            then.status(500)
               .body("Internal Server Error");
        });
        
        // Test the purge method
        let result = admin.purge("user1").await;
        
        // Verify the result is an error and contains the OPA error message
        assert!(result.is_err());
        if let Err(AuthzError::PolicyAdminError(msg)) = result {
            assert!(msg.contains("opa error: 500 Internal Server Error"));
        }
        get_mock.assert_async().await;
        delete_mock.assert_async().await;
    }
}
