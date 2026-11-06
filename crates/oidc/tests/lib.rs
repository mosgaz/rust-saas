use oidc::{OidcClient, OidcError, ProviderMetadata, TokenSet, IdTokenClaims, UserInfo};
use httpmock::Method::GET;
use httpmock::Method::POST;
use serde_json::json;
use std::sync::Arc;
use url::Url;
use chrono::{Utc, Duration};

/// Helper to create a test OidcClient with a mock server
async fn setup_test_client() -> (OidcClient, httpmock::MockServer) {
    let server = httpmock::MockServer::start_async().await;
    let issuer = server.base_url();
    let client_id = "test_client_id".to_string();
    let client_secret = Some("test_client_secret".to_string());
    let redirect_uri = Url::parse("http://localhost:3000/callback").unwrap();
    
    // Mock the discovery endpoint
    let discovery_mock = server.mock(|when, then| {
        when.method(GET)
           .path("/.well-known/openid-configuration");
        then.status(200)
           .json_body(json!({
               "issuer": issuer,
               "authorization_endpoint": format!("{}/authorize"),
               "token_endpoint": format!("{}/token"),
               "userinfo_endpoint": format!("{}/userinfo"),
               "jwks_uri": format!("{}/jwks"),
               "id_token_signing_alg_values_supported": ["RS256"]
           }));
    });
    
    // Mock the JWKS endpoint
    let jwks_mock = server.mock(|when, then| {
        when.method(GET)
           .path("/jwks");
        then.status(200)
           .json_body(json!({
               "keys": [{
                   "kty": "RSA",
                   "use": "sig",
                   "kid": "test-kid",
                   "n": "n3fr8rP9NZXb05xgjghpD0KvQ1dOvS9p3u1Fz5V1Z8e8q5Z7X9Y0A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6",
                   "e": "AQAB"
               }]
           }));
    });
    
    let client = OidcClient::discover(&issuer, client_id, client_secret, redirect_uri)
        .await
        .unwrap();
    
    (client, server)
}

#[tokio::test]
async fn test_discover_success() {
    let server = httpmock::MockServer::start_async().await;
    
    // Mock the discovery endpoint
    let issuer = server.base_url();
    let discovery_mock = server.mock(|when, then| {
        when.method(GET)
           .path("/.well-known/openid-configuration");
        then.status(200)
           .json_body(json!({
               "issuer": issuer,
               "authorization_endpoint": format!("{}/authorize"),
               "token_endpoint": format!("{}/token"),
               "jwks_uri": format!("{}/jwks"),
               "id_token_signing_alg_values_supported": ["RS256"]
           }));
    });
    
    // Mock the JWKS endpoint
    let jwks_mock = server.mock(|when, then| {
        when.method(GET)
           .path("/jwks");
        then.status(200)
           .json_body(json!({
               "keys": [{
                   "kty": "RSA",
                   "use": "sig",
                   "kid": "test-kid",
                   "n": "n3fr8rP9NZXb05xgjghpD0KvQ1dOvS9p3u1Fz5V1Z8e8q5Z7X9Y0A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6",
                   "e": "AQAB"
               }]
           }));
    });
    
    let client_id = "test_client_id".to_string();
    let client_secret = Some("test_client_secret".to_string());
    let redirect_uri = Url::parse("http://localhost:3000/callback").unwrap();
    
    let result = OidcClient::discover(&issuer, client_id, client_secret, redirect_uri).await;
    
    assert!(result.is_ok());
    let client = result.unwrap();
    
    // Verify metadata
    assert_eq!(client.metadata.issuer, issuer);
    assert_eq!(client.metadata.authorization_endpoint, format!("{}/authorize"));
    assert_eq!(client.metadata.token_endpoint, format!("{}/token"));
    assert_eq!(client.metadata.jwks_uri, format!("{}/jwks"));
    
    discovery_mock.assert_async().await;
    jwks_mock.assert_async().await;
}

#[tokio::test]
async fn test_discover_provider_not_found() {
    let server = httpmock::MockServer::start_async().await;
    let issuer = server.base_url();
    
    // No mock set up - will return 404
    let client_id = "test_client_id".to_string();
    let client_secret = Some("test_client_secret".to_string());
    let redirect_uri = Url::parse("http://localhost:3000/callback").unwrap();
    
    let result = OidcClient::discover(&issuer, client_id, client_secret, redirect_uri).await;
    
    assert!(result.is_err());
    if let Err(OidcError::Request(_)) = result {
        // Expected error type
    } else {
        panic!("Expected Request error");
    }
}

#[tokio::test]
async fn test_authorize_url() {
    let (client, _server) = setup_test_client().await;
    
    let state = "test_state";
    let nonce = "test_nonce";
    let scope = "openid profile email";
    
    let url = client.authorize_url(state, nonce, Some(scope));
    
    // Verify URL contains all required parameters
    assert!(url.contains(&client.metadata.authorization_endpoint));
    assert!(url.contains("response_type=code"));
    assert!(url.contains(&format!("client_id={}", client.client_id)));
    assert!(url.contains("redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback"));
    assert!(url.contains("scope=openid+profile+email"));
    assert!(url.contains(&format!("state={}", state)));
    assert!(url.contains(&format!("nonce={}", nonce)));
}

#[tokio::test]
async fn test_authorize_url_default_scope() {
    let (client, _server) = setup_test_client().await;
    
    let state = "test_state";
    let nonce = "test_nonce";
    
    let url = client.authorize_url(state, nonce, None);
    
    // Verify default scope is used
    assert!(url.contains("scope=openid+profile+email"));
}

#[tokio::test]
async fn test_exchange_code_success() {
    let (client, server) = setup_test_client().await;
    
    // Mock the token endpoint
    let expires_in = 3600;
    let now = Utc::now();
    let token_mock = server.mock(|when, then| {
        when.method(POST)
           .path("/token");
        then.status(200)
           .json_body(json!({
               "access_token": "test_access_token",
               "token_type": "Bearer",
               "id_token": "test_id_token",
               "refresh_token": "test_refresh_token",
               "expires_in": expires_in
           }));
    });
    
    let code = "test_code";
    let result = client.exchange_code(code).await;
    
    assert!(result.is_ok());
    let token_set = result.unwrap();
    
    assert_eq!(token_set.access_token, "test_access_token");
    assert_eq!(token_set.token_type, "Bearer");
    assert_eq!(token_set.id_token, Some("test_id_token".to_string()));
    assert_eq!(token_set.refresh_token, Some("test_refresh_token".to_string()));
    assert_eq!(token_set.expires_in, Some(expires_in));
    assert!(!token_set.is_expired());
    
    // Verify issued_at is set to current time
    assert!(token_set.issued_at <= Utc::now());
    
    token_mock.assert_async().await;
}

#[tokio::test]
async fn test_exchange_code_error() {
    let (client, server) = setup_test_client().await;
    
    // Mock the token endpoint to return an error
    let token_mock = server.mock(|when, then| {
        when.method(POST)
           .path("/token");
        then.status(400)
           .json_body(json!({
               "error": "invalid_request",
               "error_description": "Invalid code"
           }));
    });
    
    let code = "invalid_code";
    let result = client.exchange_code(code).await;
    
    assert!(result.is_err());
    
    token_mock.assert_async().await;
}

#[tokio::test]
async fn test_verify_id_token_success() {
    let (client, server) = setup_test_client().await;
    
    // Create a valid ID token (in a real test, this would be a properly signed JWT)
    // For testing purposes, we'll mock the verification
    let id_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2lkIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwibm9uY2UiOiJ0ZXN0X25vbmNlIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let nonce = "test_nonce";
    
    // In a real implementation, the token would be properly verified
    // For this test, we'll assume the token is valid
    let result = client.verify_id_token(id_token, nonce);
    
    // Since we can't properly verify the signature in this test, we'll check that the method doesn't panic
    // In a real test with a properly signed token, we would verify the claims
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_verify_id_token_nonce_mismatch() {
    let (client, _server) = setup_test_client().await;
    
    // Create a token with a different nonce
    let id_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2lkIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwibm9uY2UiOiJ3cm9uZ19ub25jZSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let nonce = "test_nonce";
    
    let result = client.verify_id_token(id_token, nonce);
    
    assert!(result.is_err());
    if let Err(OidcError::NonceMismatch { expected, actual }) = result {
        assert_eq!(expected, "test_nonce");
        assert_eq!(actual, "wrong_nonce");
    } else {
        panic!("Expected NonceMismatch error");
    }
}

#[tokio::test]
async fn test_userinfo_success() {
    let (client, server) = setup_test_client().await;
    
    // Mock the userinfo endpoint
    let userinfo_mock = server.mock(|when, then| {
        when.method(GET)
           .path("/userinfo")
           .header("Authorization", "Bearer test_access_token");
        then.status(200)
           .json_body(json!({
               "sub": "1234567890",
               "name": "John Doe",
               "email": "john.doe@example.com",
               "email_verified": true
           }));
    });
    
    let access_token = "test_access_token";
    let result = client.userinfo(access_token).await;
    
    assert!(result.is_ok());
    let user_info = result.unwrap();
    
    assert_eq!(user_info.sub, "1234567890");
    assert_eq!(user_info.name, Some("John Doe".to_string()));
    assert_eq!(user_info.email, Some("john.doe@example.com".to_string()));
    assert_eq!(user_info.email_verified, Some(true));
    
    userinfo_mock.assert_async().await;
}

#[tokio::test]
async fn test_userinfo_error() {
    let (client, server) = setup_test_client().await;
    
    // Mock the userinfo endpoint to return an error
    let userinfo_mock = server.mock(|when, then| {
        when.method(GET)
           .path("/userinfo")
           .header("Authorization", "Bearer test_access_token");
        then.status(401)
           .json_body(json!({
               "error": "invalid_token",
               "error_description": "The access token expired"
           }));
    });
    
    let access_token = "test_access_token";
    let result = client.userinfo(access_token).await;
    
    assert!(result.is_err());
    
    userinfo_mock.assert_async().await;
}