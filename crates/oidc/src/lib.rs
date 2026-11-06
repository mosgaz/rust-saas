//! OpenID Connect client implementation
//!
//! This crate provides a client for OpenID Connect (OIDC) authentication, enabling
//! integration with external identity providers like Google, Keycloak, etc.
//!
//! The implementation follows the OIDC specification and provides methods for:
//! - Discovering OIDC provider configuration
//! - Generating authorization URLs
//! - Exchanging authorization codes for tokens
//! - Verifying ID tokens
//! - Fetching user information

#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use url::Url;
use chrono::{DateTime, Utc};
use jsonwebtoken::{DecodingKey, Validation, Algorithm};

/// Errors that can occur during OIDC operations
#[derive(Debug, Error)]
pub enum OidcError {
    /// HTTP request failed
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    
    /// JSON parsing failed
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    
    /// JWT decoding failed
    #[error("jwt decode error: {0}")]
    JwtDecode(#[from] jsonwebtoken::errors::Error),
    
    /// Required field missing in response
    #[error("missing field: {0}")]
    MissingField(&'static str),
    
    /// Invalid issuer in ID token
    #[error("invalid issuer: expected {expected}, got {actual}")]
    InvalidIssuer {
        /// Expected issuer
        expected: String,
        /// Actual issuer from token
        actual: String,
    },
    
    /// Invalid audience in ID token
    #[error("invalid audience: expected {expected}, got {actual:?}")]
    InvalidAudience {
        /// Expected audience
        expected: String,
        /// Actual audience from token
        actual: Vec<String>,
    },
    
    /// Nonce mismatch in ID token
    #[error("nonce mismatch: expected {expected}, got {actual}")]
    NonceMismatch {
        /// Expected nonce
        expected: String,
        /// Actual nonce from token
        actual: String,
    },
    
    /// Token expired
    #[error("token expired: {0}")]
    TokenExpired(DateTime<Utc>),
    
    /// Issued at time in future
    #[error("issued at in future: {0}")]
    IssuedAtInFuture(DateTime<Utc>),
    
    /// Unsupported algorithm
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

/// OpenID Connect provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderMetadata {
    /// Issuer identifier
    pub issuer: String,
    /// Authorization endpoint
    pub authorization_endpoint: String,
    /// Token endpoint
    pub token_endpoint: String,
    /// Userinfo endpoint
    pub userinfo_endpoint: Option<String>,
    /// JSON Web Key Set endpoint
    pub jwks_uri: String,
    /// Supported response types
    pub response_types_supported: Option<Vec<String>>,
    /// Supported subject types
    pub subject_types_supported: Option<Vec<String>>,
    /// Supported ID token signing algorithms
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
    /// Supported scopes
    pub scopes_supported: Option<Vec<String>>,
    /// Supported claims
    pub claims_supported: Option<Vec<String>>,
}

/// Token response from token endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSet {
    /// Access token
    pub access_token: String,
    /// Token type (usually "Bearer")
    #[serde(rename = "token_type")]
    pub token_type: String,
    /// ID token (JWT)
    pub id_token: Option<String>,
    /// Refresh token
    pub refresh_token: Option<String>,
    /// Expires in seconds
    pub expires_in: Option<i64>,
    /// Scope
    pub scope: Option<String>,
    /// Issue time
    #[serde(skip)]
    pub issued_at: DateTime<Utc>,
}

impl TokenSet {
    /// Check if access token is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_in) = self.expires_in {
            let now = Utc::now();
            let expires = self.issued_at + chrono::Duration::seconds(expires_in);
            now > expires
        } else {
            false
        }
    }
}

/// Claims from ID token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Subject identifier
    pub sub: String,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: Vec<String>,
    /// Expiration time
    pub exp: i64,
    /// Issued at time
    pub iat: i64,
    /// Nonce
    pub nonce: Option<String>,
    /// Authentication time
    pub auth_time: Option<i64>,
    /// Authorized party (for third-party clients)
    pub azp: Option<String>,
    /// Access token hash
    pub at_hash: Option<String>,
    /// Code hash
    pub c_hash: Option<String>,
    
    /// Email
    pub email: Option<String>,
    /// Email verified
    pub email_verified: Option<bool>,
    /// Full name
    pub name: Option<String>,
    /// Given name
    pub given_name: Option<String>,
    /// Family name
    pub family_name: Option<String>,
    /// Locale
    pub locale: Option<String>,
    /// Picture URL
    pub picture: Option<String>,
    
    /// Custom claims
    #[serde(flatten)]
    pub custom: Value,
}

/// Userinfo response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    /// Subject identifier
    pub sub: String,
    
    /// Email
    pub email: Option<String>,
    /// Email verified
    pub email_verified: Option<bool>,
    /// Full name
    pub name: Option<String>,
    /// Given name
    pub given_name: Option<String>,
    /// Family name
    pub family_name: Option<String>,
    /// Locale
    pub locale: Option<String>,
    /// Picture URL
    pub picture: Option<String>,
    
    /// Custom claims
    #[serde(flatten)]
    pub custom: Value,
}

/// OpenID Connect client
///
/// This struct handles OIDC authentication flows with a provider.
///
/// # Example
///
/// ```
/// use url::Url;
/// use oidc::OidcClient;
///
/// let issuer = "https://accounts.google.com";
/// let client = OidcClient::discover(issuer).await.unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct OidcClient {
    /// Provider metadata
    metadata: ProviderMetadata,
    /// HTTP client
    client: reqwest::Client,
    /// JWKS (JSON Web Key Set)
    jwks: jsonwebtoken::jwk::JwkSet,
    /// Client ID
    client_id: String,
    /// Client secret
    client_secret: Option<String>,
    /// Redirect URI
    redirect_uri: Url,
}

impl OidcClient {
    /// Discover provider configuration and create client
    pub async fn discover(
        issuer: &str,
        client_id: String,
        client_secret: Option<String>,
        redirect_uri: Url,
    ) -> Result<Self, OidcError> {
        let issuer = issuer.trim_end_matches('/');
        let discovery_url = format!("{}/.well-known/openid-configuration", issuer);
        
        let client = reqwest::Client::new();
        let metadata: ProviderMetadata = client
            .get(&discovery_url)
            .send()
            .await?
            .json()
            .await?;
        
        let jwks: jsonwebtoken::jwk::JwkSet = client
            .get(&metadata.jwks_uri)
            .send()
            .await?
            .json()
            .await?;
        
        Ok(Self {
            metadata,
            client,
            jwks,
            client_id,
            client_secret,
            redirect_uri,
        })
    }
    
    /// Generate authorization URL
    ///
    /// # Arguments
    /// 
    /// * `state` - Opaque value to maintain state between request and callback
    /// * `nonce` - Value included in ID token for replay protection
    /// * `scope` - Optional scope parameter (default: "openid profile email")
    /// 
    /// # Returns
    /// 
    /// Authorization URL as a string
    pub fn authorize_url(&self, state: &str, nonce: &str, scope: Option<&str>) -> String {
        let scope = scope.unwrap_or("openid profile email");
        let redirect_uri = self.redirect_uri.as_str();
        
        format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}",
            self.metadata.authorization_endpoint,
            self.client_id,
            redirect_uri,
            scope,
            state,
            nonce
        )
    }
    
    /// Exchange authorization code for tokens
    ///
    /// # Arguments
    /// 
    /// * `code` - Authorization code received from callback
    /// 
    /// # Returns
    /// 
    /// TokenSet containing access token, ID token, etc.
    pub async fn exchange_code(&self, code: &str) -> Result<TokenSet, OidcError> {
        #[derive(Serialize)]
        struct TokenRequest {
            grant_type: &'static str,
            code: String,
            redirect_uri: String,
            client_id: String,
            client_secret: Option<String>,
        }
        
        let request = TokenRequest {
            grant_type: "authorization_code",
            code: code.to_string(),
            redirect_uri: self.redirect_uri.as_str().to_string(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
        };
        
        let mut response = self
            .client
            .post(&self.metadata.token_endpoint)
            .form(&request)
            .send()
            .await?;
        
        // Handle error response
        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(OidcError::Request(reqwest::Error::from_status(
                response.status(),
                &error_text,
            )));
        }
        
        let mut token_set: TokenSet = response.json().await?;
        token_set.issued_at = Utc::now();
        
        Ok(token_set)
    }
    
    /// Verify ID token
    ///
    /// # Arguments
    /// 
    /// * `token` - ID token (JWT) to verify
    /// * `nonce` - Nonce value used in authorization request
    /// 
    /// # Returns
    /// 
    /// Verified ID token claims
    pub fn verify_id_token(&self, token: &str, nonce: &str) -> Result<IdTokenClaims, OidcError> {
        // Parse JWT header to get algorithm
        let header = jsonwebtoken::decode_header(token)?;
        let alg = header.alg.to_string();
        
        // Check if algorithm is supported
        if let Some(supported_algs) = &self.metadata.id_token_signing_alg_values_supported {
            if !supported_algs.contains(&alg) {
                return Err(OidcError::UnsupportedAlgorithm(alg));
            }
        }
        
        // Find matching JWK
        let kid = header.kid.ok_or(OidcError::MissingField("kid"))?;
        let jwk = self.jwks.find(&kid).ok_or(OidcError::MissingField("jwk"))?;
        
        // Create decoding key
        let decoding_key = match jwk.algorithm {
            jsonwebtoken::jwk::Algorithm::RSA(_) => {
                let n = jwk.params.rsa().ok_or(OidcError::MissingField("n"))?.n.clone();
                let e = jwk.params.rsa().ok_or(OidcError::MissingField("e"))?.e.clone();
                let bytes = base64::decode_config(&n, base64::URL_SAFE_NO_PAD)?;
                let e_bytes = base64::decode_config(&e, base64::URL_SAFE_NO_PAD)?;
                let e = match e_bytes.len() {
                    1 => (e_bytes[0] as u64).into(),
                    2 => u64::from_be_bytes([0, 0, 0, 0, 0, 0, e_bytes[0], e_bytes[1]]).into(),
                    3 => u64::from_be_bytes([0, 0, 0, 0, 0, e_bytes[0], e_bytes[1], e_bytes[2]]).into(),
                    4 => u64::from_be_bytes([0, 0, 0, 0, e_bytes[0], e_bytes[1], e_bytes[2], e_bytes[3]]).into(),
                    _ => u64::from_be_bytes([
                        e_bytes[e_bytes.len() - 8],
                        e_bytes[e_bytes.len() - 7],
                        e_bytes[e_bytes.len() - 6],
                        e_bytes[e_bytes.len() - 5],
                        e_bytes[e_bytes.len() - 4],
                        e_bytes[e_bytes.len() - 3],
                        e_bytes[e_bytes.len() - 2],
                        e_bytes[e_bytes.len() - 1],
                    ]).into(),
                };
                DecodingKey::from_rsa_components(&bytes, &e)?
            },
            jsonwebtoken::jwk::Algorithm::EC(_) => {
                let x = jwk.params.ec().ok_or(OidcError::MissingField("x"))?.x.clone();
                let y = jwk.params.ec().ok_or(OidcError::MissingField("y"))?.y.clone();
                let x_bytes = base64::decode_config(&x, base64::URL_SAFE_NO_PAD)?;
                let y_bytes = base64::decode_config(&y, base64::URL_SAFE_NO_PAD)?;
                match alg.as_str() {
                    "ES256" => DecodingKey::from_ec_pem(&format!(
                        "-----BEGIN PUBLIC KEY-----\\n{}\\n-----END PUBLIC KEY-----",
                        base64::encode_config(
                            &[0x04]
                                .iter()
                                .chain(x_bytes.iter())
                                .chain(y_bytes.iter())
                                .copied()
                                .collect::<Vec<u8>>(),
                            base64::STANDARD
                        )
                    ))?,
                    _ => return Err(OidcError::UnsupportedAlgorithm(alg)),
                }
            },
            _ => return Err(OidcError::UnsupportedAlgorithm(alg)),
        };
        
        // Validate token
        let mut validation = Validation::new(Algorithm::from_str(&alg)?);
        validation.iss = Some(self.metadata.issuer.clone());
        validation.aud = Some(vec![self.client_id.clone()]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        
        let token_data = jsonwebtoken::decode::<IdTokenClaims>(token, &decoding_key, &validation)?;
        
        // Verify nonce
        if let Some(token_nonce) = &token_data.claims.nonce {
            if token_nonce != nonce {
                return Err(OidcError::NonceMismatch {
                    expected: nonce.to_string(),
                    actual: token_nonce.clone(),
                });
            }
        } else {
            return Err(OidcError::MissingField("nonce"));
        }
        
        Ok(token_data.claims)
    }
    
    /// Fetch user information
    ///
    /// # Arguments
    /// 
    /// * `access_token` - Access token obtained from token exchange
    /// 
    /// # Returns
    /// 
    /// UserInfo containing user profile information
    pub async fn userinfo(&self, access_token: &str) -> Result<UserInfo, OidcError> {
        let userinfo_endpoint = self.metadata.userinfo_endpoint
            .as_ref()
            .ok_or(OidcError::MissingField("userinfo_endpoint"))?;
        
        let response = self
            .client
            .get(userinfo_endpoint)
            .bearer_auth(access_token)
            .send()
            .await?;
        
        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(OidcError::Request(reqwest::Error::from_status(
                response.status(),
                &error_text,
            )));
        }
        
        let user_info: UserInfo = response.json().await?;
        Ok(user_info)
    }
}
