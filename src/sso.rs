use std::sync::RwLock;
use std::time::Duration;
use url::Url;

use jsonwebtoken::{DecodingKey, Validation};
use mini_moka::sync::Cache;
use once_cell::sync::Lazy;
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType, CoreUserInfoClaims};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AccessToken, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IdToken, Nonce,
    OAuth2TokenResponse, Scope,
};

use crate::{
    api::ApiResult,
    db::models::{EventType, SsoNonce},
    db::DbConn,
    CONFIG,
};

pub static COOKIE_NAME_REDIRECT: Lazy<String> = Lazy::new(|| "sso_redirect_url".to_string());

static AC_CACHE: Lazy<Cache<String, AuthenticatedUser>> =
    Lazy::new(|| Cache::builder().max_capacity(1000).time_to_live(Duration::from_secs(10 * 60)).build());

static CLIENT_CACHE: RwLock<Option<CoreClient>> = RwLock::new(None);

static SSO_JWT_VALIDATION: Lazy<Decoding> = Lazy::new(prepare_decoding);

// Will Panic if SSO is activated and a key file is present but we can't decode its content
pub fn load_lazy() {
    Lazy::force(&SSO_JWT_VALIDATION);
}

// Call the OpenId discovery endpoint to retrieve configuration
async fn get_client() -> ApiResult<CoreClient> {
    let client_id = ClientId::new(CONFIG.sso_client_id());
    let client_secret = ClientSecret::new(CONFIG.sso_client_secret());

    let issuer_url = CONFIG.sso_issuer_url()?;

    let provider_metadata = match CoreProviderMetadata::discover_async(issuer_url, async_http_client).await {
        Err(err) => err!(format!("Failed to discover OpenID provider: {err}")),
        Ok(metadata) => metadata,
    };

    Ok(CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
        .set_redirect_uri(CONFIG.sso_redirect_url()?))
}

// Simple cache to prevent recalling the discovery endpoint each time
async fn cached_client() -> ApiResult<CoreClient> {
    let cc_client = CLIENT_CACHE.read().ok().and_then(|rw_lock| rw_lock.clone());
    match cc_client {
        Some(client) => Ok(client),
        None => get_client().await.map(|client| {
            let mut cached_client = CLIENT_CACHE.write().unwrap();
            *cached_client = Some(client.clone());
            client
        }),
    }
}

// The `nonce` allow to protect against replay attacks
pub async fn authorize_url(mut conn: DbConn, state: String) -> ApiResult<Url> {
    let (auth_url, _csrf_state, nonce) = cached_client()
        .await?
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            || CsrfToken::new(state),
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .url();

    let sso_nonce = SsoNonce::new(nonce.secret().to_string());
    sso_nonce.save(&mut conn).await?;

    Ok(auth_url)
}

#[derive(Debug, Serialize, Deserialize)]
struct IdTokenPayload {
    exp: i64,
    email: Option<String>,
    nonce: String,
}

#[derive(Debug)]
struct AccessTokenPayload {
    role: Option<UserRole>,
}

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    User,
}

#[derive(Clone, Debug)]
pub struct AuthenticatedUser {
    pub nonce: String,
    pub refresh_token: String,
    pub email: String,
    pub user_name: Option<String>,
    pub role: Option<UserRole>,
}

impl AuthenticatedUser {
    pub fn is_admin(&self) -> bool {
        self.role.as_ref().is_some_and(|x| x == &UserRole::Admin)
    }
}

struct Decoding {
    key: DecodingKey,
    id_validation: Validation,
    access_validation: Validation,
    debug_key: DecodingKey,
    debug_validation: Validation,
}

impl Decoding {
    pub fn new(key: DecodingKey, validation: Validation) -> Self {
        let mut access_validation = validation.clone();
        access_validation.validate_aud = false;

        let mut debug_validation = insecure_validation();
        debug_validation.validate_aud = false;

        Decoding {
            key,
            id_validation: validation,
            access_validation,
            debug_key: DecodingKey::from_secret(&[]),
            debug_validation,
        }
    }

    pub fn log_decode_debug(&self, token_name: &str, token: &str) {
        let _ = jsonwebtoken::decode::<serde_json::Value>(token, &self.debug_key, &self.debug_validation)
            .map(|payload| debug!("Token {token_name}: {}", payload.claims));
    }
}

// DecodingKey and Validation used to read the SSO JWT token response
// If there is no key fallback to reading without validation
fn prepare_decoding() -> Decoding {
    let maybe_key = CONFIG.sso_enabled().then_some(()).and_then(|_| match std::fs::read(CONFIG.sso_key_filepath()) {
        Ok(key) => Some(DecodingKey::from_rsa_pem(&key).unwrap_or_else(|e| {
            panic!(
                "Failed to decode optional SSO public RSA Key, format should exactly match:\n\
                -----BEGIN PUBLIC KEY-----\n\
                ...\n\
                -----END PUBLIC KEY-----\n\
                Error: {e}"
            );
        })),
        Err(err) => {
            println!("[INFO] Can't read optional SSO public key at {} : {err}", CONFIG.sso_key_filepath());
            None
        }
    });

    match maybe_key {
        Some(key) => {
            let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
            validation.leeway = 30; // 30 seconds
            validation.validate_exp = true;
            validation.validate_nbf = true;
            validation.set_audience(&[CONFIG.sso_client_id()]);
            validation.set_issuer(&[CONFIG.sso_authority()]);

            Decoding::new(key, validation)
        }
        None => Decoding::new(DecodingKey::from_secret(&[]), insecure_validation()),
    }
}

fn insecure_validation() -> Validation {
    let mut validation = jsonwebtoken::Validation::default();
    validation.set_audience(&[CONFIG.sso_client_id()]);
    validation.insecure_disable_signature_validation();

    validation
}

#[derive(Clone, Debug)]
pub struct UserInformation {
    pub email: String,
    pub user_name: Option<String>,
}

fn decode_id_token<
    AC: openidconnect::AdditionalClaims,
    GC: openidconnect::GenderClaim,
    JE: openidconnect::JweContentEncryptionAlgorithm<JT>,
    JS: openidconnect::JwsSigningAlgorithm<JT>,
    JT: openidconnect::JsonWebKeyType,
>(
    oic_id_token: Option<&IdToken<AC, GC, JE, JS, JT>>,
) -> ApiResult<IdTokenPayload> {
    let id_token_str = match oic_id_token {
        None => err!("Token response did not contain an id_token"),
        Some(token) => token.to_string(),
    };

    match jsonwebtoken::decode::<IdTokenPayload>(
        id_token_str.as_str(),
        &SSO_JWT_VALIDATION.key,
        &SSO_JWT_VALIDATION.id_validation,
    ) {
        Ok(payload) => Ok(payload.claims),
        Err(err) => {
            SSO_JWT_VALIDATION.log_decode_debug("identity_token", id_token_str.as_str());
            err!(format!("Could not decode id token: {err}"))
        }
    }
}

// Errors are logged but will return None
fn decode_roles(email: &str, token: &serde_json::Value) -> Option<UserRole> {
    let roles_path = CONFIG.sso_roles_token_path();

    if let Some(json_roles) = token.pointer(&roles_path) {
        match serde_json::from_value::<Vec<UserRole>>(json_roles.clone()) {
            Ok(mut roles) => {
                roles.sort();
                roles.into_iter().next()
            }
            Err(err) => {
                debug!("Failed to parse user ({email}) roles: {err}");
                None
            }
        }
    } else {
        debug!("No roles in {email} access_token");
        None
    }
}

fn decode_access_token(email: &str, access_token: &AccessToken) -> ApiResult<AccessTokenPayload> {
    if CONFIG.sso_roles_enabled() {
        let access_token_str = access_token.secret();

        SSO_JWT_VALIDATION.log_decode_debug("access_token", access_token_str);

        match jsonwebtoken::decode::<serde_json::Value>(
            access_token_str,
            &SSO_JWT_VALIDATION.key,
            &SSO_JWT_VALIDATION.access_validation,
        ) {
            Err(err) => err!(format!("Could not decode access token: {:?}", err)),
            Ok(payload) => {
                let payload = payload.claims;

                let role = if CONFIG.sso_roles_enabled() {
                    let role = decode_roles(email, &payload);
                    if !CONFIG.sso_roles_default_to_user() && role.is_none() {
                        info!("User {email} failed to login due to missing/invalid role");
                        err!(
                            "Invalid user role. Contact your administrator",
                            ErrorEvent {
                                event: EventType::UserFailedLogIn
                            }
                        )
                    }
                    role
                } else {
                    None
                };

                Ok(AccessTokenPayload {
                    role,
                })
            }
        }
    } else {
        Ok(AccessTokenPayload {
            role: None,
        })
    }
}

async fn retrieve_user_info(client: &CoreClient, access_token: AccessToken) -> ApiResult<CoreUserInfoClaims> {
    let endpoint = match client.user_info(access_token, None) {
        Err(err) => err!(format!("No user_info endpoint: {err}")),
        Ok(endpoint) => endpoint,
    };

    match endpoint.request_async(async_http_client).await {
        Err(err) => err!(format!("Request to user_info endpoint failed: {err}")),
        Ok(user_info) => Ok(user_info),
    }
}

// During the 2FA flow we will
//  - retrieve the user information and then only discover he needs 2FA.
//  - second time we will rely on the `AC_CACHE` since the `code` has already been exchanged.
// The `nonce` will ensure that the user is authorized only once.
// We return only the `UserInformation` to force calling `redeem` to obtain the `refresh_token`.
pub async fn exchange_code(code: &String) -> ApiResult<UserInformation> {
    if let Some(authenticated_user) = AC_CACHE.get(code) {
        return Ok(UserInformation {
            email: authenticated_user.email,
            user_name: authenticated_user.user_name,
        });
    }

    let oidc_code = AuthorizationCode::new(code.clone());
    let client = cached_client().await?;

    match client.exchange_code(oidc_code).request_async(async_http_client).await {
        Ok(token_response) => {
            let refresh_token =
                token_response.refresh_token().map_or(String::new(), |token| token.secret().to_string());

            let id_token = decode_id_token(token_response.extra_fields().id_token())?;
            let user_info = retrieve_user_info(&client, token_response.access_token().to_owned()).await?;
            let user_name = user_info.preferred_username().map(|un| un.to_string());

            let email = match id_token.email {
                Some(email) => email,
                None => match user_info.email() {
                    None => err!("Neither id token nor userinfo contained an email"),
                    Some(email) => email.to_owned().to_string(),
                },
            };

            let access_token = decode_access_token(&email, token_response.access_token())?;

            let authenticated_user = AuthenticatedUser {
                nonce: id_token.nonce,
                refresh_token,
                email: email.clone(),
                user_name: user_name.clone(),
                role: access_token.role,
            };

            AC_CACHE.insert(code.clone(), authenticated_user);

            Ok(UserInformation {
                email,
                user_name,
            })
        }
        Err(err) => err!(format!("Failed to contact token endpoint: {err}")),
    }
}

// User has passed 2FA flow we can delete `nonce` and clear the cache.
pub async fn redeem(code: &String, conn: &mut DbConn) -> ApiResult<AuthenticatedUser> {
    if let Some(au) = AC_CACHE.get(code) {
        AC_CACHE.invalidate(code);

        if let Some(sso_nonce) = SsoNonce::find(&au.nonce, conn).await {
            match sso_nonce.delete(conn).await {
                Err(msg) => err!(format!("Failed to delete nonce: {msg}")),
                Ok(_) => Ok(au),
            }
        } else {
            err!("Failed to retrive nonce from db")
        }
    } else {
        err!("Failed to retrieve user info from sso cache")
    }
}
