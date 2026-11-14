//! Request extractors. `Actor` is the auth seam.

use axum::Json;
use axum::extract::{FromRequest, FromRequestParts, Path, Query};
use axum::http::request::Parts;
use percent_encoding::percent_decode_str;

use crate::{ApiError, AppState};

pub const ACTOR_HEADER: &str = "x-actor-name";
pub const ADMIN_TOKEN_HEADER: &str = "x-admin-token";
pub const TICKET_TOKEN_HEADER: &str = "x-ticket-token";

/// The worker making the request.
///
/// MVP: trusts the `X-Actor-Name` header (percent-encoded, so Japanese names
/// survive HTTP headers), which the frontend fills from a name picker.
/// Anyone can claim to be anyone. To add SSO/JWT, replace only this extractor.
///
/// It gets the `AppState`, so a real login can look up a session or a user here,
/// and a refused request can be written to an audit log before the 401 goes out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    pub name: String,
}

impl FromRequestParts<AppState> for Actor {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &AppState) -> Result<Self, Self::Rejection> {
        let raw = parts.headers.get(ACTOR_HEADER).and_then(|v| v.to_str().ok()).ok_or(ApiError::MissingActor)?;
        let name = percent_decode_str(raw).decode_utf8().map_err(|_| ApiError::MissingActor)?;
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 100 {
            return Err(ApiError::MissingActor);
        }
        Ok(Actor { name: name.to_owned() })
    }
}

/// The customer's secret, from `X-Ticket-Token`. The frontend reads it from the URL fragment.
pub struct TicketToken(pub String);

impl<S: Send + Sync> FromRequestParts<S> for TicketToken {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .headers
            .get(TICKET_TOKEN_HEADER)
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty())
            .map(|v| TicketToken(v.to_owned()))
            .ok_or(ApiError::MissingTicketToken)
    }
}

/// `Json`, `Path` and `Query` with rejections in our `{ code, message }` shape.
#[derive(FromRequest)]
#[from_request(via(Json), rejection(ApiError))]
pub struct ApiJson<T>(pub T);

#[derive(FromRequestParts)]
#[from_request(via(Path), rejection(ApiError))]
pub struct ApiPath<T>(pub T);

#[derive(FromRequestParts)]
#[from_request(via(Query), rejection(ApiError))]
pub struct ApiQuery<T>(pub T);

use axum::Json;
use axum::extract::{FromRequest, FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{ApiError, AppState};

pub const ACTOR_HEADER: &str = "x-actor-name"; // deprecated; never used for authentication
pub const ADMIN_TOKEN_HEADER: &str = "x-admin-token";
pub const TICKET_TOKEN_HEADER: &str = "x-ticket-token";

/// The worker making the request.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    pub id: Uuid,
    pub username: String,
    pub name: String,
    pub role: Role,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role { Admin, Worker }

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_at: DateTime<Utc>,
    pub user: ActorResponse,
}

#[derive(Debug, Serialize)]
pub struct ActorResponse { pub id: Uuid, pub username: String, pub name: String, pub role: Role }

#[derive(Debug, Deserialize)]
pub struct LoginRequest { pub username: String, pub password: String }

#[derive(Debug, Deserialize)]
struct ConfiguredUser { id: Uuid, username: String, password: String, name: String, role: Role }

pub const SESSION_SECONDS: i64 = 8 * 60 * 60;

pub async fn login(state: &AppState, req: LoginRequest) -> Result<LoginResponse, ApiError> {
    let users: Vec<ConfiguredUser> = std::env::var("AUTH_USERS")
        .ok().and_then(|raw| serde_json::from_str(&raw).ok()).unwrap_or_default();
    let user = users.iter().find(|u| u.username == req.username && u.password == req.password)
        .ok_or(ApiError::InvalidCredentials)?;
    let role = match user.role { Role::Admin => "admin", Role::Worker => "worker" };
    sqlx::query("INSERT INTO auth_users (id, username, name, role) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET username=excluded.username, name=excluded.name, role=excluded.role")
        .bind(user.id.to_string()).bind(&user.username).bind(&user.name).bind(role)
        .execute(&state.pool).await.map_err(|e| ApiError::WorksOnMyMachine(e.to_string()))?;
    let bearer = crate::token::generate().map_err(|e| ApiError::WorksOnMyMachine(e.to_string()))?;
    let expires_at = Utc::now() + chrono::Duration::seconds(SESSION_SECONDS);
    sqlx::query("INSERT INTO auth_sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(crate::token::hash(&bearer)).bind(user.id.to_string()).bind(expires_at)
        .execute(&state.pool).await.map_err(|e| ApiError::WorksOnMyMachine(e.to_string()))?;
    Ok(LoginResponse { access_token: bearer, token_type: "Bearer", expires_at,
        user: ActorResponse { id: user.id, username: user.username.clone(), name: user.name.clone(), role: user.role } })
}

pub async fn logout(state: &AppState, authorization: Option<&str>) -> Result<(), ApiError> {
    let token = authorization.and_then(|v| v.strip_prefix("Bearer ")).filter(|v| !v.is_empty())
        .ok_or(ApiError::MissingActor)?;
    let result = sqlx::query("UPDATE auth_sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL")
        .bind(Utc::now()).bind(crate::token::hash(token)).execute(&state.pool).await
        .map_err(|e| ApiError::WorksOnMyMachine(e.to_string()))?;
    if result.rows_affected() == 0 { return Err(ApiError::MissingActor); }
    Ok(())
}

impl FromRequestParts<AppState> for Actor {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let token = parts.headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer ")).filter(|v| !v.is_empty()).ok_or(ApiError::MissingActor)?;
        let row = sqlx::query_as::<_, (String, String, String, String, String)>(
            "SELECT u.id, u.username, u.name, u.role, s.expires_at FROM auth_sessions s JOIN auth_users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL")
            .bind(crate::token::hash(token)).fetch_optional(&state.pool).await
            .map_err(|e| ApiError::WorksOnMyMachine(e.to_string()))?.ok_or(ApiError::MissingActor)?;
        let (id, username, name, role, expires_at) = row;
        let expires_at: DateTime<Utc> = expires_at.parse().map_err(|_| ApiError::MissingActor)?;
        if expires_at <= Utc::now() { return Err(ApiError::MissingActor); }
        let role = serde_json::from_str(&format!("\"{role}\"")).map_err(|_| ApiError::MissingActor)?;
        Ok(Actor { id: Uuid::parse_str(&id).map_err(|_| ApiError::MissingActor)?, username, name, role })
    }
}

/// The customer's secret, from `X-Ticket-Token`. The frontend reads it from the URL fragment.
pub struct TicketToken(pub String);

impl<S: Send + Sync> FromRequestParts<S> for TicketToken {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .headers
            .get(TICKET_TOKEN_HEADER)
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty())
            .map(|v| TicketToken(v.to_owned()))
            .ok_or(ApiError::MissingTicketToken)
    }
}

/// `Json`, `Path` and `Query` with rejections in our `{ code, message }` shape.
#[derive(FromRequest)]
#[from_request(via(Json), rejection(ApiError))]
pub struct ApiJson<T>(pub T);

#[derive(FromRequestParts)]
#[from_request(via(Path), rejection(ApiError))]
pub struct ApiPath<T>(pub T);

#[derive(FromRequestParts)]
#[from_request(via(Query), rejection(ApiError))]
pub struct ApiQuery<T>(pub T);
