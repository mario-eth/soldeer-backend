use axum_typed_multipart::{
    FieldData,
    TryFromMultipart,
    TypedMultipart,
};
use chrono::prelude::*;
use serde::{
    Deserialize,
    Serialize,
};
use std::fmt;
use tempfile::NamedTempFile;

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone)]
pub struct User {
    pub id: uuid::Uuid,
    pub email: String,
    pub password: String,
    pub role: String,
    pub verified: bool,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
}

#[derive(Debug, Deserialize)]
pub struct RegisterUserSchema {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginUserSchema {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Role {
    Admin,
    Moderator,
    User,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Role::Admin => write!(f, "0"),
            Role::Moderator => write!(f, "1"),
            Role::User => write!(f, "2"),
        }
    }
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone)]
pub struct Project {
    pub id: uuid::Uuid,
    pub name: String,
    pub description: String,
    pub github_url: String,
    pub user_id: uuid::Uuid,
    #[sqlx(default)]
    pub deleted: Option<bool>,
    pub current_revision: Option<uuid::Uuid>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone)]
pub struct Revision {
    pub id: uuid::Uuid,
    pub version: String,
    pub internal_name: String,
    pub url: String,
    pub project_id: uuid::Uuid,
    pub deleted: bool,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateProjectSchema {
    pub name: String,
    pub description: String,
    pub github_url: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProjectSchema {
    pub id: uuid::Uuid,
    pub name: String,
    pub description: String,
    pub github_url: String,
}

#[derive(TryFromMultipart)]
pub struct UploadRevisionSchema {
    // The `unlimited arguments` means that this field will be limited to the
    // total size of the request body. If you want to limit the size of this
    // field to a specific value you can also specify a limit in bytes, like
    // '5MiB' or '1GiB'.
    #[form_data(limit = "unlimited")]
    pub zip: FieldData<NamedTempFile>,

    pub version: String,
    pub project_id: uuid::Uuid,
}

#[derive(Debug, Deserialize)]
pub struct DeleteProjectSchema {
    pub id: uuid::Uuid,
}

#[derive(Debug, Deserialize)]
pub struct CreateRevisionSchema {
    pub version: String,
    pub url: String,
    pub project_id: uuid::Uuid,
}
