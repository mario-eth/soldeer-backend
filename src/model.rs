use chrono::prelude::*;
use serde::{
    Deserialize,
    Serialize,
};
use std::fmt;

use axum::{
    http::StatusCode,
    Json,
};

use crate::utils::ORGANIZATION_NAME_PATTERN;

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone)]
pub struct User {
    pub id: uuid::Uuid,
    pub email: String,
    pub password: String,
    pub username: String,
    pub role: String,
    pub verified: bool,
    pub github_id: Option<String>,
    pub github_username: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub organization_id: Option<uuid::Uuid>,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone)]
pub struct Organization {
    pub id: uuid::Uuid,
    pub name: String,
    pub description: Option<String>,
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
    pub username: String,
    pub organization_name: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginUserSchema {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Role {
    Owner,
    Admin,
    User,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Role::Owner => write!(f, "owner"),
            Role::Admin => write!(f, "admin"),
            Role::User => write!(f, "user"),
        }
    }
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone, Default)]
pub struct Project {
    pub id: uuid::Uuid,
    pub name: String,
    pub description: String,
    pub github_url: String,
    pub created_by: uuid::Uuid,
    #[sqlx(default)]
    pub deleted: Option<bool>,
    #[sqlx(default)]
    pub downloads: Option<i64>,
    pub image: Option<String>,
    pub long_description: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub organization_id: Option<uuid::Uuid>,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone)]
pub struct Revision {
    pub id: uuid::Uuid,
    pub version: String,
    pub internal_name: String,
    pub url: String,
    pub project_id: uuid::Uuid,
    #[sqlx(default)]
    pub downloads: Option<i64>,
    pub deleted: bool,
    pub created_at: Option<DateTime<Utc>>,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone)]
pub struct Verification {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    #[sqlx(default)]
    pub used: Option<bool>,
    pub verification_type: String,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateProjectSchema {
    pub name: String,
    pub description: String,
    pub long_description: String,
    pub github_url: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProjectSchema {
    pub id: uuid::Uuid,
    pub description: String,
    pub github_url: String,
    pub long_description: String,
}

#[derive(Debug, Deserialize)]
pub struct FetchProjectsSchema {
    #[serde(default)]
    pub organization_id: Option<uuid::Uuid>,
    #[serde(default)]
    pub project_id: Option<uuid::Uuid>,
    #[serde(default)]
    pub project_name: Option<String>,
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct FetchRevisionsSchema {
    pub project_id: Option<uuid::Uuid>,
    pub revision_id: Option<uuid::Uuid>,
    pub project_name: Option<String>,
    pub revision: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserPasswordSchema {
    pub current_password: String,
    pub password: String,
    pub repeat_password: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUsernameSchema {
    pub username: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyEmailSchema {
    pub code: uuid::Uuid,
}
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct GetLastCodeSchema {
    pub user_id: uuid::Uuid,
}

#[derive(Debug, Deserialize)]
pub struct RequestPasswordSchema {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub enum VerificationType {
    Register,
    Password,
}

impl fmt::Display for VerificationType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordSchema {
    pub code: uuid::Uuid,
    pub password: String,
    pub repeat_password: String,
}

#[derive(Debug, Deserialize)]
pub struct GithubCallbackSchema {
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateOrganizationSchema {
    pub name: String,
    pub description: String,
}

impl UpdateOrganizationSchema {
    pub fn validate(&self) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
        if self.name.len() < 3 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "status": "fail",
                    "message": "Organization name must be at least 3 characters",
                })),
            ));
        }

        if self.description.len() < 3 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "status": "fail",
                    "message": "Organization description must be at least 3 characters",
                })),
            ));
        }

        let smart_name = self.name.replace(" ", "");

        let pattern_name = regex::Regex::new(ORGANIZATION_NAME_PATTERN).unwrap();
        if !pattern_name.is_match(&smart_name) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "status": "fail",
                    "message": "Invalid organization name format, must contain only letters, numbers, and hyphens",
                })),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct AddUserToOrganizationSchema {
    pub email: String,
    pub username: String,
    pub password: String,
    pub role: String,
}
