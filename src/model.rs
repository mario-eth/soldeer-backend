use chrono::prelude::*;
use serde::{
    Deserialize,
    Serialize,
};
use std::fmt;

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
#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone, Default)]
pub struct Project {
    pub id: uuid::Uuid,
    pub name: String,
    pub description: String,
    pub github_url: String,
    pub user_id: uuid::Uuid,
    #[sqlx(default)]
    pub deleted: Option<bool>,
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

#[derive(Debug, Deserialize)]
pub struct FetchProjectsSchema {
    #[serde(default)]
    pub user_id: Option<uuid::Uuid>,
    #[serde(default)]
    pub project_id: Option<uuid::Uuid>,
    #[serde(default)]
    pub project_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FetchRevisionsSchema {
    pub project_id: Option<uuid::Uuid>,
    pub revision_id: Option<uuid::Uuid>,
    pub project_name: Option<String>,
    pub revision: Option<String>,
}
