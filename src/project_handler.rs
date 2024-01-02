use std::sync::Arc;

use axum::{
    extract::{
        Multipart,
        State,
    },
    http::StatusCode,
    response::IntoResponse,
    Extension,
    Json,
};
use regex::Regex;
use serde_json::json;

use crate::{
    model::{
        CreateProjectSchema,
        Project,
        UpdateProjectSchema,
        UploadRevisionSchema,
        User,
    },
    AppState,
};

pub async fn add_project_handler(
    Extension(user): Extension<User>,
    State(data): State<Arc<AppState>>,
    Json(body): Json<CreateProjectSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let escaped_name = body.name.to_ascii_lowercase();
    validate_add_project_params(&escaped_name, &body.description, &body.github_url)?;

    let project_exists: Option<bool> =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM projects WHERE name = $1)")
            .bind(escaped_name.to_owned())
            .fetch_one(&data.db)
            .await
            .map_err(|e| {
                let error_response = serde_json::json!({
                    "status": "fail",
                    "message": format!("Database error: {}", e),
                });
                (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
            })?;

    if let Some(exists) = project_exists {
        if exists {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": "This project already exists",
            });
            return Err((StatusCode::CONFLICT, Json(error_response)));
        }
    }

    let project = sqlx::query_as!(
        Project,
        "INSERT INTO projects (name, description, github_url, user_id) VALUES ($1, $2, $3, $4) RETURNING *",
        escaped_name,
        body.description,
        body.github_url,
        user.id
    )
    .fetch_one(&data.db)
    .await
    .map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Database error: {}", e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    let project_response = serde_json::json!({"status": "success","data": serde_json::json!({
        "data": project
    })});
    Ok(Json(project_response))
}

pub async fn update_project_handler(
    Extension(user): Extension<User>,
    State(data): State<Arc<AppState>>,
    Json(body): Json<UpdateProjectSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let escaped_name = body.name.to_ascii_lowercase();
    validate_add_project_params(&escaped_name, &body.description, &body.github_url)?;

    let project_exists: Option<bool> = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM projects WHERE name = $1 AND user_id = $2)",
    )
    .bind(escaped_name.to_owned())
    .bind(user.id)
    .fetch_one(&data.db)
    .await
    .map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Database error: {}", e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    if project_exists.is_none() {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "This project does not exist",
        });
        return Err((StatusCode::NOT_FOUND, Json(error_response)));
    }

    let project = sqlx::query_as!(
        Project,
        "UPDATE projects SET name = $1, description = $2, github_url = $3 WHERE id = $4 AND user_id = $5 RETURNING *",
        escaped_name,
        body.description,
        body.github_url,
        body.id,
        user.id
    )
    .fetch_one(&data.db)
    .await
    .map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Database error: {}", e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    let project_response = serde_json::json!({"status": "success","data": serde_json::json!({
        "data": project
    })});
    Ok(Json(project_response))
}

pub async fn delete_project_handler(
    Extension(user): Extension<User>,
    State(data): State<Arc<AppState>>,
    Json(body): Json<UpdateProjectSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let project = sqlx::query_as!(
        Project,
        "DELETE FROM projects WHERE id = $1 AND user_id = $2 RETURNING *",
        body.id,
        user.id
    )
    .fetch_one(&data.db)
    .await
    .map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Database error: {}", e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    let project_response = serde_json::json!({"status": "success","data": serde_json::json!({
        "data": project
    })});
    Ok(Json(project_response))
}

// pub async fn add_revision(Extension(user): Extension<User>,
// State(data): State<Arc<AppState>>,
// body: UploadRevisionSchema){

// }

fn validate_add_project_params(
    name: &str,
    description: &str,
    github_url: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let pattern_name = Regex::new(r"^[a-z][a-z-]*[a-z]$").unwrap();
    if !pattern_name.is_match(&name) {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Invalid project name",
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }

    if name.len() < 3 || name.len() > 100 {
        let error_response = json!({
            "status": "fail",
            "message": "Project name must be between 3 and 50 characters",
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }

    if description.len() < 3 {
        let error_response = json!({
            "status": "fail",
            "message": "Project description must be greater than 3 characters",
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }

    let pattern_github = Regex::new(r"^https:\/\/github\.com\/[^\s\/?#]+$").unwrap();
    if !pattern_github.is_match(&github_url) {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Invalid github url",
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }

    Ok(())
}
