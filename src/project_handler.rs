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
        User,
    },
    AppState,
};

use std::collections::HashMap;

use uuid::Uuid;

pub async fn add_project_handler(
    Extension(user): Extension<User>,
    State(data): State<Arc<AppState>>,
    Json(body): Json<CreateProjectSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let escaped_name = body.name.to_ascii_lowercase();
    validate_add_project_params(&escaped_name, &body.description, &body.github_url)?;

    let project_exists: Option<bool> = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM projects WHERE name = $1 AND deleted = FALSE)",
    )
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

    let project = sqlx
        ::query_as!(
            Project,
            "INSERT INTO projects (name, description, github_url, user_id) VALUES ($1, $2, $3, $4) RETURNING *",
            escaped_name,
            body.description,
            body.github_url,
            user.id
        )
        .fetch_one(&data.db).await
        .map_err(|e| {
            let error_response =
                serde_json::json!({
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

    let project_exists: Option<bool> = sqlx
        ::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM projects WHERE name = $1 AND user_id = $2 AND deleted = FALSE)"
        )
        .bind(escaped_name.to_owned())
        .bind(user.id)
        .fetch_one(&data.db).await
        .map_err(|e| {
            let error_response =
                serde_json::json!({
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
        .fetch_one(&data.db).await
        .map_err(|e| {
            let error_response =
                serde_json::json!({
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
            "UPDATE projects SET deleted = TRUE WHERE id = $1 AND user_id = $2 AND deleted = FALSE RETURNING *",
            body.id,
            user.id
        )
        .fetch_one(&data.db).await
        .map_err(|e| {
            let error_response =
                serde_json::json!({
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

pub async fn upload_revision(
    Extension(user): Extension<User>,
    State(data): State<Arc<AppState>>,
    mut files: Multipart,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    // TODO check if revision was already uploaded
    // TODO add revision in the db
    // Check if file is zip only and add a restriction on the max file size

    // get the name of aws bucket from env variable
    let bucket = &data.env.aws_s3_bucket;
    // if you have a public url for your bucket, place it as ENV variable BUCKET_URL
    //get the public url for aws bucket
    let aws_client = &data.aws_client;
    // we are going to store the response in HashMap as filename: url => key: value
    let mut res = HashMap::new();
    let mut project: Project = Project::default();
    let mut revision: String = String::new();
    while let Some(file) = files.next_field().await.unwrap() {
        let field_name = file.name().unwrap().to_string();
        if field_name == "project_id" {
            let project_id =
                Uuid::parse_str(std::str::from_utf8(file.bytes().await.unwrap().as_ref()).unwrap())
                    .unwrap();
            project = sqlx::query_as!(
                Project,
                "SELECT * FROM projects WHERE id = $1 AND user_id = $2 AND deleted = FALSE",
                project_id,
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
            continue;
        } else if field_name == "revision" {
            revision = std::str::from_utf8(file.bytes().await.unwrap().as_ref())
                .unwrap()
                .to_string();
            continue;
        }
        // this is the name which is sent in formdata from frontend or whoever called the api, i am
        // using it as category, we can get the filename from file data
        // get the project from database

        // name of the file with extension
        let name = file.file_name().unwrap().to_string();
        // file data
        let data = file.bytes().await.unwrap();
        // the path of file to store on aws s3 with file name and extension
        let key = format!(
            "{}/{}_{}_{}",
            project.name.replace("-", "_"),
            revision.replace(".", "_"),
            chrono::Utc::now().format("%d-%m-%Y_%H:%M:%S"),
            &name.replace(" ", "_")
        );

        // send Putobject request to aws s3
        let _resp = aws_client
            .put_object()
            .bucket(bucket)
            .key(&key)
            .body(data.into())
            .send()
            .await
            .map_err(|err| {
                dbg!(err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"err": "an error ocurred during image upload"})),
                )
            })?;
        res.insert(
            // concatenating name and category so even if the filenames are same it will not
            // conflict
            "result", "success",
        );
    }
    // send the urls in response
    Ok(Json(serde_json::json!(res)))
}

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

    let pattern_github = Regex::new(r"^https:\/\/github\.com\/[^\s?#]+(?:\/[^\s?#]+)*$").unwrap();
    if !pattern_github.is_match(&github_url) {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Invalid github url",
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }

    Ok(())
}
