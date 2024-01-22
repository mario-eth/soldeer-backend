use std::sync::Arc;

use axum::{
    extract::{
        Multipart,
        Query,
        State,
    },
    http::StatusCode,
    response::IntoResponse,
    Extension,
    Json,
};
use regex::Regex;
use serde_json::json;
use sqlx::{
    postgres::PgArguments,
    query::QueryAs,
    Postgres,
};

use crate::{
    model::{
        CreateProjectSchema,
        FetchProjectsSchema,
        FetchRevisionsSchema,
        Project,
        Revision,
        UpdateProjectSchema,
        User,
    },
    AppState,
};

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

pub async fn upload_revision(
    Extension(user): Extension<User>,
    State(data): State<Arc<AppState>>,
    mut files: Multipart,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    println!("Uploading revision...");
    // get the name of aws bucket from env variable
    let bucket = &data.env.aws_s3_bucket;
    // if you have a public url for your bucket, place it as ENV variable BUCKET_URL
    //get the public url for aws bucket
    let aws_client = &data.aws_client;
    // we are going to store the response in HashMap as filename: url => key: value
    let mut project: Project = Project::default();
    let mut revision: String = String::new();
    let mut remote_name: String = String::new();
    while let Some(file) = files.next_field().await.unwrap() {
        let field_name = file.name().unwrap().to_string();
        if field_name == "project_id" {
            let project_id: Uuid =
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
            if project.id == Uuid::nil() {
                let error_response = serde_json::json!({
                    "status": "fail",
                    "message": "Project field was not sent correctly. The order must be project_id, revision, file",
                });
                return Err((StatusCode::NOT_FOUND, Json(error_response)));
            }
            let revision_exists: Option<bool> = sqlx
                ::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM revisions WHERE version = $1 AND project_id = $2 AND deleted = FALSE)"
                )
                .bind(revision.to_owned())
                .bind(project.id)
                .fetch_one(&data.db).await
                .map_err(|e| {
                    let error_response =
                        serde_json::json!({
                    "status": "fail",
                    "message": format!("Database error: {}", e),
                });
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
                })?;

            if revision_exists.unwrap() {
                let error_response = serde_json::json!({
                    "status": "fail",
                    "message": "This revision already exists",
                });
                return Err((StatusCode::NOT_FOUND, Json(error_response)));
            }
            continue;
        }
        // this is the name which is sent in formdata from frontend or whoever called the api, i am
        // using it as category, we can get the filename from file data
        // get the project from database

        // name of the file with extension
        let name = file.file_name().unwrap().to_string();

        // checks if it's a zip file
        if file.content_type().unwrap() != "application/zip" {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": "The revision is not a zip",
            });
            return Err((StatusCode::NOT_FOUND, Json(error_response)));
        }
        let revision_name = revision.replace(".", "_");
        println!("Revision ready to upload to aws s3 {} {}", &project.name, &revision_name);
        // file data
        let data = file.bytes().await.unwrap();
        // the path of file to store on aws s3 with file name and extension
        remote_name = format!(
            "{}/{}_{}_{}",
            &project.name,
            &revision_name,
            chrono::Utc::now().format("%d-%m-%Y_%H:%M:%S"),
            &name.replace(" ", "_")
        );

        // send Putobject request to aws s3
        let _resp = aws_client
            .put_object()
            .bucket(bucket)
            .key(&remote_name)
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
    }
    let inserted_revision = sqlx
        ::query_as!(
            Revision,
            "INSERT INTO revisions (version, internal_name, url, project_id) VALUES ($1, $2, $3, $4) RETURNING *",
            &revision,
            &remote_name,
            data.env.aws_bucket_url.to_owned()+remote_name.as_str(),
            project.id
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

    let revision_response = serde_json::json!({"status": "success","data": serde_json::json!({
        "data": inserted_revision
    })});
    Ok(Json(revision_response))
}

pub async fn get_projects(
    State(data): State<Arc<AppState>>,
    Query(params): Query<FetchProjectsSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let query: QueryAs<'_, Postgres, Project, PgArguments>;
    if params.project_id.is_some() {
        query = sqlx::query_as("SELECT * FROM projects WHERE id = $1 AND deleted = FALSE")
            .bind(params.project_id.unwrap());
    } else if params.project_name.is_some() {
        query = sqlx::query_as("SELECT * FROM projects WHERE name = $1 AND deleted = FALSE")
            .bind(params.project_name.unwrap());
    } else {
        if params.user_id.is_none() {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": "User id is required",
            });
            return Err((StatusCode::BAD_REQUEST, Json(error_response)));
        }
        query = sqlx::query_as("SELECT * FROM projects WHERE user_id = $1 AND deleted = FALSE")
            .bind(params.user_id.unwrap());
    }
    let projects: Vec<Project> = query
        .fetch_all(&data.db)
        .await
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": format!("Database error: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?
        .iter()
        .map(|project| {
            Project {
                id: project.id,
                name: project.name.clone(),
                description: project.description.clone(),
                github_url: project.github_url.clone(),
                user_id: project.user_id,
                deleted: project.deleted,
                created_at: project.created_at,
                updated_at: project.updated_at,
            }
        })
        .collect();

    let project_response = serde_json::json!({"status": "success","data": projects
    });
    Ok(Json(project_response))
}

pub async fn get_project_revisions(
    State(data): State<Arc<AppState>>,
    Query(params): Query<FetchRevisionsSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let query: QueryAs<'_, Postgres, Revision, PgArguments>;
    println!("params: {:?}", params);
    let project: Project;
    if params.project_name.is_some() {
        project = sqlx::query_as!(
            Project,
            "SELECT * FROM projects WHERE name = $1 AND deleted = FALSE",
            params.project_name.as_ref().unwrap(),
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
    } else if params.project_id.is_some() {
        project = sqlx::query_as!(
            Project,
            "SELECT * FROM projects WHERE id = $1 AND deleted = FALSE",
            params.project_id.unwrap(),
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
    } else {
        project = Project::default();
    }

    println!("project: {:?}", project);

    if params.revision.is_some() {
        query = sqlx::query_as(
            "SELECT * FROM revisions WHERE project_id = $1 AND version = $2 AND deleted = FALSE",
        )
        .bind(project.id)
        .bind(params.revision.unwrap());
    } else if params.project_name.is_some() {
        query = sqlx::query_as("SELECT * FROM revisions WHERE project_id = $1 AND deleted = FALSE")
            .bind(project.id);
    } else if params.revision_id.is_some() {
        query = sqlx::query_as("SELECT * FROM revisions WHERE id = $1 AND deleted = FALSE")
            .bind(params.project_id.unwrap());
    } else {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Project id or name is required",
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }
    let revisions: Vec<Revision> = query
        .fetch_all(&data.db)
        .await
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": format!("Database error: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?
        .iter()
        .map(|revision| {
            Revision {
                id: revision.id,
                version: revision.version.clone(),
                internal_name: revision.internal_name.clone(),
                url: revision.url.clone(),
                project_id: revision.project_id,
                deleted: revision.deleted,
                created_at: revision.created_at,
            }
        })
        .collect();
    println!("revisions: {:?}", revisions);
    let revision_response = serde_json::json!({"status": "success","data": revisions});
    Ok(Json(revision_response))
}

fn validate_add_project_params(
    name: &str,
    description: &str,
    github_url: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let pattern_name = Regex::new(r"^[@|a-z][a-z0-9-]*[a-z]$").unwrap();
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
