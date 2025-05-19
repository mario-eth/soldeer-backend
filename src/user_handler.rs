use std::sync::Arc;

use argon2::{
    password_hash::SaltString,
    Argon2,
    PasswordHash,
    PasswordHasher,
    PasswordVerifier,
};
use aws_config::BehaviorVersion;
use axum::{
    extract::{
        Query,
        State,
    },
    http::{
        header,
        Response,
        StatusCode,
    },
    response::IntoResponse,
    Extension,
    Json,
};
use axum_extra::extract::cookie::{
    Cookie,
    SameSite,
};
use email_address_parser::{
    EmailAddress,
    ParsingOptions,
};
use jsonwebtoken::{
    encode,
    EncodingKey,
    Header,
};
use passwords::analyzer;
use rand_core::OsRng;
use serde_json::json;
use std::str::FromStr;

use crate::utils::{
    ORGANIZATION_NAME_PATTERN,
    USERNAME_PATTERN,
};
use crate::{
    model::{
        AddUserToOrganizationSchema,
        GetLastCodeSchema,
        GithubCallbackSchema,
        LoginUserSchema,
        Organization,
        RegisterUserSchema,
        RequestPasswordSchema,
        ResetPasswordSchema,
        Role,
        TokenClaims,
        UpdateOrganizationSchema,
        UpdateUserPasswordSchema,
        UpdateUsernameSchema,
        User,
        Verification,
        VerificationType,
        VerifyEmailSchema,
    },
    response::FilteredUser,
    AppState,
};
use aws_sdk_sesv2::types::{
    Body,
    Content,
    Destination,
    EmailContent,
    Message,
};
use aws_sdk_sesv2::{
    Client,
    Error,
};

pub async fn health_checker_handler() -> impl IntoResponse {
    const MESSAGE: &str = "Healthy!";

    let json_response = serde_json::json!({
        "status": "success",
        "message": MESSAGE
    });

    Json(json_response)
}

pub async fn register_user_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<RegisterUserSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let escaped_email: String = body
        .email
        .to_owned()
        .to_ascii_lowercase()
        .trim()
        .to_string();
    validate_login_params(&escaped_email, &body.password)?;
    let user_exists: Option<bool> =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
            .bind(escaped_email.to_owned())
            .fetch_one(&data.db)
            .await
            .map_err(|e| {
                println!("Error checking if user exists: {e:?}");
                let error_response = serde_json::json!({
                    "status": "fail",
                    "message": "Error checking if user exists",
                });
                (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
            })?;

    if let Some(exists) = user_exists {
        if exists {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": "Unexpected error, please try",
            });
            return Err((StatusCode::CONFLICT, Json(error_response)));
        }
    }

    let escaped_username: String = body.username.to_owned().trim().to_string();
    validate_username(&escaped_username)?;

    let escaped_organization_name: String = body.organization_name.to_owned().trim().to_string();

    sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)",
        escaped_username
    )
    .fetch_one(&data.db)
    .await
    .map_err(|e| {
        println!("Error checking username: {e:?}");
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Error, this username is already taken",
        });
        (StatusCode::BAD_REQUEST, Json(error_response))
    })?;

    let user = register_user_db(
        Some(body.password.clone().to_string()),
        &escaped_email,
        &escaped_username,
        &escaped_organization_name,
        None,
        None,
        None,
        false,
        &Role::Owner.to_string(),
        &data.db,
    )
    .await?;

    println!("sending email");
    let _ = send_verification_email(&user, &data.env.url_front, &data.db).await;

    let user_response = serde_json::json!({"status": "success","data": serde_json::json!({
        "user": filter_user_record(&user)
    })});

    Ok(Json(user_response))
}

pub async fn login_user_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<LoginUserSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let escaped_email: String = body
        .email
        .to_owned()
        .to_ascii_lowercase()
        .trim()
        .to_string();
    validate_login_params(&escaped_email, &body.password)?;
    let user = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE email = $1 AND verified = true",
        body.email.to_ascii_lowercase()
    )
    .fetch_optional(&data.db)
    .await
    .map_err(|e| {
        println!("Error fetching user: {e:?}");
        let error_response = serde_json::json!({
            "status": "error",
            "message": "Error user not found or not verified",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?
    .ok_or_else(|| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Invalid email or password",
        });
        (StatusCode::UNAUTHORIZED, Json(error_response))
    })?;

    let is_valid = match PasswordHash::new(&user.password) {
        Ok(parsed_hash) => {
            Argon2::default()
                .verify_password(body.password.as_bytes(), &parsed_hash)
                .is_ok_and(|_| true)
        }
        Err(_) => false,
    };

    if !is_valid {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Invalid email or password"
        });
        return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
    }

    let cookie = generate_token(
        user.id.to_string(),
        &data.env.jwt_secret,
        &data.env.jwt_expires_in,
    );

    let mut response =
        Response::new(json!({"status": "success", "token": cookie.value()}).to_string());
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie.to_string().parse().unwrap());
    Ok(response)
}

pub async fn logout_handler() -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let cookie = Cookie::build(("token", ""))
        .path("/")
        .max_age(time::Duration::hours(-1))
        .same_site(SameSite::Lax)
        .http_only(true);

    let mut response = Response::new(json!({"status": "success"}).to_string());
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie.to_string().parse().unwrap());
    Ok(response)
}

pub async fn get_me_handler(
    Extension(user): Extension<User>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let json_response = serde_json::json!({
        "status":  "success",
        "data": serde_json::json!({
            "user": filter_user_record(&user)
        })
    });

    Ok(Json(json_response))
}

pub async fn verify_account_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<VerifyEmailSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    if body.code.is_nil() {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Invalid code",
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }
    let verification = sqlx::query_as!(
        Verification,
        "SELECT * FROM verifications WHERE id = $1 AND verification_type = $2",
        body.code,
        VerificationType::Register.to_string()
    )
    .fetch_optional(&data.db)
    .await
    .map_err(|e| {
        println!("Error fetching verification code: {e:?}");
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Error verifying the account",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?
    .ok_or_else(|| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Invalid token",
        });
        (StatusCode::UNAUTHORIZED, Json(error_response))
    })?;

    if verification.used.is_some() && verification.used.unwrap() {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Token has already been used",
        });
        return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
    }

    let _ = sqlx::query_as!(
        User,
        "UPDATE users SET verified = true WHERE id = $1 RETURNING *",
        verification.user_id
    )
    .fetch_one(&data.db)
    .await
    .map_err(|e| {
        println!("Error updating user: {e:?}");
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Error verifying the account",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    let _ = sqlx::query!(
        "UPDATE verifications SET used = true WHERE id = $1 RETURNING *",
        body.code
    )
    .fetch_one(&data.db)
    .await
    .map_err(|e| {
        println!("Error updating verification on verify account: {e:?}");
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Error verifying the account",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    let json_response = serde_json::json!({
        "status": "success",
        "data": ""
    });

    Ok(Json(json_response))
}

pub async fn update_user_password_handler(
    Extension(user): Extension<User>,
    State(data): State<Arc<AppState>>,
    Json(body): Json<UpdateUserPasswordSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    if body.password != body.repeat_password {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Passwords do not match",
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }
    let is_valid = match PasswordHash::new(&user.password) {
        Ok(parsed_hash) => {
            Argon2::default()
                .verify_password(body.current_password.as_bytes(), &parsed_hash)
                .is_ok_and(|_| true)
        }
        Err(_) => false,
    };

    if !is_valid {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Invalid current password"
        });
        return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
    }

    validate_password(&body.password)?;
    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": format!("Error while hashing password: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })
        .map(|hash| hash.to_string())?;
    let user = sqlx::query_as!(
        User,
        "UPDATE users SET password = $1 WHERE id = $2 RETURNING *",
        hashed_password,
        user.id
    )
    .fetch_one(&data.db)
    .await
    .map_err(|e| {
        println!("Error updating user: {e:?}");
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Error updating user",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    if user.id.is_nil() {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "User could not be updated",
        });
        return Err((StatusCode::NOT_FOUND, Json(error_response)));
    }
    let user_response = serde_json::json!({"status": "success","data": serde_json::json!({
        "data": "{}"
    })});
    Ok(Json(user_response))
}

pub async fn update_username_handler(
    Extension(user): Extension<User>,
    State(data): State<Arc<AppState>>,
    Json(body): Json<UpdateUsernameSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let escaped_username: String = body.username.to_owned().trim().to_string();
    validate_username(&escaped_username)?;
    sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)",
        escaped_username
    )
    .fetch_one(&data.db)
    .await
    .map_err(|e| {
        println!("Error checking username: {e:?}");
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Error, this username is already taken",
        });
        (StatusCode::BAD_REQUEST, Json(error_response))
    })?;

    sqlx::query_as!(
        User,
        "UPDATE users SET username = $1 WHERE id = $2 RETURNING *",
        escaped_username,
        user.id
    )
    .fetch_one(&data.db)
    .await
    .map_err(|e| {
        println!("Error updating user: {e:?}");
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Error updating user",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    let user_response = serde_json::json!({"status": "success","data": serde_json::json!({
        "data": "{}"
    })});
    Ok(Json(user_response))
}

pub async fn update_organization_handler(
    Extension(user): Extension<User>,
    State(data): State<Arc<AppState>>,
    Json(body): Json<UpdateOrganizationSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    body.validate()?;

    let escaped_name: String = body.name.to_owned().trim().to_string();

    if user.role != Role::Owner.to_string() {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "You are not the owner of the organization",
        });
        return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
    }

    let organization = sqlx::query_as!(
        Organization,
        "UPDATE organizations SET name = $1, description = $2 WHERE id = $3 RETURNING *",
        escaped_name,
        body.description,
        user.organization_id
    )
    .fetch_one(&data.db)
    .await
    .map_err(|e| {
        println!("Error updating organization: {e:?}");
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Error updating organization",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;
    let organization_response = serde_json::json!({"status": "success","data": serde_json::json!({
        "data": organization
    })});
    Ok(Json(organization_response))
}

pub async fn send_verification_email(
    user: &User,
    base_url: &str,
    db: &sqlx::Pool<sqlx::Postgres>,
) -> Result<(), Error> {
    let email = user.email.to_owned();

    let verification = sqlx::query_as!(
        Verification,
        "INSERT INTO verifications (used, user_id, verification_type) VALUES (false, $1, $2) RETURNING *",
        user.id,
        VerificationType::Register.to_string()
    )
    .fetch_one(db)
    .await
    .map_err(|e| {
        println!("Error inserting verification: {e:?}");
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Error creating verification code",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })
    .unwrap();

    let verification_link = format!("https://{}/verify?token={}", base_url, verification.id);

    let mut dest: Destination = Destination::builder().build();
    dest.to_addresses = Some(vec![email]);
    let message = format!(
        "Hello, \n Please verify your email by clicking on this link: <a href=\"{verification_link}\">{verification_link}</a>",
    );
    let subject_content = Content::builder()
        .data("Email verification".to_owned())
        .charset("UTF-8")
        .build()
        .expect("building Content");
    let body_content = Content::builder()
        .data(message)
        .charset("UTF-8")
        .build()
        .expect("building Content");
    let body = Body::builder().html(body_content).build();
    let msg = Message::builder()
        .subject(subject_content)
        .body(body)
        .build();
    let aws_configuration: aws_config::SdkConfig =
        aws_config::load_defaults(BehaviorVersion::v2024_03_28()).await;
    let email_content = EmailContent::builder().simple(msg).build();
    let client = Client::new(&aws_configuration);
    let response = client
        .send_email()
        .from_email_address("no-reply@soldeer.xyz")
        .destination(dest)
        .content(email_content)
        .send()
        .await;
    if response.is_err() {
        println!("Error sending email: {:?}", response.err());
    }

    Ok(())
}

pub async fn request_new_password_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<RequestPasswordSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let escaped_email: String = body
        .email
        .to_owned()
        .to_ascii_lowercase()
        .trim()
        .to_string();

    let user = sqlx::query_as!(User, "SELECT * FROM users WHERE email = $1", escaped_email)
        .fetch_optional(&data.db)
        .await
        .map_err(|e| {
            println!("Error fetching user: {e:?}");
            let error_response = serde_json::json!({
                "status": "fail",
                "message": "Unknown error",
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?
        .ok_or_else(|| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": "Unknown error",
            });
            (StatusCode::UNAUTHORIZED, Json(error_response))
        })?;

    let _ = send_request_new_password_email(&user, &data.env.url_front, &data.db).await;

    let json_response = serde_json::json!({
        "status": "success",
        "data": ""
    });

    Ok(Json(json_response))
}

pub async fn github_login_handler(
    State(data): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let client_id = data.env.github_client_id.clone();
    let redirect_uri = data.env.github_redirect_uri.clone();

    let github_auth_url = format!(
        "https://github.com/login/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&scope=user:email",
    );

    let json_response = serde_json::json!({
        "status": "success",
        "data": serde_json::json!({
            "url": github_auth_url
        })
    });

    Ok(Json(json_response))
}

pub async fn github_callback_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<GithubCallbackSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let client_id = data.env.github_client_id.clone();
    let client_secret = data.env.github_client_secret.clone();

    let access_token = match exchange_code_for_token(&body.code, &client_id, &client_secret).await {
        Ok(token) => token,
        Err(e) => return Err(e),
    };

    let (github_id, primary_email, username) = match get_github_data(access_token.as_str()).await {
        Ok(data) => data,
        Err(e) => return Err(e),
    };

    let user_existence =
        match check_login_or_register(&primary_email, &github_id, &username, &data.db).await {
            Ok(existence) => existence,
            Err(e) => {
                let error_response = serde_json::json!({
                    "status": "fail",
                    "message": format!("Failed to check or register user: {}", e)
                });
                return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)));
            }
        };

    if let Some(user) = user_existence {
        let cookie = generate_token(
            user.id.to_string(),
            &data.env.jwt_secret,
            &data.env.jwt_expires_in,
        );
        let mut response =
            Response::new(json!({"status": "success", "token": cookie.value()}).to_string());
        response
            .headers_mut()
            .insert(header::SET_COOKIE, cookie.to_string().parse().unwrap());

        Ok(response)
    } else {
        let user = register_user_db(
            None,
            &primary_email,
            &username,
            &format!("Default Organization for {username}"),
            None,
            Some(github_id),
            Some(username.clone()),
            true,
            &Role::Owner.to_string(),
            &data.db,
        )
        .await?;

        let response = Response::new(
            json!({"status": "success", "data": serde_json::json!({
                "user": filter_user_record(&user)
            })})
            .to_string(),
        );

        Ok(response)
    }
}

pub async fn add_user_to_organization_handler(
    Extension(user): Extension<User>,
    State(data): State<Arc<AppState>>,
    Json(body): Json<AddUserToOrganizationSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    if user.role != Role::Owner.to_string() && user.role != Role::Admin.to_string() {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "You are not allowed to perform this action",
        });
        return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
    }

    let organization = sqlx::query_as!(
        Organization,
        "SELECT * FROM organizations WHERE id = $1",
        user.organization_id
    )
    .fetch_one(&data.db)
    .await
    .map_err(|e| {
        println!("Error fetching organization: {e:?}");
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Error fetching organization",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    let escaped_email: String = body
        .email
        .to_owned()
        .to_ascii_lowercase()
        .trim()
        .to_string();
    validate_login_params(&escaped_email, &body.password)?;

    let escaped_username: String = body.username.to_owned().trim().to_string();
    validate_username(&escaped_username)?;

    let user_exists: Option<bool> =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
            .bind(escaped_email.to_owned())
            .fetch_one(&data.db)
            .await
            .map_err(|e| {
                println!("Error checking if user exists: {e:?}");
                let error_response = serde_json::json!({
                    "status": "fail",
                    "message": "Error checking if user exists",
                });
                (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
            })?;

    if let Some(exists) = user_exists {
        if exists {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": "Unexpected error, please try again",
            });
            return Err((StatusCode::CONFLICT, Json(error_response)));
        }
    }

    let new_user = register_user_db(
        Some(body.password.clone().to_string()),
        &escaped_email,
        &escaped_username,
        &organization.name,
        Some(organization.id),
        None,
        None,
        true,
        &body.role.to_string(),
        &data.db,
    )
    .await?;

    let json_response = serde_json::json!({
        "status": "success",
        "data": serde_json::json!({
            "user": filter_user_record(&new_user)
        })
    });
    Ok(Json(json_response))
}

pub async fn send_request_new_password_email(
    user: &User,
    base_url: &str,
    db: &sqlx::Pool<sqlx::Postgres>,
) -> Result<(), Error> {
    let email = user.email.to_owned();

    let verification = sqlx::query_as!(
        Verification,
        "INSERT INTO verifications (used, user_id, verification_type) VALUES (false, $1, $2) RETURNING *",
        user.id,
        VerificationType::Password.to_string()
    )
    .fetch_one(db)
    .await
    .map_err(|e| {
        println!("Error inserting verification: {e:?}");
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Error creating verification code",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })
    .unwrap();

    let verification_link = format!(
        "https://{}/reset-password?token={}",
        base_url, verification.id
    );

    let mut dest: Destination = Destination::builder().build();
    dest.to_addresses = Some(vec![email]);
    let message = format!(
        "Hello, \n You requested a new password, please use the following link to set a new password <a href=\"{verification_link}\">{verification_link}</a>",
    );
    let subject_content = Content::builder()
        .data("Email verification".to_owned())
        .charset("UTF-8")
        .build()
        .expect("building Content");
    let body_content = Content::builder()
        .data(message)
        .charset("UTF-8")
        .build()
        .expect("building Content");
    let body = Body::builder().html(body_content).build();
    let msg = Message::builder()
        .subject(subject_content)
        .body(body)
        .build();
    let aws_configuration: aws_config::SdkConfig =
        aws_config::load_defaults(BehaviorVersion::v2024_03_28()).await;
    let email_content = EmailContent::builder().simple(msg).build();
    let client = Client::new(&aws_configuration);
    let response = client
        .send_email()
        .from_email_address("no-reply@soldeer.xyz")
        .destination(dest)
        .content(email_content)
        .send()
        .await;
    if response.is_err() {
        println!("Error sending email: {:?}", response.err());
    }

    Ok(())
}

pub async fn reset_password_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<ResetPasswordSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    if body.password != body.repeat_password {
        let error_response = serde_json::json!({
        "status": "fail",
        "message": "Passwords do not match",
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }

    let verification = sqlx::query_as!(
        Verification,
        "SELECT * FROM verifications WHERE id = $1 AND verification_type = $2",
        body.code,
        VerificationType::Password.to_string()
    )
    .fetch_optional(&data.db)
    .await
    .map_err(|e| {
        println!("Error fetching verification code: {e:?}");
        let error_response = serde_json::json!({
        "status": "fail",
        "message": "Error verifying the account",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?
    .ok_or_else(|| {
        let error_response = serde_json::json!({
        "status": "fail",
        "message": "Invalid token",
        });
        (StatusCode::UNAUTHORIZED, Json(error_response))
    })?;

    if verification.used.is_some() && verification.used.unwrap() {
        let error_response = serde_json::json!({
        "status": "fail",
        "message": "Token has already been used",
        });
        return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
    }

    validate_password(&body.password)?;
    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": format!("Error while hashing password: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })
        .map(|hash| hash.to_string())?;

    let _user = sqlx::query_as!(
        User,
        "UPDATE users SET password = $1 WHERE id = $2 RETURNING *",
        hashed_password,
        verification.user_id
    )
    .fetch_one(&data.db)
    .await
    .map_err(|e| {
        println!("Error updating user: {e:?}");
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Error updating user",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    let _ = sqlx::query_as!(
        Verification,
        "UPDATE verifications SET used = true WHERE id = $1 RETURNING *",
        body.code
    )
    .fetch_one(&data.db)
    .await
    .map_err(|e| {
        println!("Error updating verification on reset password: {e:?}");
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Error verifying the account",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    let json_response = serde_json::json!({
        "status": "success",
        "data": "Password updated"
    });
    Ok(Json(json_response))
}

fn filter_user_record(user: &User) -> FilteredUser {
    FilteredUser {
        id: user.id.to_string(),
        email: user.email.to_owned(),
        role: user.role.to_owned(),
        verified: user.verified,
        createdAt: user.created_at.unwrap(),
        updatedAt: user.updated_at.unwrap(),
    }
}

fn validate_login_params(
    email: &str,
    password: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let email: Option<EmailAddress> = EmailAddress::parse(email, Some(ParsingOptions::default()));

    if email.is_none() {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Email is invalid",
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }

    validate_password(password)?;
    Ok(())
}

pub fn validate_password(password: &str) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let analyzed = analyzer::analyze(password);
    if analyzed.length() < 8
        || analyzed.symbols_count() < 1
        || analyzed.numbers_count() < 1
        || analyzed.uppercase_letters_count() < 1
    {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Password is too weak. Must contain 1 non-alphanumeric character, 1 upper letter, 1 number and be at least 8 characters long",
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }

    Ok(())
}

async fn exchange_code_for_token(
    code: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    // Exchange code for access token
    let token_url = "https://github.com/login/oauth/access_token";
    let client = reqwest::Client::new();

    let token_response = client
        .post(token_url)
        .header("Accept", "application/json")
        .form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code", code),
        ])
        .send()
        .await
        .map_err(|e| {
            println!("Error getting GitHub token: {e:?}");
            let error_response = serde_json::json!({
                "status": "fail",
                "message": "Failed to get GitHub token"
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;

    let token_data: serde_json::Value = token_response.json().await.map_err(|e| {
        println!("Error parsing token response: {e:?}");
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Failed to parse GitHub response"
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    let access_token = token_data["access_token"].as_str().ok_or_else(|| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "No access token in GitHub response"
        });
        (StatusCode::BAD_REQUEST, Json(error_response))
    })?;

    Ok(access_token.to_string())
}

async fn get_github_data(
    access_token: &str,
) -> Result<(String, String, String), (StatusCode, Json<serde_json::Value>)> {
    let client = reqwest::Client::new();
    // Get user data from GitHub
    let user_response = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {access_token}"))
        .header("User-Agent", "Soldeer")
        .send()
        .await
        .map_err(|e| {
            println!("Error getting GitHub user data: {e:?}");
            let error_response = serde_json::json!({
                "status": "fail",
                "message": "Failed to get GitHub user data"
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;

    let user_data: serde_json::Value = user_response.json().await.map_err(|e| {
        println!("Error parsing user data: {e:?}");
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Failed to parse GitHub user data"
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    // Get user email from GitHub
    let email_response = client
        .get("https://api.github.com/user/emails")
        .header("Authorization", format!("Bearer {access_token}"))
        .header("User-Agent", "Soldeer-App")
        .send()
        .await
        .map_err(|e| {
            println!("Error getting GitHub email: {e:?}");
            let error_response = serde_json::json!({
                "status": "fail",
                "message": "Failed to get GitHub email"
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;

    let email_data: Vec<serde_json::Value> = email_response.json().await.map_err(|e| {
        println!("Error parsing email data: {e:?}");
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Failed to parse GitHub email data"
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    let primary_email = email_data
        .iter()
        .find(|email| email["primary"].as_bool().unwrap_or(false))
        .and_then(|email| email["email"].as_str())
        .ok_or_else(|| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": "No primary email found"
            });
            (StatusCode::BAD_REQUEST, Json(error_response))
        })?;

    let github_id = user_data["id"].as_i64().ok_or_else(|| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "No GitHub ID found"
        });
        (StatusCode::BAD_REQUEST, Json(error_response))
    })?;

    let username = user_data["login"].as_str().ok_or_else(|| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "No GitHub username found"
        });
        (StatusCode::BAD_REQUEST, Json(error_response))
    })?;

    Ok((
        github_id.to_string(),
        primary_email.to_string(),
        username.to_string(),
    ))
}

fn generate_token<'a>(id: String, jwt_secret: &str, jwt_expires_in: &str) -> Cookie<'a> {
    let now: chrono::prelude::DateTime<chrono::prelude::Utc> = chrono::Utc::now();
    let iat: usize = now.timestamp() as usize;
    let exp: usize = (now + chrono::Duration::minutes(i64::from_str(jwt_expires_in).unwrap()))
        .timestamp() as usize;
    let claims: TokenClaims = TokenClaims { sub: id, exp, iat };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    )
    .unwrap();

    Cookie::build(("token", token.to_owned()))
        .path("/")
        .max_age(time::Duration::hours(1))
        .same_site(SameSite::Lax)
        .http_only(true)
        .build()
}

async fn check_login_or_register(
    email: &str,
    github_id: &str,
    username: &str,
    db: &sqlx::Pool<sqlx::Postgres>,
) -> Result<Option<User>, Error> {
    let user_results = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE email = $1 OR github_id = $2",
        email,
        github_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| {
        println!("Error fetching user on github login: {e:?}");
        let error_response = serde_json::json!({
        "status": "fail",
        "message": "Error fetching the user",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    });
    let user = user_results.unwrap_or(None);
    if user.is_some() && user.as_ref().unwrap().github_id.is_none() {
        let _=  sqlx::query_as!(
            User,
            "UPDATE users SET github_id = $1, github_username = $2, verified = true WHERE id = $3 RETURNING *",
            github_id,
            username,
            &user.as_ref().unwrap().id
        )
        .fetch_one(db)
        .await;
    }
    Ok(user)
}

async fn register_user_db(
    password: Option<String>,
    email: &str,
    username: &str,
    organization_name: &str,
    mut organization_id: Option<uuid::Uuid>,
    github_id: Option<String>,
    github_username: Option<String>,
    verified: bool,
    role: &str,
    db: &sqlx::Pool<sqlx::Postgres>,
) -> Result<User, (StatusCode, Json<serde_json::Value>)> {
    validate_organization_params(organization_name, "No Description")?;

    if organization_id.is_none() {
        let organization = sqlx::query_as!(
            Organization,
            "INSERT INTO organizations (name) VALUES ($1) RETURNING *",
            organization_name
        )
        .fetch_one(db)
        .await
        .map_err(|e| {
            println!("Error inserting organization: {e:?}");
            let error_response = serde_json::json!({
                "status": "fail",
                "message": "Error creating organization",
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;
        organization_id = Some(organization.id);
    }

    let salt = SaltString::generate(&mut OsRng);
    let normalized_password = match password {
        Some(password) => password,
        None => SaltString::generate(&mut OsRng).as_str().to_string(),
    };
    let hashed_password = Argon2::default()
        .hash_password(normalized_password.as_bytes(), &salt)
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": format!("Error while hashing password: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })
        .map(|hash| hash.to_string())?;

    let user = sqlx::query_as!(
        User,
        "INSERT INTO users (email,password,username,role,github_id,github_username,verified, organization_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *",
        email,
        hashed_password,
        username,
        role,
        github_id,
        github_username,
        verified,
        organization_id.unwrap()
    )
    .fetch_one(db)
    .await
    .map_err(|e| {
        println!("Error inserting user: {e:?}");
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Error creating user",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    Ok(user)
}

pub fn validate_organization_params(
    name: &str,
    description: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if name.len() < 3 {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Organization name must be at least 3 characters",
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }

    if description.len() < 3 {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Organization description must be at least 3 characters",
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }

    let pattern_name = regex::Regex::new(ORGANIZATION_NAME_PATTERN).unwrap();
    if !pattern_name.is_match(&name.to_ascii_lowercase()) {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Invalid organization name format",
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }

    Ok(())
}

pub fn validate_username(username: &str) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if username.len() < 3 {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Username must be at least 3 characters",
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }
    let pattern_name = regex::Regex::new(USERNAME_PATTERN).unwrap();
    if !pattern_name.is_match(&username.to_ascii_lowercase()) {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Invalid username format",
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }
    Ok(())
}

#[allow(dead_code)]
pub async fn get_last_code_handler(
    State(data): State<Arc<AppState>>,
    Query(params): Query<GetLastCodeSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let verification = sqlx::query_as!(
        Verification,
        "SELECT * FROM verifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1",
        params.user_id
    )
    .fetch_optional(&data.db)
    .await
    .map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Database error: {e:?}"),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?
    .ok_or_else(|| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "No verification code found",
        });
        (StatusCode::NOT_FOUND, Json(error_response))
    })?;

    let json_response = serde_json::json!({
        "status": "success",
        "data": serde_json::json!({
            "code": verification.id.to_string()
        })
    });

    Ok(Json(json_response))
}
