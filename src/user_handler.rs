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

use crate::{
    model::{
        GetLastCodeSchema,
        LoginUserSchema,
        RegisterUserSchema,
        RequestPasswordSchema,
        ResetPasswordSchema,
        Role,
        TokenClaims,
        UpdateUserSchema,
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
                println!("Error checking if user exists: {:?}", e);
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
                "message": "User with that email already exists",
            });
            return Err((StatusCode::CONFLICT, Json(error_response)));
        }
    }

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
        "INSERT INTO users (email,password,role) VALUES ($1, $2, $3) RETURNING *",
        escaped_email,
        hashed_password,
        Role::User.to_string()
    )
    .fetch_one(&data.db)
    .await
    .map_err(|e| {
        println!("Error inserting user: {:?}", e);
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Error creating user",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

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
        println!("Error fetching user: {:?}", e);
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
                .map_or(false, |_| true)
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

    let now: chrono::prelude::DateTime<chrono::prelude::Utc> = chrono::Utc::now();
    let iat: usize = now.timestamp() as usize;
    let exp: usize = (now
        + chrono::Duration::minutes(i64::from_str(&data.env.jwt_expires_in).unwrap()))
    .timestamp() as usize;
    let claims: TokenClaims = TokenClaims {
        sub: user.id.to_string(),
        exp,
        iat,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(data.env.jwt_secret.as_ref()),
    )
    .unwrap();

    let cookie = Cookie::build(("token", token.to_owned()))
        .path("/")
        .max_age(time::Duration::hours(1))
        .same_site(SameSite::Lax)
        .http_only(true);

    let mut response = Response::new(json!({"status": "success", "token": token}).to_string());
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
            "message": format!("Database error: {}", e),
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
        println!("Error fetching verification code: {:?}", e);
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
        println!("Error updating user: {:?}", e);
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
        println!("Error updating verification on verify account: {:?}", e);
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

pub async fn update_me_handler(
    Extension(user): Extension<User>,
    State(data): State<Arc<AppState>>,
    Json(body): Json<UpdateUserSchema>,
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
                .map_or(false, |_| true)
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
        println!("Error updating user: {:?}", e);
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
        println!("Error inserting verification: {:?}", e);
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Error creating verification code",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })
    .unwrap();

    let verification_link = format!(
        "https://{}/verify?token={}",
        base_url,
        verification.id.to_string()
    );

    let mut dest: Destination = Destination::builder().build();
    dest.to_addresses = Some(vec![email]);
    let message = format!(
        "Hello, \n Please verify your email by clicking on this link: <a href=\"{}\">{}</a>",
        verification_link, verification_link
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
        aws_config::load_defaults(BehaviorVersion::v2023_11_09()).await;
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
            println!("Error fetching user: {:?}", e);
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
        println!("Error inserting verification: {:?}", e);
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Error creating verification code",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })
    .unwrap();

    let verification_link = format!(
        "https://{}/reset-password?token={}",
        base_url,
        verification.id.to_string()
    );

    let mut dest: Destination = Destination::builder().build();
    dest.to_addresses = Some(vec![email]);
    let message = format!(
        "Hello, \n You requested a new password, please use the following link to set a new password <a href=\"{}\">{}</a>",
        verification_link, verification_link
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
        aws_config::load_defaults(BehaviorVersion::v2023_11_09()).await;
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

    let mut verification = sqlx::query_as!(
        Verification,
        "SELECT * FROM verifications WHERE id = $1 AND verification_type = $2",
        body.code,
        VerificationType::Password.to_string()
    )
    .fetch_optional(&data.db)
    .await
    .map_err(|e| {
        println!("Error fetching verification code: {:?}", e);
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

    let user = sqlx::query_as!(
        User,
        "UPDATE users SET password = $1 WHERE id = $2 RETURNING *",
        hashed_password,
        verification.user_id
    )
    .fetch_one(&data.db)
    .await
    .map_err(|e| {
        println!("Error updating user: {:?}", e);
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Error updating user",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    verification = sqlx::query_as!(
        Verification,
        "UPDATE verifications SET used = true WHERE id = $1 RETURNING *",
        body.code
    )
    .fetch_one(&data.db)
    .await
    .map_err(|e| {
        println!("Error updating verification on reset password: {:?}", e);
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
