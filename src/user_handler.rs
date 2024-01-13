use std::sync::Arc;

use argon2::{
    password_hash::SaltString,
    Argon2,
    PasswordHash,
    PasswordHasher,
    PasswordVerifier,
};
use axum::{
    extract::State,
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
        LoginUserSchema,
        RegisterUserSchema,
        Role,
        TokenClaims,
        User,
    },
    response::FilteredUser,
    AppState,
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
    let escaped_email: String = body.email.to_owned().to_ascii_lowercase();
    validate_login_params(&escaped_email, &body.password)?;
    let user_exists: Option<bool> =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
            .bind(escaped_email.to_owned())
            .fetch_one(&data.db)
            .await
            .map_err(|e| {
                let error_response = serde_json::json!({
                    "status": "fail",
                    "message": format!("Database error: {}", e),
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
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Database error: {}", e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    let user_response = serde_json::json!({"status": "success","data": serde_json::json!({
        "user": filter_user_record(&user)
    })});

    Ok(Json(user_response))
}

pub async fn login_user_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<LoginUserSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let escaped_email: String = body.email.to_owned().to_ascii_lowercase();
    validate_login_params(&escaped_email, &body.password)?;
    let user = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE email = $1",
        body.email.to_ascii_lowercase()
    )
    .fetch_optional(&data.db)
    .await
    .map_err(|e| {
        let error_response = serde_json::json!({
            "status": "error",
            "message": format!("Database error: {}", e),
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
    let exp: usize = (now + chrono::Duration::minutes(i64::from_str(&data.env.jwt_expires_in).unwrap())).timestamp() as usize;
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
