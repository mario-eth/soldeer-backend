mod config;
mod jwt_auth;
mod model;
mod project_handler;
mod response;
mod route;
mod user_handler;

use aws_config::BehaviorVersion;
use aws_sdk_s3 as s3;
use axum::http::{
    header::{
        ACCEPT,
        AUTHORIZATION,
        CONTENT_TYPE,
    },
    HeaderValue,
    Method,
};
use config::Config;
use dotenv::dotenv;
use route::create_router;
use s3::Client;
use sqlx::{
    postgres::PgPoolOptions,
    Pool,
    Postgres,
};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

pub struct AppState {
    db: Pool<Postgres>,
    env: Config,
    aws_client: aws_sdk_s3::Client,
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    let config = Config::init();

    let pool = match PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => {
            println!("✅Connection to the database is successful!");
            pool
        }
        Err(err) => {
            println!("🔥 Failed to connect to the database: {:?}", err);
            std::process::exit(1);
        }
    };

    let cors = CorsLayer::new()
        .allow_origin("http://localhost:3000".parse::<HeaderValue>().unwrap())
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ])
        .allow_credentials(true)
        .allow_headers([AUTHORIZATION, ACCEPT, CONTENT_TYPE]);

    // install global collector configured based on RUST_LOG env var.
    tracing_subscriber::fmt::init();

    // the aws credentials from environment
    let aws_configuration = aws_config::load_defaults(BehaviorVersion::v2023_11_09()).await;

    //create aws s3 client
    let aws_s3_client = Client::new(&aws_configuration);

    let app: axum::Router = create_router(Arc::new(AppState {
        db: pool.clone(),
        env: config.clone(),
        aws_client: aws_s3_client.clone(),
    }))
    .layer(cors);

    println!("🚀 Server started successfully");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
