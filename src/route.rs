use std::sync::Arc;

use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::{
        delete,
        get,
        post,
        put,
    },
    Router,
};

use crate::{
    jwt_auth::auth,
    project_handler::{
        add_project_handler,
        delete_project_handler,
        update_project_handler,
        upload_revision,
    },
    user_handler::{
        get_me_handler,
        health_checker_handler,
        login_user_handler,
        logout_handler,
        register_user_handler,
    },
    AppState,
};

pub fn create_router(app_state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/healthchecker", get(health_checker_handler))
        .route("/api/v1/auth/register", post(register_user_handler))
        .route("/api/v1/auth/login", post(login_user_handler))
        .route(
            "/api/v1/auth/logout",
            get(logout_handler)
                .route_layer(middleware::from_fn_with_state(app_state.clone(), auth)),
        )
        .route(
            "/api/v1/users/me",
            get(get_me_handler)
                .route_layer(middleware::from_fn_with_state(app_state.clone(), auth)),
        )
        .route(
            "/api/v1/project",
            post(add_project_handler)
                .route_layer(middleware::from_fn_with_state(app_state.clone(), auth)),
        )
        .route(
            "/api/v1/project",
            put(update_project_handler)
                .route_layer(middleware::from_fn_with_state(app_state.clone(), auth)),
        )
        .route(
            "/api/v1/project",
            delete(delete_project_handler)
                .route_layer(middleware::from_fn_with_state(app_state.clone(), auth)),
        )
        .route(
            "/api/v1/revision/upload",
            post(upload_revision)
                .route_layer(middleware::from_fn_with_state(app_state.clone(), auth))
                .layer(DefaultBodyLimit::max(52428800)),
        )
        .with_state(app_state)
}
