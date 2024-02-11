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
        get_project_revisions,
        get_project_revisions_cli,
        get_projects,
        update_project_handler,
        upload_revision,
    },
    user_handler::{
        get_last_code_handler, // TODO REMOVE IN PROD
        get_me_handler,
        health_checker_handler,
        login_user_handler,
        logout_handler,
        register_user_handler,
        request_new_password_handler,
        reset_password_handler,
        update_me_handler,
        verify_account_handler,
    },
    AppState,
};

pub fn create_router(app_state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/healthchecker", get(health_checker_handler))
        .route("/api/v1/auth/register", post(register_user_handler))
        .route("/api/v1/auth/login", post(login_user_handler))
        .route("/api/v1/verify", post(verify_account_handler))
        .route(
            "/api/v1/request-password",
            post(request_new_password_handler),
        )
        .route("/api/v1/reset-password", post(reset_password_handler))
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
            "/api/v1/users/me",
            post(update_me_handler)
                .route_layer(middleware::from_fn_with_state(app_state.clone(), auth)),
        )
        .route("/api/v1/project", get(get_projects))
        .route("/api/v1/revision", get(get_project_revisions))
        .route("/api/v1/revision-cli", get(get_project_revisions_cli))
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
        // .route("/api/v1/get_last_code", get(get_last_code_handler)) // TODO THIS NEEDS TO BE REMOVED IN PROD
        .with_state(app_state)
}
