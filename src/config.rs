#[derive(Debug, Clone)]
pub struct Config {
    pub url: String,
    pub url_front: String,
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_expires_in: String,
    pub aws_s3_bucket: String,
    pub aws_bucket_url: String,
    pub github_client_id: String,
    pub github_redirect_uri: String,
    pub github_client_secret: String,
}

impl Config {
    pub fn init() -> Config {
        let url = std::env::var("ROOT_URL").expect("ROOT_URL must be set");
        let url_front = std::env::var("URL_FRONT").expect("URL_FRONT must be set");
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
        let jwt_expires_in = std::env::var("JWT_EXPIRED_IN").expect("JWT_EXPIRED_IN must be set");
        let aws_s3_bucket = std::env::var("AWS_S3_BUCKET").expect("AWS_S3_BUCKET must be set");
        let aws_bucket_url = std::env::var("AWS_BUCKET_URL").expect("AWS_BUCKET_URL must be set");
        let github_client_id =
            std::env::var("GITHUB_CLIENT_ID").expect("GITHUB_CLIENT_ID must be set");
        let github_redirect_uri =
            std::env::var("GITHUB_REDIRECT_URI").expect("GITHUB_REDIRECT_URI must be set");
        let github_client_secret =
            std::env::var("GITHUB_CLIENT_SECRET").expect("GITHUB_CLIENT_SECRET must be set");
        Config {
            url,
            url_front,
            database_url,
            jwt_secret,
            jwt_expires_in,
            aws_s3_bucket,
            aws_bucket_url,
            github_client_id,
            github_redirect_uri,
            github_client_secret,
        }
    }
}
