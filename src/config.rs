#[derive(Debug, Clone)]
pub struct Config {
    pub url: String,
    pub url_front: String,
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_expires_in: String,
    pub jwt_maxage: i32,
    pub aws_s3_bucket: String,
    pub aws_bucket_url: String,
}

impl Config {
    pub fn init() -> Config {
        let url = std::env::var("ROOT_URL").expect("ROOT_URL must be set");
        let url_front = std::env::var("URL_FRONT").expect("URL_FRONT must be set");
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
        let jwt_expires_in = std::env::var("JWT_EXPIRED_IN").expect("JWT_EXPIRED_IN must be set");
        let jwt_maxage = std::env::var("JWT_MAXAGE").expect("JWT_MAXAGE must be set");
        let aws_s3_bucket = std::env::var("AWS_S3_BUCKET").expect("AWS_S3_BUCKET must be set");
        let aws_bucket_url = std::env::var("AWS_BUCKET_URL").expect("AWS_BUCKET_URL must be set");
        Config {
            url,
            url_front,
            database_url,
            jwt_secret,
            jwt_expires_in,
            jwt_maxage: jwt_maxage.parse::<i32>().unwrap(),
            aws_s3_bucket,
            aws_bucket_url,
        }
    }
}
