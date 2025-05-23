# PRE-DEPLOY

1. `cargo sqlx prepare -- --all-targets --all-features` - needed to run the sqlx in offline mode, sqlx needs to query the database to generate the code, so we do this to avoid the connection to the db at compile time
2. `cargo build --release` - this might not be needed, need to investigate more
3. create .env_docker file to store environment variables
   Example of the .env_docker file:

```bash
ROOT_URL=0.0.0.0:3000
URL_FRONT=0.0.0.0:3000

POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_USER=admin
POSTGRES_PASSWORD=1234
POSTGRES_DB=soldeer

DATABASE_URL=postgresql://admin:1234@postgres:5432/soldeer?schema=public

PGADMIN_DEFAULT_EMAIL=admin@admin.com
PGADMIN_DEFAULT_PASSWORD=1234

JWT_SECRET=my_ultra_secure_secret
JWT_EXPIRED_IN=43800 # token lifetime in minutes

AWS_ACCESS_KEY_ID=AA..........AA
AWS_SECRET_ACCESS_KEY=KKK....K
AWS_DEFAULT_REGION=region
AWS_S3_BUCKET=bucket_name
AWS_BUCKET_URL=aws_bucket_url


GITHUB_CLIENT_ID=EXAMPLE_CLIENT_ID
GITHUB_REDIRECT_URI=http://localhost:3000/api/v1/auth/github/callback
GITHUB_CLIENT_SECRET=EXAMPLE_CLIENT_SECRET

```

Make sure you replace all the secrets correctly

4. Build the docker image

Before running the build

```docker
export DOCKER_DEFAULT_PLATFORM=linux/amd64
```

```docker
docker build -t soldeer-backend .
```

# DEPLOY using the docker image

Run the docker image built in pre-deploy

```
docker run --network soldeer-backend_default --env-file .env_docker --name soldeer-backend -p 8080:3000 -d soldeer-backend
```

The network is `soldeer-backend_default` because that's how the postgres is built locally via docker-compose.

### Reference article for general axum server with sqlx

https://codevoweb.com/jwt-authentication-in-rust-using-axum-framework/

### RUN LOCALLY

```bash
cargo watch -q -c -w src/ -x run
```
