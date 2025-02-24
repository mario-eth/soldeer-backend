# Build Stage
ARG SQLX_OFFLINE=true

FROM rust:1.82.0 as builder

RUN USER=root cargo new --bin soldeer-backend
WORKDIR /soldeer-backend
COPY ./Cargo.toml ./Cargo.toml
# Build empty app with downloaded dependencies to produce a stable image layer for next build
RUN cargo build --release

# Build the backend server with own code
RUN rm src/*.rs
ADD . ./
RUN rm -rf target
ARG SQLX_OFFLINE=true
RUN cargo build --release

# Build the actual container with just the binary
FROM ubuntu:24.04
ARG APP=/usr/src/app
ARG SQLX_OFFLINE=true
# COPY . .

RUN apt-get update && apt install -y openssl

RUN apt-get update \
    && apt-get install -y ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 3000

ENV TZ=Etc/UTC \
    APP_USER=appuser

RUN groupadd $APP_USER \
    && useradd -g $APP_USER $APP_USER \
    && mkdir -p ${APP}

COPY --from=builder /soldeer-backend/target/release/soldeer-backend ${APP}/soldeer-backend
COPY ./.sqlx ${APP}/.sqlx

RUN chown -R $APP_USER:$APP_USER ${APP}

USER $APP_USER
WORKDIR ${APP}

CMD ["./soldeer-backend"]
