FROM lukemathwalker/cargo-chef:0.1.61-rust-1.70-slim-buster AS planner
WORKDIR /plan

COPY ./adns-server ./adns-server
COPY ./adns-proto ./adns-proto
COPY ./adns-zone ./adns-zone
COPY ./adns-client ./adns-client
COPY ./Cargo.lock .
COPY ./Cargo.toml .

RUN cargo chef prepare --recipe-path recipe.json

FROM lukemathwalker/cargo-chef:0.1.61-rust-1.70-buster AS builder

WORKDIR /build
RUN apt-get update && apt-get install cmake -y

COPY --from=planner /plan/recipe.json recipe.json

RUN cargo chef cook --release --recipe-path recipe.json -p adns-server

COPY ./adns-server ./adns-server
COPY ./adns-proto ./adns-proto
COPY ./adns-zone ./adns-zone
COPY ./adns-client ./adns-client
COPY ./Cargo.lock .
COPY ./Cargo.toml .

RUN cargo build --release -p adns-server && mv /build/target/release/adns-server /build/target/adns-server

FROM debian:buster-slim
WORKDIR /runtime

COPY --from=builder /build/target/adns-server /runtime/adns-server

RUN apt-get update && apt-get install libssl1.1 ca-certificates -y && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/runtime/adns-server"]