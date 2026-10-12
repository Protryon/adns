FROM --platform=$BUILDPLATFORM lukemathwalker/cargo-chef:0.1.73-rust-1.92-trixie AS planner
WORKDIR /plan

COPY ./adns-server ./adns-server
COPY ./adns-proto ./adns-proto
COPY ./adns-zone ./adns-zone
COPY ./adns-client ./adns-client
COPY ./Cargo.lock .
COPY ./Cargo.toml .

RUN cargo chef prepare --recipe-path recipe.json

# builder runs natively on the build host and cross compiles for TARGETARCH
FROM --platform=$BUILDPLATFORM lukemathwalker/cargo-chef:0.1.73-rust-1.92-trixie AS builder
ARG TARGETARCH

WORKDIR /build
RUN apt-get update && apt-get install -y cmake gcc-aarch64-linux-gnu libc6-dev-arm64-cross gcc-x86-64-linux-gnu libc6-dev-amd64-cross

ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
    CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc

RUN case "$TARGETARCH" in \
        amd64) echo x86_64-unknown-linux-gnu ;; \
        arm64) echo aarch64-unknown-linux-gnu ;; \
        *) echo "unsupported arch $TARGETARCH" >&2; exit 1 ;; \
    esac > /rust_target && rustup target add $(cat /rust_target)

COPY --from=planner /plan/recipe.json recipe.json

RUN cargo chef cook --release --target $(cat /rust_target) --recipe-path recipe.json -p adns-server

COPY ./adns-server ./adns-server
COPY ./adns-proto ./adns-proto
COPY ./adns-zone ./adns-zone
COPY ./adns-client ./adns-client
COPY ./Cargo.lock .
COPY ./Cargo.toml .

RUN cargo build --release --target $(cat /rust_target) -p adns-server && mv /build/target/$(cat /rust_target)/release/adns-server /build/target/adns-server

FROM debian:trixie-slim
WORKDIR /runtime

COPY --from=builder /build/target/adns-server /runtime/adns-server

RUN apt-get update && apt-get install libssl3 ca-certificates -y && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/runtime/adns-server"]
