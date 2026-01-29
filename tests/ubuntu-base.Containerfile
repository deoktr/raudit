FROM docker.io/library/rust:1.89 AS build

RUN rustup target add x86_64-unknown-linux-gnu \
	&& rustup toolchain install stable-x86_64-unknown-linux-gnu

WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY src src
RUN cargo fetch

RUN cargo build --release --target=x86_64-unknown-linux-gnu --offline

FROM docker.io/library/ubuntu:latest

COPY --from=build /src/target/x86_64-unknown-linux-gnu/release/raudit /raudit

ENTRYPOINT ["/raudit", "--json=pretty"]
