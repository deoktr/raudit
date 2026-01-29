# do the hardening first to avoid rebuilds if raudit changes
FROM docker.io/library/ubuntu:latest AS base

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
    openssh-server \
    && rm -rf /var/lib/apt/lists/*

# hardening

# FIXME: does not work inside the container
# sysctl hardening
# COPY tests/ubuntu/sysctl/* /etc/sysctl.d/
# RUN sysctl --system

COPY tests/ubuntu/login.defs /etc/login.defs

COPY tests/ubuntu/apt/* /etc/apt/apt.conf.d/

FROM docker.io/library/rust:1.89 AS build

RUN rustup target add x86_64-unknown-linux-gnu \
	&& rustup toolchain install stable-x86_64-unknown-linux-gnu

WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY src src
RUN cargo fetch

RUN cargo build --release --target=x86_64-unknown-linux-gnu --offline

FROM base

COPY --from=build /src/target/x86_64-unknown-linux-gnu/release/raudit /raudit

ENTRYPOINT ["/raudit", "--json=pretty"]
