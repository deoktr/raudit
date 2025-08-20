FROM docker.io/library/rust:1.89

RUN rustup target add x86_64-unknown-linux-gnu && \
	rustup toolchain install stable-x86_64-unknown-linux-gnu

WORKDIR /src

COPY Cargo.toml .
COPY Cargo.lock .
COPY src src
RUN cargo fetch

CMD [ "cargo", "build", "--release", "--target=x86_64-unknown-linux-gnu", "--offline" ]
