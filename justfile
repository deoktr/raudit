alias t := test

[private]
default:
    @just --choose

ci: test lint audit

test:
    cargo test --all

format:
    cargo fmt

lint:
    cargo clippy

audit:
    cargo audit
