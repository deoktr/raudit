alias t := test

[private]
default:
    @just --choose

ci: test lint security

[group("test")]
test:
    cargo test --all

[group("lint")]
lint: check clippy

[group("lint")]
check:
    cargo check

[group("lint")]
clippy:
    cargo clippy

[group("security")]
security: audit

[group("security")]
audit:
    cargo audit
