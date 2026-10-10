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

e2e_build:
    cargo build --release

e2e_install_deps:
    sudo apt-get install -y qemu-system-x86 qemu-utils cloud-image-utils genisoimage sshpass

e2e_hardened: e2e_build
    python3 e2e/qemu_test.py hardened --log-level info

e2e_insecure: e2e_build
    python3 e2e/qemu_test.py insecure --log-level info

e2e_all: e2e_build
    python3 e2e/qemu_test.py all --log-level info

e2e_update: e2e_build
    python3 e2e/qemu_test.py all --update-baselines --log-level info
