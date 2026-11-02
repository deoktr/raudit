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

e2e_build_musl:
    #!/usr/bin/env bash
    set -eu
    case "$(uname -m)" in
        x86_64) target="x86_64-unknown-linux-musl" ;;
        aarch64) target="aarch64-unknown-linux-musl" ;;
        *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
    esac
    rustup target add "${target}"
    cargo build --release --target "${target}"

e2e_container_hardened: e2e_build_musl
    python3 e2e/container_test.py openssh hardened --log-level info

e2e_container_weak: e2e_build_musl
    python3 e2e/container_test.py openssh weak --log-level info

e2e_container_alpine: e2e_build_musl
    python3 e2e/container_test.py all all --distro alpine --log-level info

e2e_container_ubuntu: e2e_build_musl
    python3 e2e/container_test.py all all --distro ubuntu --log-level info

e2e_container_all: e2e_build_musl
    python3 e2e/container_test.py all all --log-level info

e2e_container_update: e2e_build_musl
    python3 e2e/container_test.py all all --update-baselines --log-level info
