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

e2e_test target="ubuntu-base":
    podman build . -f 'tests/{{ target }}.Containerfile' -t 'raudit-test-{{ target }}'
    podman run --rm 'raudit-test-{{ target }}' > 'raudit-test-{{ target }}.json'
    ./tests/compare.py -b 'tests/raudit-test-{{ target }}.json' -t 'raudit-test-{{ target }}.json'

e2e_test_all:
    just e2e_test 'ubuntu-base'
    just e2e_test 'ubuntu-hardened'
