# Local development helpers

.PHONY: all fmt clippy test test-all integration

all: fmt clippy test

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
	cargo test -p backseat

integration:
	cargo test -p backseat --test integration -- --ignored

test-all:
	cargo test --workspace
