# Local development helpers

.PHONY: all fmt clippy test build-payload test-all

all: fmt clippy test

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
	cargo test -p backseat --lib
	cargo test -p backseat --doc

test-all:
	cargo test --workspace
