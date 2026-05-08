# Local development helpers

.PHONY: all fmt clippy test build-payload test-all

all: fmt clippy test

fmt:
	cargo fmt --all

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

test: build-payload
	cargo test -p backseat --lib
	cargo test -p backseat --doc

build-payload:
	cargo build -p backseat-payload

test-all: build-payload
	cargo test -p backseat
