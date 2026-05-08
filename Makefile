# Local development helpers

.PHONY: all fmt clippy test test-all integration setup-hooks

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

setup-hooks:
	ln -sf "$(PWD)/scripts/pre-commit" "$(PWD)/.git/hooks/pre-commit"
