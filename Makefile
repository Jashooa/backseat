# Local development helpers

.PHONY: all fmt clippy test test-all integration setup-hooks build-fixture

all: fmt clippy test

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

build-fixture:
	cargo build -p backseat-test-fixture

test: build-fixture
	cargo test --workspace

# Force-run integration tests even if skip/prerequisites fail.
# Requires: weston installed, ptrace_scope = 0.
integration: build-fixture
	cargo test -p backseat --test integration -- --nocapture

test-all: test

setup-hooks:
	ln -sf "$(PWD)/scripts/pre-commit" "$(PWD)/.git/hooks/pre-commit"
