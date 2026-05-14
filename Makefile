# Local development helpers

.PHONY: all fmt clippy test test-all integration setup-hooks

all: fmt clippy test

fmt:
	cargo fmt

clippy:
	cargo clippy --all-targets --features fixture -- -D warnings

test:
	cargo test --features fixture

# Force-run integration tests even if skip/prerequisites fail.
# Requires: weston installed, ptrace_scope = 0.
integration:
	cargo test --test integration --features fixture -- --nocapture

test-all: test

setup-hooks:
	ln -sf "$(PWD)/scripts/pre-commit" "$(PWD)/.git/hooks/pre-commit"
