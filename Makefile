# Local development helpers

.PHONY: all fmt clippy test test-all integration setup-hooks

all: fmt clippy test

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
	cargo test --workspace

# Force-run integration tests even if skiCheck prerequisites fail.
# Requires: weston installed, ptrace_scope = 0.
integration:
	cargo test -p backseat --test integration -- --nocapture

test-all: test

setup-hooks:
	ln -sf "$(PWD)/scripts/pre-commit" "$(PWD)/.git/hooks/pre-commit"
