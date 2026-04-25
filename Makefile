.PHONY: build build-release install test test-release test-pvm test-state test-rpc run run-blocks testnet seq-testnet clean fmt clippy audit help

# Default target
help:
	@echo "Grey Node Development Commands"
	@echo ""
	@echo "Building:"
	@echo "  make build          - Debug build"
	@echo "  make build-release  - Release build"
	@echo "  make install        - Install to ~/.cargo/bin"
	@echo ""
	@echo "Testing:"
	@echo "  make test           - Run all tests"
	@echo "  make test-release   - Run tests in release mode"
	@echo "  make test-state     - Run state conformance tests"
	@echo "  make test-rpc       - Run RPC tests"
	@echo ""
	@echo "Running:"
	@echo "  make run            - Run debug build"
	@echo "  make testnet        - Run test network"
	@echo "  make seq-testnet    - Run sequential testnet"
	@echo ""
	@echo "Quality:"
	@echo "  make fmt            - Format code"
	@echo "  make clippy         - Run clippy"
	@echo "  make audit          - Run cargo audit"
	@echo "  make clean          - Clean build artifacts"

# Building
build:
	cargo build -p grey

build-release:
	cargo build --release -p grey

install:
	cargo install --path grey/crates/grey

# Testing
test:
	cargo test -p grey-state

test-release:
	cargo test --release -p grey-state

test-state:
	cargo test -p grey-state

test-rpc:
	cargo test -p grey-rpc

# Running
run:
	cargo run -p grey

run-blocks:
	cargo run --release -- --test

testnet:
	cargo run --release -- --seq-testnet

seq-testnet:
	cargo run --release -- --seq-testnet

# Quality
fmt:
	cargo fmt --all

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

audit:
	cargo audit

clean:
	cargo clean
