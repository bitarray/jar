# Grey — JAM blockchain node Makefile
#
# Quick start:
#   make test      — Run all tests
#   make build     — Build release binary
#   make run       — Run single-node test
#   make testnet   — Run 6-validator testnet
#
# For a full list of targets, run: make help

.PHONY: help build test test-release run testnet clean fmt lint clippy doc \
        docker-build docker-run conform install check

# Default target
.DEFAULT_GOAL := help

# ── Development ──────────────────────────────────────────────────────────

help: ## Show this help message
	@echo "Grey — JAM blockchain node"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

build: ## Build debug binary
	cargo build

build-release: ## Build optimized release binary
	cargo build --release

install: ## Install grey binary to ~/.cargo/bin
	cargo install --path grey/crates/grey

# ── Testing ───────────────────────────────────────────────────────────────

test: ## Run all tests (debug mode)
	cargo test --workspace

test-release: ## Run all tests (release mode, faster)
	cargo test --workspace --release

test-pvm: ## Run tests with recompiler PVM
	GREY_PVM=recompiler cargo test --workspace --release

test-state: ## Run state transition tests only
	cargo test -p grey-state --release

test-rpc: ## Run RPC tests
	cargo test -p grey-rpc

# ── Running ───────────────────────────────────────────────────────────────

run: ## Run sequential block test (no networking)
	cargo run --release --bin grey -- --test

run-blocks: ## Run sequential test with custom block count (BLOCKS=50)
	cargo run --release --bin grey -- --test --test-blocks $(or $(BLOCKS),50)

testnet: ## Run 6-validator testnet for 60 seconds
	cargo run --release --bin grey -- --testnet 60

testnet-forever: ## Run testnet until Ctrl+C
	cargo run --release --bin grey -- --testnet 0

seq-testnet: ## Run deterministic sequential testnet
	cargo run --release --bin grey -- --seq-testnet

# ── Code Quality ──────────────────────────────────────────────────────────

fmt: ## Format code with rustfmt
	cargo fmt --all

fmt-check: ## Check code formatting
	cargo fmt --all --check

clippy: ## Run clippy linter
	cargo clippy --workspace --all-targets -- -D warnings

lint: fmt-check clippy ## Run all linters (fmt + clippy)

check: ## Fast check (no tests, catches most errors)
	cargo check --workspace

doc: ## Generate and open documentation
	cargo doc --workspace --no-deps --open

# ── Conformance ───────────────────────────────────────────────────────────

conform: ## Run conformance tests (requires Python 3)
	python3 scripts/run_conform.py

conform-compare: ## Compare state with reference at block N (BLOCK=68)
	python3 scripts/compare_with_ref.py $(or $(BLOCK),68)

# ── Docker ────────────────────────────────────────────────────────────────

docker-build: ## Build Docker image
	docker build -t grey:latest -f grey/Dockerfile .

docker-run: ## Run Grey in Docker
	docker run -p 9000:9000 -p 9933:9933 -v grey-data:/data grey:latest

docker-testnet: ## Run testnet via docker-compose
	docker compose -f grey/docker-compose.yml up --build

docker-down: ## Stop docker-compose testnet
	docker compose -f grey/docker-compose.yml down -v

# ── Security & Audit ──────────────────────────────────────────────────────

audit: ## Run cargo audit for security vulnerabilities
	cargo audit

audit-fix: ## Run cargo audit with ignored advisories
	cargo audit --ignore RUSTSEC-2025-0009 --ignore RUSTSEC-2025-0010

sbom: ## Generate Software Bill of Materials
	cargo cyclonedx --format json --spec-version 1.5

# ── Cleaning ──────────────────────────────────────────────────────────────

clean: ## Remove build artifacts
	cargo clean
	rm -rf target/

clean-db: ## Remove local database
	rm -rf grey-db/

# ── Metrics & Monitoring ──────────────────────────────────────────────────

metrics: ## Run with Prometheus metrics on port 9615
	cargo run --release --bin grey -- --metrics-port 9615

grafana-up: ## Start Grafana + Prometheus stack
	docker compose -f grey/grafana/docker-compose.yml up -d

grafana-down: ## Stop Grafana stack
	docker compose -f grey/grafana/docker-compose.yml down
