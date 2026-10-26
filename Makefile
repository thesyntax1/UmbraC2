# UmbraC2 -- build and test entry points
#
# Everything here is intentionally explicit: no hidden steps, and every target
# prints the exact command it runs so it can be reproduced by hand.
SHELL := /usr/bin/env bash

ROOT      := $(shell pwd)
SERVER    := $(ROOT)/server
BEACON    := $(ROOT)/implant/rust
ANDROID   := $(ROOT)/implant/android
OPERATOR  := $(ROOT)/operator
OUT       := $(ROOT)/build
PYTHON    ?= python3
# Use the Gradle wrapper when it has been generated, otherwise the CLI.
GRADLE    ?= $(shell test -x implant/android/gradlew && echo ./gradlew || echo gradle)

.DEFAULT_GOAL := help
.PHONY: help doctor build server beacon operator test test-go test-rust test-py check-vectors check-symbols check vectors \
        fmt clean dev-mock secrets cross-linux cross-windows cross-macos android-apk android-check

doctor: ## check which toolchains are available (nothing here is fatal)
	@echo "python      : $$($(PYTHON) -V 2>&1)"
	@$(PYTHON) -c "import cryptography; print('  cryptography: ' + cryptography.__version__)" 2>/dev/null \
		|| echo "  cryptography: MISSING  (pip install cryptography -- needed by the operator CLI)"
	@$(PYTHON) -c "import pytest; print('  pytest      : ' + pytest.__version__)" 2>/dev/null \
		|| echo "  pytest      : missing  (pip install pytest -- needed by make test-py)"
	@command -v go >/dev/null && echo "go          : $$(go version | cut -d' ' -f3)" || echo "go          : missing  (server build/tests)"
	@command -v cargo >/dev/null && echo "cargo       : $$(cargo --version | cut -d' ' -f2)" || echo "cargo       : missing  (beacon build/tests)"
	@command -v gradle >/dev/null && echo "gradle      : $$(gradle --version 2>/dev/null | awk '/^Gradle/{print $$2}')" || echo "gradle      : missing  (android apk)"
	@test -n "$$ANDROID_NDK_HOME" && echo "android ndk : $$ANDROID_NDK_HOME" || echo "android ndk : missing  (only needed for the JNI build)"
	@echo
	@echo "make check works with python alone; make test needs go + cargo as well."

help: ## show this help
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: server beacon operator ## build the server, the host beacon and the CLI

server: ## build the team server (host platform)
	@echo ">> go build ./server/cmd/umbra-server"
	@cd $(SERVER) && go build -trimpath -ldflags "-s -w" -o $(OUT)/umbra-server ./cmd/umbra-server

beacon: ## build the Rust beacon for the host platform
	@echo ">> cargo build --release (host)"
	@mkdir -p $(OUT)
	@cd $(BEACON) && cargo build --release
	@cp $(BEACON)/target/release/umbra-beacon $(OUT)/umbra-beacon 2>/dev/null || true

operator: ## install the operator CLI in editable mode
	@cd $(OPERATOR) && $(PYTHON) -m pip install -e .

test: check test-go test-rust test-py ## run every suite + the static contract checks
	@echo "all suites passed"

test-go: ## go test ./... (includes the shared protocol vectors)
	@cd $(SERVER) && go vet ./... && go test ./... -count=1

test-rust: ## cargo test (unit tests + contracts/vectors.json conformance)
	@cd $(BEACON) && cargo test --all-targets

test-py: ## pytest (protocol vectors + end-to-end against the mock server)
	@$(PYTHON) -m pytest tests -q

check-vectors: ## verify every implementation agrees on the wire constants
	@$(PYTHON) tools/check_consistency.py

check-symbols: ## static cross-package check for Go and Rust (no toolchain needed)
	@$(PYTHON) tools/check_symbols.py

check: check-vectors check-symbols ## every static contract check

vectors: ## regenerate contracts/vectors.json (the cross-language contract)
	@$(PYTHON) tools/gen_vectors.py

fmt: ## format Go and Rust sources
	@cd $(SERVER) && gofmt -w .
	@cd $(BEACON) && cargo fmt

cross-linux: ## static beacon binaries for linux x86_64 / aarch64 (musl)
	@cd $(BEACON) && rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
	@cd $(BEACON) && cargo build --release --target x86_64-unknown-linux-musl
	@cd $(BEACON) && cargo build --release --target aarch64-unknown-linux-musl

cross-windows: ## beacon binaries for 64-bit Windows (GNU toolchain)
	@cd $(BEACON) && rustup target add x86_64-pc-windows-gnu
	@cd $(BEACON) && cargo build --release --target x86_64-pc-windows-gnu

cross-macos: ## beacon binaries for Intel and Apple silicon (build on macOS)
	@cd $(BEACON) && rustup target add x86_64-apple-darwin aarch64-apple-darwin
	@cd $(BEACON) && cargo build --release --target x86_64-apple-darwin
	@cd $(BEACON) && cargo build --release --target aarch64-apple-darwin

android-apk: ## build the Android implant APK (needs Android SDK/NDK)
	@cd $(ANDROID) && $(GRADLE) assembleRelease

android-check: ## compile the Android implant without signing (fast sanity build)
	@cd $(ANDROID) && $(GRADLE) assembleDebug

dev-mock: ## start the development server with a fake agent (no Go needed)
	@$(PYTHON) tools/mock_server.py --port 4002 --spawn-agent

secrets: ## generate a PSK and an operator token
	@echo "agent PSK      : $$($(PYTHON) -c 'import os;print(os.urandom(32).hex())')"
	@echo "operator token : $$($(PYTHON) -c 'import os;print(os.urandom(32).hex())')"

clean: ## remove build output
	@rm -rf $(OUT) $(BEACON)/target
	@find . -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
