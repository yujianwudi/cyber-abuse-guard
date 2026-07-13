SHELL := /bin/bash

GO ?= go
GOFMT ?= gofmt
VERSION ?= 0.1.2
CYCLONEDX_GOMOD ?= cyclonedx-gomod
CYCLONEDX_GOMOD_VERSION ?= v1.9.0
GOVULNCHECK ?= govulncheck
GOVULNCHECK_VERSION ?= v1.6.0
PLUGIN_ID := cyber-abuse-guard
DIST_DIR := $(CURDIR)/dist
DIRTY_SUFFIX := $(if $(filter 1,$(ALLOW_DIRTY_BUILD)),-dirty,)
ARTIFACT_VERSION := $(VERSION)$(DIRTY_SUFFIX)
SO := $(DIST_DIR)/$(PLUGIN_ID)-v$(ARTIFACT_VERSION).so
STORE_ZIP := $(DIST_DIR)/$(PLUGIN_ID)_$(ARTIFACT_VERSION)_linux_amd64.zip
AUDIT_BUNDLE := $(DIST_DIR)/$(PLUGIN_ID)-v$(ARTIFACT_VERSION)-audit-bundle.zip
TEST_TAGS := sqlite_omit_load_extension

.NOTPARALLEL: release

.PHONY: all format-check git-diff-check module-verify test unit-test vet race \
	fuzz-smoke script-test corpus-regression holdout-test benchmark build-linux-amd64 \
	integration-test ruleset-manifest sbom vulncheck release-preflight \
	package-release package-source-release release release-evidence formal-release release-doc-consistency release-doc-consistency-test verify-release verification-fault-test cpa-store-contract artifact-hash \
	reproducibility-test clean-tree-check tools clean

all: test build-linux-amd64

format-check:
	@command -v "$(GOFMT)" >/dev/null 2>&1 || { \
		echo 'required formatter not found: $(GOFMT)' >&2; exit 1; \
	}; \
	files=(); \
	while IFS= read -r -d '' file; do \
		[[ -f "$$file" ]] && files+=("$$file"); \
	done < <(git ls-files -co --exclude-standard -z -- '*.go'); \
	if [[ $${#files[@]} -eq 0 ]]; then exit 0; fi; \
	bad="$$($(GOFMT) -l "$${files[@]}")" || exit $$?; \
	if [[ -n "$$bad" ]]; then printf 'gofmt required:\n%s\n' "$$bad" >&2; exit 1; fi

git-diff-check:
	git diff --check

module-verify:
	$(GO) mod verify
	$(GO) mod tidy -diff
	$(GO) -C integration/pluginstorecontract mod verify
	$(GO) -C integration/pluginstorecontract mod tidy -diff

test:
	$(GO) test -tags=$(TEST_TAGS) ./...

unit-test: test

vet:
	$(GO) vet -tags=$(TEST_TAGS) ./...

race:
	CGO_ENABLED=1 $(GO) test -race -tags=$(TEST_TAGS) ./...

fuzz-smoke:
	$(GO) test ./internal/extract -run='^$$' -fuzz=FuzzExtractText -fuzztime=5s
	$(GO) test ./internal/classifier -run='^$$' -fuzz=FuzzClassifier -fuzztime=5s
	$(GO) test ./internal/config -run='^$$' -fuzz=FuzzConfigParser -fuzztime=5s

script-test:
	./scripts/check-production-health-test.sh
	GO=$(GO) ./scripts/create-store-archive-test.sh
	./scripts/generate-hmac-key-test.sh
	./scripts/release-doc-consistency-test.sh

corpus-regression:
	$(GO) test -tags=$(TEST_TAGS) ./internal/classifier \
		-run='^TestBalancedCorpusMetrics$$' -count=1 -v

holdout-test:
	@$(GO) test -tags=$(TEST_TAGS) ./internal/classifier \
		-list='^TestIndependentHoldoutV10$$' | \
		grep -Fxq 'TestIndependentHoldoutV10' || { \
			echo 'required independent evaluation v10 gate is missing' >&2; exit 1; \
		}
	INDEPENDENT_HOLDOUT_V10=1 $(GO) test -tags=$(TEST_TAGS) ./internal/classifier \
		-run='^TestIndependentHoldoutV10$$' -count=1 -v

benchmark:
	$(GO) test ./internal/classifier \
		-run='^TestClassifier(Adversarial)?PerformanceAcceptance$$' -count=1 -v
	$(GO) test ./internal/classifier -run='^$$' -bench=. -benchmem -count=3

build-linux-amd64:
	GO=$(GO) VERSION=$(VERSION) ./scripts/build-linux-amd64.sh

integration-test: build-linux-amd64
	CYBER_ABUSE_GUARD_PLUGIN=$(SO) CGO_ENABLED=1 $(GO) test \
		-tags=integration,$(TEST_TAGS) -v -count=1 ./integration

ruleset-manifest:
	GO=$(GO) VERSION=$(VERSION) ./scripts/release-ruleset-manifest.sh

sbom:
	GO=$(GO) VERSION=$(VERSION) CYCLONEDX_GOMOD=$(CYCLONEDX_GOMOD) \
		CYCLONEDX_GOMOD_VERSION=$(CYCLONEDX_GOMOD_VERSION) ./scripts/release-sbom.sh

vulncheck:
	$(GOVULNCHECK) ./...

release-preflight:
	GO=$(GO) VERSION=$(VERSION) ./scripts/release-preflight.sh

package-release:
	GO=$(GO) VERSION=$(VERSION) CYCLONEDX_GOMOD=$(CYCLONEDX_GOMOD) \
		CYCLONEDX_GOMOD_VERSION=$(CYCLONEDX_GOMOD_VERSION) ./scripts/package-release.sh

package-source-release:
	GO=$(GO) VERSION=$(VERSION) ./scripts/package-source-release.sh

release-evidence:
	GO=$(GO) VERSION=$(VERSION) ./scripts/generate-release-evidence.sh

release-doc-consistency:
	./scripts/release-doc-consistency.sh

release-doc-consistency-test:
	./scripts/release-doc-consistency-test.sh

formal-release:
	GO=$(GO) VERSION=$(VERSION) CYCLONEDX_GOMOD=$(CYCLONEDX_GOMOD) \
		CYCLONEDX_GOMOD_VERSION=$(CYCLONEDX_GOMOD_VERSION) GOVULNCHECK=$(GOVULNCHECK) \
		./scripts/formal-release.sh

release: release-preflight format-check git-diff-check module-verify test vet race \
	fuzz-smoke script-test corpus-regression holdout-test benchmark integration-test vulncheck sbom package-release cpa-store-contract

verify-release:
	GO=$(GO) VERSION=$(VERSION) CYCLONEDX_GOMOD=$(CYCLONEDX_GOMOD) \
		CYCLONEDX_GOMOD_VERSION=$(CYCLONEDX_GOMOD_VERSION) ./scripts/verify-release.sh

cpa-store-contract:
	@if [[ -f "$(SO)" && -f "$(STORE_ZIP)" && \
		-f "$(DIST_DIR)/build-metadata.json" && -f "$(DIST_DIR)/checksums.txt" ]]; then \
		DIST_DIR="$(DIST_DIR)" $(GO) -C integration/pluginstorecontract test -count=1 ./...; \
	else \
		env -u DIST_DIR $(GO) -C integration/pluginstorecontract test -count=1 ./...; \
	fi

verification-fault-test:
	GO=$(GO) VERSION=$(VERSION) CYCLONEDX_GOMOD=$(CYCLONEDX_GOMOD) \
		CYCLONEDX_GOMOD_VERSION=$(CYCLONEDX_GOMOD_VERSION) \
		./scripts/release-verification-fault-test.sh

artifact-hash:
	cd $(DIST_DIR) && sha256sum -c checksums.txt
	cd $(DIST_DIR) && sha256sum -c $(notdir $(SO)).sha256
	cd $(DIST_DIR) && sha256sum -c ruleset.sha256

reproducibility-test:
	GO=$(GO) VERSION=$(VERSION) CYCLONEDX_GOMOD=$(CYCLONEDX_GOMOD) \
		CYCLONEDX_GOMOD_VERSION=$(CYCLONEDX_GOMOD_VERSION) ./scripts/reproducibility-test.sh

clean-tree-check:
	@test -z "$$(git status --porcelain)" || { git status --short >&2; exit 1; }

tools:
	GOBIN="$$($(GO) env GOPATH)/bin" $(GO) install \
		github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@$(CYCLONEDX_GOMOD_VERSION)
	GOBIN="$$($(GO) env GOPATH)/bin" $(GO) install \
		golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

clean:
	rm -rf $(DIST_DIR) build integration/.work coverage.out
