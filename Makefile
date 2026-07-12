SHELL := /bin/bash

GO ?= go
VERSION ?= 0.1.0
PLUGIN_ID := cyber-abuse-guard
DIST_DIR := $(CURDIR)/dist
SO := $(DIST_DIR)/$(PLUGIN_ID)-v$(VERSION).so
ZIP := $(DIST_DIR)/$(PLUGIN_ID)_$(VERSION)_linux_amd64.zip

.PHONY: all test vet race fuzz-smoke benchmark build-linux-amd64 integration-test release verify-release clean

all: test build-linux-amd64

test:
	$(GO) test -tags=sqlite_omit_load_extension ./...

vet:
	$(GO) vet -tags=sqlite_omit_load_extension ./...

race:
	CGO_ENABLED=1 $(GO) test -race -tags=sqlite_omit_load_extension ./...

fuzz-smoke:
	$(GO) test ./internal/extract -run='^$$' -fuzz=FuzzExtractText -fuzztime=5s
	$(GO) test ./internal/classifier -run='^$$' -fuzz=FuzzClassifier -fuzztime=5s
	$(GO) test ./internal/config -run='^$$' -fuzz=FuzzConfigParser -fuzztime=5s

benchmark:
	$(GO) test ./internal/classifier -run='^$$' -bench=. -benchmem -count=3

build-linux-amd64:
	GO=$(GO) VERSION=$(VERSION) ./scripts/build-linux-amd64.sh

integration-test: build-linux-amd64
	CYBER_ABUSE_GUARD_PLUGIN=$(SO) CGO_ENABLED=1 $(GO) test -tags=integration,sqlite_omit_load_extension -v -count=1 ./integration

release: test vet race build-linux-amd64
	VERSION=$(VERSION) ./scripts/package-release.sh

verify-release:
	VERSION=$(VERSION) ./scripts/verify-release.sh

clean:
	rm -rf $(DIST_DIR) build integration/.work coverage.out
