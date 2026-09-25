BIN := bin/supermcp
GO  ?= go

.PHONY: build test lint check-migrations chart-test kind-test adapters web web-client airgap clean

build:
	$(GO) build -trimpath -o $(BIN) ./cmd/supermcp

test:
	$(GO) test -race ./...

lint:
	gofmt -l . && $(GO) vet ./...

# Refuse a migration that would break pods of the previous release during a
# rolling upgrade; docs/UPGRADING.md, "How migrations are checked". The
# fixture test runs first so a checker that stopped refusing cannot pass.
check-migrations:
	./scripts/check-migrations_test.sh
	./scripts/check-migrations.sh

# The chart renders the master key the way docs/install.md says: a key
# file mounted and named in ENCRYPTION_KEK_FILE only when asked for.
chart-test:
	helm lint charts/supermcp
	./scripts/chart_test.sh

# Build the image, install the chart on a kind cluster against a real
# Postgres, check it serves, upgrade it in place and check it kept
# serving. The helm-install CI job runs the same script. Needs kind,
# kubectl, helm and Docker; exits 2 naming whichever is missing.
kind-test:
	./hack/kind/test.sh

# Regenerate the adapter catalog from the vendored v1 corpus and rebuild the index.
# The catalog is generated; adapters/embed.go and the recorded cassettes
# are not, so the clean step keeps both. A cassette is an afternoon of
# calling real upstreams and cannot be regenerated offline.
#
# The index is kept too: the generator reads it to carry each adapter's
# earlier content hashes forward, which is how a catalog re-sync tells an
# older install from a newer one and refuses to move a connector back.
#
# RETIRED stays in the corpus, which the converter tests still read, but is
# left out of the catalog: immobilienscout24 needs OAuth 1.0a and sorare a
# bcrypt-salted login, and neither is implemented.
RETIRED := immobilienscout24,sorare

adapters: build
	find adapters -name adapter.yaml -delete
	rm -f adapters/convert-report.json
	$(BIN) adapter convert -in pkg/adapter/v1/testdata/corpus -out adapters -report adapters/convert-report.json -skip $(RETIRED)
	$(BIN) adapter validate --strict adapters
	$(BIN) adapter index -out adapters/index.gen.json
	$(BIN) adapter test

# Regenerate the TypeScript client from the Go OpenAPI document.
web-client: build
	$(BIN) openapi > web/openapi.json
	cd web && pnpm install --frozen-lockfile && pnpm generate

# Build the SPA into internal/web/dist (embedded by `go build`).
web: web-client
	cd web && pnpm build
	touch internal/web/dist/.gitkeep

# The bundle an operator installs from a disconnected network. Needs the
# image built or pulled first; the script says so if it is missing.
airgap:
	./hack/airgap.sh

clean:
	rm -rf bin dist internal/web/dist/assets
