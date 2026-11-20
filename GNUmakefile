OPENAPI_URL ?= https://api.cloudafrica.net/openapi.json

default: generate build test

build:
	go build ./...

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run

# Regenerate client.gen.go from the pinned openapi.json.
generate:
	go generate ./...

# Re-pin openapi.json from OPENAPI_URL (or OPENAPI_FILE, e.g. a nebula
# gateway/build/openapi/gateway.json) and regenerate. Refuses a document that
# names any server other than production.
regen:
	@set -e; tmp=$$(mktemp); trap 'rm -f "$$tmp"' EXIT; \
	if [ -n "$(OPENAPI_FILE)" ]; then cp "$(OPENAPI_FILE)" "$$tmp"; src="$(OPENAPI_FILE)"; \
	else curl -fsSL "$(OPENAPI_URL)" -o "$$tmp"; src="$(OPENAPI_URL)"; fi; \
	servers=$$(jq -c '[.servers[]?.url]' "$$tmp"); \
	if [ "$$servers" != '["https://api.cloudafrica.net"]' ]; then \
		echo "refusing $$src: servers are $$servers, want only https://api.cloudafrica.net" >&2; exit 1; fi; \
	jq . "$$tmp" > openapi.json; \
	printf 'gateway OpenAPI, %s, fetched %s\n' "$$src" "$$(date -u +%Y-%m-%dT%H:%MZ)" > openapi.source
	$(MAKE) generate

.PHONY: default build test lint generate regen
