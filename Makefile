GO ?= go
DEMO_ARGS ?=

.PHONY: check-go demo test vet build

check-go:
	@command -v "$(GO)" >/dev/null 2>&1 || { \
		printf '%s\n' 'Go 1.25+ is required. On macOS with Homebrew, run: brew install go' \
			'Official installer: https://go.dev/dl/' >&2; \
		exit 1; \
	}

demo: check-go
	"$(GO)" run ./cmd/demo $(DEMO_ARGS)

test: check-go
	"$(GO)" test -race ./...

vet: check-go
	"$(GO)" vet ./...

build: check-go
	"$(GO)" build ./cmd/...
