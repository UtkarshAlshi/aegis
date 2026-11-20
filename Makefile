.PHONY: demo test vet build

demo:
	go run ./cmd/demo

test:
	go test -race ./...

vet:
	go vet ./...

build:
	go build ./cmd/...
