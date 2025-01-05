.PHONY: all
all: build test

.PHONY: init
init:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8

.PHONY: build
build:
	go build -o ./bin/dpass ./cmd/dpass && go build -o ./bin/dcoin ./cmd/dcoin

.PHONY: test
test:
	go test -v --count=1 ./...

.PHONY: lint
lint:
	golangci-lint run
