.PHONY: all
all: build test

.PHONY: build
build:
	go build -o ./bin/dpass ./cmd/dpass && go build -o ./bin/dcoin ./cmd/dcoin

.PHONY: test
test:
	go test -v --count=1 ./...

.PHONY: init
init:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.7.2

.PHONY: lint
lint:
	golangci-lint run
