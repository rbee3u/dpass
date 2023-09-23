.PHONY: build
build:
	go build -o ./bin/dpass ./cmd/dpass
	go build -o ./bin/dcoin ./cmd/dcoin

.PHONY: test
test:
	go test -v --count=1 ./...

.PHONY: install-lint
install-lint:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.54.2

.PHONY: lint
lint:
	golangci-lint run
