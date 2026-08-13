MODULE := $(shell go list -m)

.PHONY: all deps style format build test lint

all: format build test lint

deps:
	go install golang.org/x/tools/cmd/goimports@v0.48.0
	go install mvdan.cc/gofumpt@v0.11.0
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
	go install github.com/goreleaser/goreleaser/v2@v2.17.1

style:
	@files="$$(goimports -local $(MODULE) -l .)"; \
	[ -n "$$files" ] || files="$$(gofumpt -l .)"; \
	[ -z "$$files" ] || { \
		printf "%s\n" "$$files"; \
		echo "Run 'make format' to fix style issues."; \
		exit 1; \
	}

format:
	goimports -local $(MODULE) -l -w . && gofumpt -l -w .

build:
	mkdir -p ./bin && go build -o ./bin/dpass $(MODULE)

test:
	go test -count 1 ./...

lint:
	golangci-lint run
