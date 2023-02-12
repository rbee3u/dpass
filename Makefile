build:
	go build -o ./bin/dpass ./cmd/dpass
	go build -o ./bin/dcoin ./cmd/dcoin

test:
	go test -v --count=1 ./...

lint:
	golangci-lint run

install-lint:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.51.1
