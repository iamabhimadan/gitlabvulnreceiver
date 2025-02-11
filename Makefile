# Build and test configuration
GOTEST=go test
GOTEST_OPT?= -v -race -timeout 30s
GOOS?=linux
GOARCH?=amd64

.PHONY: test
test:
	$(GOTEST) $(GOTEST_OPT) ./...

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: build
build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o bin/receiver

.PHONY: clean
clean:
	rm -rf bin/

.PHONY: generate
generate:
	go generate ./...

.DEFAULT_GOAL := build 