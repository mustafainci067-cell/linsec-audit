BINARY     := linsec-audit
PKG        := ./cmd/linsec-audit
IMAGE_NAME := linsec-audit:vuln

.PHONY: build build-linux test test-cover lint docker-build docker-test clean

build:
	@mkdir -p bin
	go build -trimpath -ldflags="-s -w" -o bin/$(BINARY) $(PKG)

build-linux:
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/$(BINARY)-linux $(PKG)

test:
	go test -v ./...

test-cover:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

lint:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (echo "Unformatted Go files:"; gofmt -l .; exit 1)

docker-build:
	docker build -f test/Dockerfile.vuln -t $(IMAGE_NAME) .

docker-test: docker-build
	docker run --rm $(IMAGE_NAME)

clean:
	rm -rf bin/ coverage.out coverage.html remediate.sh report.html report.json
