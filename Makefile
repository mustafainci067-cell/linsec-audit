BINARY := linsec-audit
PKG    := ./cmd/linsec-audit

.PHONY: build test lint clean

build:
	@mkdir -p bin
	go build -trimpath -ldflags="-s -w" -o bin/$(BINARY) $(PKG)

test:
	go test -v ./...

lint:
	go vet ./...

clean:
	rm -rf bin/