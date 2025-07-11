BIN = cryptopals

.PHONY: build test clean all

build:
	go build -o ${BIN} ./cmd/cryptopals/

test:
	go test -v ./...

test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

test-race:
	go test -race -v ./...

test-internal:
	go test -v ./internal/...

test-set1:
	go test -v ./internal/set1/...

test-set2:
	go test -v ./internal/set2/...

clean:
	go clean
	rm -f ${BIN}
	rm -f coverage.out coverage.html


