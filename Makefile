.PHONY: build test race vet check clean

build:
	go build -trimpath -o bin/pdp ./cmd/pdp

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

check: vet race build

clean:
	rm -f bin/pdp
