.PHONY: build test vet creds clean

build:
	go build -o net-dis ./cmd/net-dis

test:
	go test ./...

vet:
	go vet ./...

creds: build
	./net-dis --fetch-creds

clean:
	rm -f net-dis
