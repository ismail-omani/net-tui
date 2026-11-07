.PHONY: build test vet creds clean

build:
	go build -o net-tui ./cmd/net-tui

test:
	go test ./...

vet:
	go vet ./...

creds: build
	./net-tui --fetch-creds

clean:
	rm -f net-tui
