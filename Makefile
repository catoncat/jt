.PHONY: test build cross

test:
	go test ./...

build:
	go build -trimpath -ldflags '-s -w' -o bin/jt ./cmd/jt

cross:
	mkdir -p dist
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags '-s -w' -o dist/jt-darwin-arm64 ./cmd/jt
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o dist/jt-linux-amd64 ./cmd/jt
	GOOS=linux GOARCH=arm64 go build -trimpath -ldflags '-s -w' -o dist/jt-linux-arm64 ./cmd/jt
