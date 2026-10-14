.PHONY: build test up down clean

build:
	CGO_ENABLED=0 go build -o bin/server ./server
	CGO_ENABLED=0 go build -o bin/client ./client

test:
	go test ./...

up:
	docker compose up --build

down:
	docker compose down

clean:
	rm -rf bin
