BINARY_NAME=ldsdemo

build:
	GOARCH=amd64 GOOS=linux go build -o bin/${BINARY_NAME} main.go
	openssl req -x509 -newkey rsa:2048 -keyout bin/key.pem -out bin/cert.pem -sha256 -days 365 -subj "/O=axway" -nodes -addext "keyUsage = digitalSignature, keyEncipherment, dataEncipherment, cRLSign, keyCertSign" -addext "extendedKeyUsage = serverAuth, clientAuth" -addext "subjectAltName = DNS:one.example.com,DNS:two.example.com" > /dev/null 2>&1

run:
	./${BINARY_NAME}

build_and_run: build run

clean:
	go clean
	rm bin/${BINARY_NAME}

test:
	go test ./...

test_coverage:
	go test ./... -coverprofile=coverage.out

dep:
	go mod tidy

vet:
	go vet

lint:
	golangci-lint run --enable-all