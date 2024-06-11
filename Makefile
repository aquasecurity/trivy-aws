.PHONY: test
test:
	go test -race ./...

.PHONY: build
build:
	make build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64 build-windows-amd64

.PHONY: build-linux-amd64
build-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o trivy-aws-linux-amd64 ./cmd/trivy-aws/main.go

.PHONY: build-linux-arm64
build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-s -w" -o trivy-aws-linux-arm64 ./cmd/trivy-aws/main.go

.PHONY: build-darwin-amd64
build-darwin-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o trivy-aws-darwin-amd64 ./cmd/trivy-aws/main.go

.PHONY: build-darwin-arm64
build-darwin-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w" -o trivy-aws-darwin-arm64 ./cmd/trivy-aws/main.go

.PHONY: build-windows-amd64
build-windows-amd64:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o trivy-aws-windows-amd64 ./cmd/trivy-aws/main.go

.PHONY: test-no-localstack
test-no-localstack:
	go test $$(go list ./... | grep -v internal/adapters | awk -F'github.com/aquasecurity/trivy-aws' '{print "./"$$2}')

.PHONY: quality
quality:
	which golangci-lint || go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.54.2
	golangci-lint run --timeout 3m --verbose

.PHONY: update-aws-deps
update-aws-deps:
	@grep aws-sdk-go-v2 go.mod | grep -v '// indirect' | sed 's/^[ [[:blank:]]]*//g' | sed 's/[[:space:]]v.*//g' | xargs go get
	@go mod tidy

.PHONY: bundle-linux
bundle-linux:
	tar -cvzf trivy-aws-linux.tar.gz plugin.yaml trivy-aws-linux-amd64 trivy-aws-linux-arm64 LICENSE

.PHONY: bundle-darwin
bundle-darwin:
	tar -cvzf trivy-aws-darwin.tar.gz plugin.yaml trivy-aws-darwin-amd64 trivy-aws-darwin-arm64 LICENSE

.PHONY: bundle-windows
bundle-windows:
	tar -cvzf trivy-aws-windows.tar.gz plugin.yaml trivy-aws-windows-amd64 LICENSE
