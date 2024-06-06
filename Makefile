.PHONY: test
test:
	go test -race ./...

.PHONY: build
build:
	CGO_ENABLED=0 go build -ldflags "-s -w" -o trivy-aws ./cmd/trivy-aws/main.go

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

.PHONY: bundle
bundle:
	tar -cvzf trivy-aws.tar.gz plugin.yaml trivy-aws LICENSE