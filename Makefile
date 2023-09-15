.PHONY: test
test:
	go test -race ./...

.PHONY: test-no-localstack
test-no-localstack:
	go test $$(go list ./... | grep -v internal/adapters/cloud/aws | awk -F'github.com/aquasecurity/defsec/' '{print "./"$$2}')

.PHONY: quality
quality:
	which golangci-lint || go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.47.2
	golangci-lint run --timeout 3m --verbose

.PHONY: update-aws-deps
update-aws-deps:
	@grep aws-sdk-go-v2 go.mod | grep -v '// indirect' | sed 's/^[\t\s]*//g' | sed 's/\s.*//g' | xargs go get
	@go mod tidy