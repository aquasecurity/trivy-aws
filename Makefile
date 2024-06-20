.PHONY: test
test:
	go test -race ./...

PLATFORMS = linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64
OUTPUTS = $(patsubst %,%/trivy-aws,$(PLATFORMS))
build: clean $(OUTPUTS)
# os/arch/trivy-aws
%/trivy-aws:
	@mkdir -p $(dir $@); \
	GOOS=$(word 1,$(subst /, ,$*)); \
	GOARCH=$(word 2,$(subst /, ,$*)); \
	CGO_ENABLED=0 GOOS=$$GOOS GOARCH=$$GOARCH go build -ldflags "-s -w" -o trivy-aws-$$GOOS-$$GOARCH ./cmd/trivy-aws/main.go; \
	tar -cvzf trivy-aws-$$GOOS-$$GOARCH.tar.gz plugin.yaml trivy-aws-$$GOOS-$$GOARCH LICENSE

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

.PHONY: clean
clean:
	rm -rf trivy-aws*