SED=$(shell command -v gsed || command -v sed)

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
	if [ $$GOOS = "windows" ]; then \
		mv trivy-aws-$$GOOS-$$GOARCH trivy-aws-$$GOOS-$$GOARCH.exe; \
		tar -cvzf trivy-aws-$$GOOS-$$GOARCH.tar.gz plugin.yaml trivy-aws-$$GOOS-$$GOARCH.exe LICENSE; \
	else \
		tar -cvzf trivy-aws-$$GOOS-$$GOARCH.tar.gz plugin.yaml trivy-aws-$$GOOS-$$GOARCH LICENSE; \
	fi

.PHONY: test-no-localstack
test-no-localstack:
	go test $$(go list ./... | grep -v internal/adapters | awk -F'github.com/aquasecurity/trivy-aws' '{print "./"$$2}')

.PHONY: quality
quality:
	which golangci-lint || go install github.com/golangci/golangci-lint/cmd/golangci-lint@v2.1.2
	golangci-lint run --timeout 3m --verbose

.PHONY: update-aws-deps
update-aws-deps:
	@grep aws-sdk-go-v2 go.mod | grep -v '// indirect' | sed 's/^[ [[:blank:]]]*//g' | sed 's/[[:space:]]v.*//g' | xargs go get
	@go mod tidy

.PHONY: clean
clean:
	rm -rf trivy-aws*

.PHONY: bump-manifest
bump-manifest:
	@[ $$NEW_VERSION ] || ( echo "env 'NEW_VERSION' is not set"; exit 1 )
	@current_version=$$(cat plugin.yaml | grep 'version' | awk '{ print $$2}' | tr -d '"') ;\
	echo Current version: $$current_version ;\
	echo New version: $$NEW_VERSION ;\
	$(SED) -i -e "s/$$current_version/$$NEW_VERSION/g" plugin.yaml ;\
