package commands_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-aws/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/clock"
)

const (
	account = "12345678"
	region  = "us-east-1"
)

func Test_Run(t *testing.T) {

	tests := []struct {
		name              string
		args              []string
		cacheFile         string
		supportedServices []string
		golden            string
		wantErr           string
	}{
		{
			name: "succeed with cached infra",
			args: []string{
				"--service", "s3",
				"--include-non-failures",
				"--format", "json",
			},
			supportedServices: []string{"s3"},
			cacheFile:         "s3onlycache.json",
			golden:            "s3-scan.json.golden",
		},
		{
			name: "custom rego rule with passed results",
			args: []string{
				"--service", "s3",
				"--include-non-failures",
				"--config-check", filepath.Join("testdata", "check.rego"),
				"--check-namespaces", "user",
				"--config-data", filepath.Join("testdata", "data"),
				"--format", "json",
			},
			supportedServices: []string{"s3"},
			cacheFile:         "s3onlycache.json",
			golden:            "custom-scan.json.golden",
		},
		{
			name: "compliance report summary",
			args: []string{
				"--service", "s3",
				"--format", "table",
				"--report", "summary",
				"--compliance", filepath.Join("@testdata", "example-spec.yaml"),
			},
			supportedServices: []string{"s3"},
			cacheFile:         "s3onlycache.json",
			golden:            "compliance-report-summary.golden",
		},
		{
			name: "scan an unsupported service",
			args: []string{
				"--service", "theultimateservice",
				"--format", "json",
			},
			wantErr: `service 'theultimateservice' is not currently supported`,
		},
		{
			name: "scan all supported services",
			args: []string{
				"--include-non-failures",
				"--format", "json",
			},
			supportedServices: []string{"s3", "cloudtrail"},
			cacheFile:         "s3andcloudtrailcache.json",
			golden:            "s3-cloud-trail-scan.json.golden",
		},
		{
			name: "skip certain services and include specific services",
			args: []string{
				"--service", "s3",
				"--skip-service", "cloudtrail",
				"--include-non-failures",
				"--format", "json",
			},
			supportedServices: []string{"s3", "cloudtrail"},
			cacheFile:         "s3andcloudtrailcache.json",
			// we skip cloudtrail but still expect results from it as it is cached
			golden: "s3-cloud-trail-scan.json.golden",
		},
		{
			name: "only skip certain services but scan the rest",
			args: []string{
				"--skip-service", "cloudtrail,iam",
				"--include-non-failures",
				"--format", "json",
			},
			supportedServices: []string{"s3", "cloudtrail", "iam"},
			cacheFile:         "s3onlycache.json",
			golden:            "s3-scan.json.golden",
		},
		{
			name: "fail - service specified to both include and exclude",
			args: []string{
				"--service", "s3",
				"--skip-service", "s3",
				"--include-non-failures",
				"--format", "json",
			},
			cacheFile: "s3andcloudtrailcache.json",
			wantErr:   "service: s3 specified to both skip and include",
		},
		{
			name: "ignore findings with .trivyignore",
			args: []string{
				"--include-non-failures",
				"--format", "json",
				"--ignorefile", filepath.Join("testdata", ".trivyignore"),
			},
			supportedServices: []string{"s3"},
			cacheFile:         "s3onlycache.json",
			golden:            "s3-scan-with-ignores.json.golden",
		},
	}

	cacheDir := t.TempDir()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.supportedServices != nil {
				oldAllSupportedServicesFunc := commands.AllSupportedServicesFunc
				commands.AllSupportedServicesFunc = func() []string {
					return tt.supportedServices
				}
				defer func() {
					commands.AllSupportedServicesFunc = oldAllSupportedServicesFunc
				}()
			}

			outputFile := filepath.Join(t.TempDir(), "output")

			args := []string{
				"--region", region,
				"--account", account,
				"--skip-check-update",
				"--quiet",
				"--timeout", time.Minute.String(),
				"--cache-dir", cacheDir,
				"--max-cache-age", "876000h",
				"--output", outputFile,
			}

			args = append(args, tt.args...)

			if tt.cacheFile != "" {
				cacheFile := filepath.Join(cacheDir, "cloud", "aws", account, region, "data.json")
				require.NoError(t, os.MkdirAll(filepath.Dir(cacheFile), 0700))

				cacheData, err := os.ReadFile(filepath.Join("testdata", tt.cacheFile))
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(cacheFile, cacheData, 0600))
			}

			err := run(args)

			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)

			want, err := os.ReadFile(filepath.Join("testdata", tt.golden))
			require.NoError(t, err)

			out, err := os.ReadFile(outputFile)
			require.NoError(t, err)

			assert.Equal(t, normalizeNewlines(string(want)), normalizeNewlines(string(out)))
		})
	}
}

func run(args []string) error {
	defer viper.Reset()

	ctx := clock.With(context.Background(), time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC))

	app := commands.NewCmd()
	app.SetOut(io.Discard)
	app.SetArgs(args)

	// Run trivy-aws
	return app.ExecuteContext(ctx)
}

func normalizeNewlines(input string) string {
	return strings.ReplaceAll(input, "\r\n", "\n")
}
