package commands

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-aws/pkg/flag"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	trivyflag "github.com/aquasecurity/trivy/pkg/flag"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_Run(t *testing.T) {
	regoDir := t.TempDir()

	tests := []struct {
		name         string
		options      flag.Options
		golden       string
		expectErr    bool
		cacheContent string
		regoPolicy   string
		allServices  []string
		inputData    string
		ignoreFile   string
	}{
		{
			name: "succeed with cached infra",
			options: flag.Options{
				Options: trivyflag.Options{
					RegoOptions: trivyflag.RegoOptions{SkipCheckUpdate: true},
					AWSOptions: trivyflag.AWSOptions{
						Region:   "us-east-1",
						Services: []string{"s3"},
						Account:  "12345678",
					},
					MisconfOptions: trivyflag.MisconfOptions{IncludeNonFailures: true},
				},
				CloudOptions: flag.CloudOptions{
					MaxCacheAge: time.Hour * 24 * 365 * 100,
				},
			},
			cacheContent: "testdata/s3onlycache.json",
			allServices:  []string{"s3"},
			golden:       "s3-scan.json.golden",
		},
		{
			name: "custom rego rule with passed results",
			options: flag.Options{
				Options: trivyflag.Options{
					AWSOptions: trivyflag.AWSOptions{
						Region:   "us-east-1",
						Services: []string{"s3"},
						Account:  "12345678",
					},
					RegoOptions: trivyflag.RegoOptions{
						Trace: true,
						CheckPaths: []string{
							filepath.Join(regoDir, "policies"),
						},
						CheckNamespaces: []string{
							"user",
						},
						DataPaths: []string{
							filepath.Join(regoDir, "data"),
						},
						SkipCheckUpdate: true,
					},
					MisconfOptions: trivyflag.MisconfOptions{
						IncludeNonFailures: true,
					},
				},
				CloudOptions: flag.CloudOptions{
					MaxCacheAge: time.Hour * 24 * 365 * 100,
				},
			},
			regoPolicy: `# METADATA
# title: Bad input data
# description: Just failing rule with input data
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   severity: LOW
#   service: s3
#   input:
#     selector:
#     - type: cloud
package user.whatever
import data.settings.DS123.foo

deny {
	foo == true
}
`,
			inputData: `{
	"settings": {
		"DS123": {
			"foo": true
		}
	}
}`,
			cacheContent: filepath.Join("testdata", "s3onlycache.json"),
			allServices:  []string{"s3"},
			golden:       "custom-scan.json.golden",
		},
		{
			name: "compliance report summary",
			options: flag.Options{
				Options: trivyflag.Options{
					AWSOptions: trivyflag.AWSOptions{
						Region:   "us-east-1",
						Services: []string{"s3"},
						Account:  "12345678",
					},
					ReportOptions: trivyflag.ReportOptions{
						Compliance: spec.ComplianceSpec{
							Spec: iacTypes.Spec{
								ID:          "@testdata/example-spec.yaml",
								Title:       "my-custom-spec",
								Description: "My fancy spec",
								Version:     "1.2",
								Controls: []iacTypes.Control{
									{
										ID:          "1.1",
										Name:        "Unencrypted S3 bucket",
										Description: "S3 Buckets should be encrypted to protect the data that is stored within them if access is compromised.",
										Checks: []iacTypes.SpecCheck{
											{ID: "AVD-AWS-0088"},
										},
										Severity: "HIGH",
									},
								},
							},
						},
						Format:       "table",
						ReportFormat: "summary",
					},
					RegoOptions: trivyflag.RegoOptions{
						SkipCheckUpdate: true,
					},
				},
				CloudOptions: flag.CloudOptions{
					MaxCacheAge: time.Hour * 24 * 365 * 100,
				},
			},
			cacheContent: "testdata/s3onlycache.json",
			allServices:  []string{"s3"},
			golden:       "compliance-report-summary.golden",
		},
		{
			name: "scan an unsupported service",
			options: flag.Options{
				Options: trivyflag.Options{
					RegoOptions: trivyflag.RegoOptions{SkipCheckUpdate: true},
					AWSOptions: trivyflag.AWSOptions{
						Region:   "us-east-1",
						Account:  "123456789",
						Services: []string{"theultimateservice"},
					},
					MisconfOptions: trivyflag.MisconfOptions{IncludeNonFailures: true},
				},
				CloudOptions: flag.CloudOptions{
					MaxCacheAge: time.Hour * 24 * 365 * 100,
				},
			},
			cacheContent: "testdata/s3onlycache.json",
			expectErr:    true,
		},
		{
			name: "scan every service",
			options: flag.Options{
				Options: trivyflag.Options{
					RegoOptions: trivyflag.RegoOptions{SkipCheckUpdate: true},
					AWSOptions: trivyflag.AWSOptions{
						Region:  "us-east-1",
						Account: "123456789",
					},
					MisconfOptions: trivyflag.MisconfOptions{IncludeNonFailures: true},
				},
				CloudOptions: flag.CloudOptions{
					MaxCacheAge: time.Hour * 24 * 365 * 100,
				},
			},
			cacheContent: "testdata/s3andcloudtrailcache.json",
			allServices: []string{
				"s3",
				"cloudtrail",
			},
			golden: "s3-cloud-trail-scan.json.golden",
		},
		{
			name: "skip certain services and include specific services",
			options: flag.Options{
				Options: trivyflag.Options{
					RegoOptions: trivyflag.RegoOptions{SkipCheckUpdate: true},
					AWSOptions: trivyflag.AWSOptions{
						Region:       "us-east-1",
						Services:     []string{"s3"},
						SkipServices: []string{"cloudtrail"},
						Account:      "123456789",
					},
					MisconfOptions: trivyflag.MisconfOptions{IncludeNonFailures: true},
				},
				CloudOptions: flag.CloudOptions{
					MaxCacheAge: time.Hour * 24 * 365 * 100,
				},
			},
			cacheContent: "testdata/s3andcloudtrailcache.json",
			allServices: []string{
				"s3",
				"cloudtrail",
			},
			// we skip cloudtrail but still expect results from it as it is cached
			golden: "s3-cloud-trail-scan.json.golden",
		},
		{
			name: "only skip certain services but scan the rest",
			options: flag.Options{
				Options: trivyflag.Options{
					RegoOptions: trivyflag.RegoOptions{SkipCheckUpdate: true},
					AWSOptions: trivyflag.AWSOptions{
						Region: "us-east-1",
						SkipServices: []string{
							"cloudtrail",
							"iam",
						},
						Account: "12345678",
					},
					MisconfOptions: trivyflag.MisconfOptions{IncludeNonFailures: true},
				},
				CloudOptions: flag.CloudOptions{
					MaxCacheAge: time.Hour * 24 * 365 * 100,
				},
			},
			allServices: []string{
				"s3",
				"cloudtrail",
				"iam",
			},
			cacheContent: "testdata/s3onlycache.json",
			golden:       "s3-scan.json.golden",
		},
		{
			name: "fail - service specified to both include and exclude",
			options: flag.Options{
				Options: trivyflag.Options{
					RegoOptions: trivyflag.RegoOptions{SkipCheckUpdate: true},
					AWSOptions: trivyflag.AWSOptions{
						Region:       "us-east-1",
						Services:     []string{"s3"},
						SkipServices: []string{"s3"},
						Account:      "123456789",
					},
					MisconfOptions: trivyflag.MisconfOptions{IncludeNonFailures: true},
				},
				CloudOptions: flag.CloudOptions{
					MaxCacheAge: time.Hour * 24 * 365 * 100,
				},
			},
			cacheContent: "testdata/s3andcloudtrailcache.json",
			expectErr:    true,
		},
		{
			name: "ignore findings with .trivyignore",
			options: flag.Options{
				Options: trivyflag.Options{
					RegoOptions: trivyflag.RegoOptions{SkipCheckUpdate: true},
					AWSOptions: trivyflag.AWSOptions{
						Region:   "us-east-1",
						Services: []string{"s3"},
						Account:  "12345678",
					},
					MisconfOptions: trivyflag.MisconfOptions{IncludeNonFailures: true},
				},
				CloudOptions: flag.CloudOptions{
					MaxCacheAge: time.Hour * 24 * 365 * 100,
				},
			},
			cacheContent: "testdata/s3onlycache.json",
			allServices:  []string{"s3"},
			ignoreFile:   "testdata/.trivyignore",
			golden:       "s3-scan-with-ignores.json.golden",
		},
	}

	ctx := clock.With(context.Background(), time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC))
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.allServices != nil {
				oldAllSupportedServicesFunc := allSupportedServicesFunc
				allSupportedServicesFunc = func() []string {
					return test.allServices
				}
				defer func() {
					allSupportedServicesFunc = oldAllSupportedServicesFunc
				}()
			}

			output := bytes.NewBuffer(nil)
			test.options.SetOutputWriter(output)
			test.options.Debug = true
			test.options.SkipCheckUpdate = true
			test.options.GlobalOptions.Timeout = time.Minute
			if test.options.Format == "" {
				test.options.Format = "json"
			}
			test.options.Severities = []dbTypes.Severity{
				dbTypes.SeverityUnknown,
				dbTypes.SeverityLow,
				dbTypes.SeverityMedium,
				dbTypes.SeverityHigh,
				dbTypes.SeverityCritical,
			}

			if test.regoPolicy != "" {
				require.NoError(t, os.MkdirAll(filepath.Join(regoDir, "policies"), 0755))
				require.NoError(t, os.WriteFile(filepath.Join(regoDir, "policies", "user.rego"), []byte(test.regoPolicy), 0600))
			}

			if test.inputData != "" {
				require.NoError(t, os.MkdirAll(filepath.Join(regoDir, "data"), 0755))
				require.NoError(t, os.WriteFile(filepath.Join(regoDir, "data", "data.json"), []byte(test.inputData), 0600))
			}

			if test.cacheContent != "" {
				cacheRoot := t.TempDir()
				test.options.CacheDir = cacheRoot
				cacheFile := filepath.Join(cacheRoot, "cloud", "aws", test.options.Account, test.options.Region, "data.json")
				require.NoError(t, os.MkdirAll(filepath.Dir(cacheFile), 0700))

				cacheData, err := os.ReadFile(test.cacheContent)
				require.NoError(t, err, test.name)

				require.NoError(t, os.WriteFile(cacheFile, cacheData, 0600))
			}

			if test.ignoreFile != "" {
				test.options.ReportOptions.IgnoreFile = test.ignoreFile
			}

			err := Run(ctx, test.options)
			if test.expectErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			want, err := os.ReadFile(filepath.Join("testdata", test.golden))
			require.NoError(t, err)

			assert.Equal(t, string(want), output.String())
		})
	}
}
