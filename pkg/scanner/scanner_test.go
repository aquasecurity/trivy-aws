package scanner

import (
	"context"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/rds"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/authorization"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type testStruct struct {
	name      string
	scanner   *Scanner
	fwApplied framework.Framework
}

func TestScanner_GetRegisteredRules(t *testing.T) {
	testCases := []testStruct{
		{
			name:      "default rules",
			scanner:   &Scanner{},
			fwApplied: framework.Default,
		},
		{
			name: "get framework rules",
			scanner: &Scanner{
				frameworks: []framework.Framework{framework.CIS_AWS_1_2},
			},
			fwApplied: framework.CIS_AWS_1_2,
		},
		{
			name: "get spec rules",
			scanner: &Scanner{
				spec: "awscis1.2",
			},
			fwApplied: framework.CIS_AWS_1_2,
		},
		{
			name: "invalid spec",
			scanner: &Scanner{
				spec: "invalid spec",
				// we still expect default rules to work
			},
			fwApplied: framework.Default,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, r := range tc.scanner.getRules() {
				assertRules(t, r.Rule, tc)
			}
		})
	}
}

func assertRules(t *testing.T, r scan.Rule, tc testStruct) {
	t.Helper()

	if _, ok := r.Frameworks[tc.fwApplied]; !ok {
		assert.FailNowf(t, "unexpected rule found", "rule: %s in test case: %s", r.AVDID, tc.name)
	}
}

func Test_AWSInputSelectors(t *testing.T) {
	testCases := []struct {
		name            string
		srcFS           fs.FS
		dataFS          fs.FS
		state           state.State
		expectedResults struct {
			totalResults int
			summaries    []string
		}
	}{
		{
			name: "selector is not defined",
			srcFS: createFS(map[string]string{
				"policies/rds_policy.rego": `# METADATA
# title: "RDS Publicly Accessible"
package builtin.aws.rds.aws0999

deny[res] {
	res := true
}
`,
				"policies/cloudtrail_policy.rego": `# METADATA
# title: "CloudTrail Bucket Delete Policy"
package builtin.aws.cloudtrail.aws0888

deny[res] {
	res := true
}
`,
			}),
			state: state.State{AWS: aws.AWS{
				RDS: rds.RDS{
					Instances: []rds.Instance{
						{Metadata: iacTypes.Metadata{},
							PublicAccess: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
						},
					},
				},
				// note: there is no CloudTrail resource in our AWS state (so we expect no results for it)
			}},
			expectedResults: struct {
				totalResults int
				summaries    []string
			}{totalResults: 2, summaries: []string{"RDS Publicly Accessible", "CloudTrail Bucket Delete Policy"}},
		},
		{
			name: "selector is empty",
			srcFS: createFS(map[string]string{
				"policies/rds_policy.rego": `# METADATA
# title: "RDS Publicly Accessible"
package builtin.aws.rds.aws0999

deny[res] {
	res := true
}
`,
				"policies/cloudtrail_policy.rego": `# METADATA
# title: "CloudTrail Bucket Delete Policy"
package builtin.aws.cloudtrail.aws0888

deny[res] {
	res := true
}
`,
			}),
			state: state.State{AWS: aws.AWS{
				RDS: rds.RDS{
					Instances: []rds.Instance{
						{Metadata: iacTypes.Metadata{},
							PublicAccess: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
						},
					},
				},
			}},
			expectedResults: struct {
				totalResults int
				summaries    []string
			}{totalResults: 2, summaries: []string{"RDS Publicly Accessible", "CloudTrail Bucket Delete Policy"}},
		},
		{
			name: "selector without subtype",
			srcFS: createFS(map[string]string{
				"policies/rds_policy.rego": `# METADATA
# title: "RDS Publicly Accessible"
# custom:
#   input:
#     selector:
#     - type: cloud
package builtin.aws.rds.aws0999

deny[res] {
	res := true
}
`,
				"policies/cloudtrail_policy.rego": `# METADATA
# title: "CloudTrail Bucket Delete Policy"
# custom:
#   input:
#     selector:
#     - type: cloud
package builtin.aws.cloudtrail.aws0888

deny[res] {
	res := true
}
`,
			}),
			state: state.State{AWS: aws.AWS{
				RDS: rds.RDS{
					Instances: []rds.Instance{
						{Metadata: iacTypes.Metadata{},
							PublicAccess: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
						},
					},
				},
				// note: there is no CloudTrail resource in our AWS state (so we expect no results for it)
			}},
			expectedResults: struct {
				totalResults int
				summaries    []string
			}{totalResults: 2, summaries: []string{"RDS Publicly Accessible", "CloudTrail Bucket Delete Policy"}},
		},
		{
			name: "conflicting selectors",
			srcFS: createFS(map[string]string{
				"policies/rds_policy.rego": `# METADATA
# title: "RDS Publicly Accessible"
# custom:
#   provider: aws
#   service: rds
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - provider: aws
#           service: ec2
package builtin.aws.rds.aws0999

deny[res] {
	res := true
}
`,
			}),

			state: state.State{AWS: aws.AWS{
				RDS: rds.RDS{
					Instances: []rds.Instance{
						{Metadata: iacTypes.Metadata{},
							PublicAccess: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
						},
					},
				},
			}},
			expectedResults: struct {
				totalResults int
				summaries    []string
			}{totalResults: 0},
		},
		{
			name: "selector is defined with empty subtype",
			srcFS: createFS(map[string]string{
				"policies/rds_policy.rego": `# METADATA
# title: "RDS Publicly Accessible"
# custom:
#   input:
#     selector:
#     - type: cloud
package builtin.aws.rds.aws0999

deny[res] {
	res := true
}
`,
				"policies/cloudtrail_policy.rego": `# METADATA
# title: "CloudTrail Bucket Delete Policy"
# custom:
#   input:
#     selector:
#     - type: cloud
package builtin.aws.cloudtrail.aws0888

deny[res] {
	res := true
}
`,
			}),
			state: state.State{AWS: aws.AWS{
				RDS: rds.RDS{
					Instances: []rds.Instance{
						{Metadata: iacTypes.Metadata{},
							PublicAccess: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
						},
					},
				},
				// note: there is no CloudTrail resource in our AWS state (so we expect no results for it)
			}},
			expectedResults: struct {
				totalResults int
				summaries    []string
			}{totalResults: 2, summaries: []string{"RDS Publicly Accessible", "CloudTrail Bucket Delete Policy"}},
		},
		{
			name: "single cloud, single selector",
			srcFS: createFS(map[string]string{
				"policies/rds_policy.rego": `# METADATA
# title: "RDS Publicly Accessible"
# description: "Ensures RDS instances are not launched into the public cloud."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html
# custom:
#   avd_id: AVD-AWS-0999
#   provider: aws
#   service: rds
#   severity: HIGH
#   short_code: enable-public-access
#   recommended_action: "Remove the public endpoint from the RDS instance'"
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - provider: aws
#           service: rds
package builtin.aws.rds.aws0999

deny[res] {
	instance := input.aws.rds.instances[_]
	instance.publicaccess.value
	res := result.new("Instance has Public Access enabled", instance.publicaccess)
}
`,
				"policies/cloudtrail_policy.rego": `# METADATA
# title: "CloudTrail Bucket Delete Policy"
# description: "Ensures CloudTrail logging bucket has a policy to prevent deletion of logs without an MFA token"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete
# custom:
#   avd_id: AVD-AWS-0888
#   provider: aws
#   service: cloudtrail
#   severity: HIGH
#   short_code: bucket_delete
#   recommended_action: "Enable MFA delete on the CloudTrail bucket"
#   input:
#     selector:
#     - type: cloud
#       subtypes: 
#         - provider: aws 
#           service: cloudtrail
package builtin.aws.cloudtrail.aws0888

deny[res] {
	trail := input.aws.cloudtrail.trails[_]
	trail.bucketname.value != ""
    bucket := input.aws.s3.buckets[_]
    bucket.name.value == trail.bucketname.value
    not bucket.versioning.mfadelete.value
	res := result.new("Bucket has MFA delete disabled", bucket.name)
}
`,
			}),
			state: state.State{AWS: aws.AWS{
				RDS: rds.RDS{
					Instances: []rds.Instance{
						{Metadata: iacTypes.Metadata{},
							PublicAccess: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
						},
					},
				},
				// note: there is no CloudTrail resource in our AWS state (so we expect no results for it)
			}},
			expectedResults: struct {
				totalResults int
				summaries    []string
			}{totalResults: 1, summaries: []string{"RDS Publicly Accessible"}},
		},
		{
			name: "multi cloud, single selector, same named service",
			srcFS: createFS(map[string]string{
				"policies/azure_iam_policy.rego": `# METADATA
# title: "Azure IAM Policy"
# custom:
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - provider: azure 
#           service: iam 
package builtin.azure.iam.iam1234

deny[res] {
	res := true
}
`,
				"policies/aws_iam_policy.rego": `# METADATA
# title: "AWS IAM Policy"
# custom:
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - provider: aws 
#           service: iam 
package builtin.aws.iam.iam5678

deny[res] {
	res := true
}
`,
			}),
			state: state.State{
				AWS: aws.AWS{
					IAM: iam.IAM{
						PasswordPolicy: iam.PasswordPolicy{
							MinimumLength: iacTypes.Int(1, iacTypes.NewTestMetadata()),
						}},
				},
				Azure: azure.Azure{
					Authorization: authorization.Authorization{
						RoleDefinitions: []authorization.RoleDefinition{{
							Metadata: iacTypes.NewTestMetadata(),
							Permissions: []authorization.Permission{
								{
									Metadata: iacTypes.NewTestMetadata(),
									Actions: []iacTypes.StringValue{
										iacTypes.String("*", iacTypes.NewTestMetadata()),
									},
								},
							},
							AssignableScopes: []iacTypes.StringValue{
								iacTypes.StringUnresolvable(iacTypes.NewTestMetadata()),
							}},
						}},
				},
				// note: there is no Azure IAM in our cloud state (so we expect no results for it)
			},
			expectedResults: struct {
				totalResults int
				summaries    []string
			}{totalResults: 1, summaries: []string{"AWS IAM Policy"}},
		},
		{
			name: "single cloud, single selector with config data",
			srcFS: createFS(map[string]string{
				"policies/rds_policy.rego": `# METADATA
# title: "RDS Publicly Accessible"
# description: "Ensures RDS instances are not launched into the public cloud."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html
# custom:
#   avd_id: AVD-AWS-0999
#   provider: aws
#   service: rds
#   severity: HIGH
#   short_code: enable-public-access
#   recommended_action: "Remove the public endpoint from the RDS instance'"
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - provider: aws
#           service: rds
package builtin.aws.rds.aws0999
import data.settings.DS0999.ignore_deletion_protection
deny[res] {
	instance := input.aws.rds.instances[_]
	instance.publicaccess.value
	not ignore_deletion_protection
	res := result.new("Instance has Public Access enabled", instance.publicaccess)
}
`,
				"policies/rds_cmk_encryption.rego": `# METADATA
# title: "RDS CMK Encryption"
# description: "Ensures RDS instances are encrypted with CMK."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html
# custom:
#   avd_id: AVD-AWS-0998
#   provider: aws
#   service: rds
#   severity: HIGH
#   short_code: rds_cmk_encryption
#   recommended_action: "CMK Encrypt RDS instance'"
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - provider: aws
#           service: rds
package builtin.aws.rds.aws0998
import data.settings.DS0998.rds_desired_encryption_level
deny[res] {
	instance := input.aws.rds.instances[_]
	rds_desired_encryption_level <= 2
	res := result.new("Instance is not CMK encrypted", instance.publicaccess)
}
`,
			}),
			dataFS: createFS(map[string]string{
				"config-data/data.json": `{
    "settings": {
		"DS0999": {
			"ignore_deletion_protection": false
		},
        "DS0998": {
            "rds_desired_encryption_level": 2
        }
    }
}
`,
			}),
			state: state.State{AWS: aws.AWS{
				RDS: rds.RDS{
					Instances: []rds.Instance{
						{Metadata: iacTypes.Metadata{},
							PublicAccess: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
						},
					},
				},
			}},
			expectedResults: struct {
				totalResults int
				summaries    []string
			}{totalResults: 2, summaries: []string{"RDS Publicly Accessible", "RDS CMK Encryption"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var scannerOpts []options.ScannerOption
			if tc.dataFS != nil {
				scannerOpts = append(scannerOpts, rego.WithPolicyDirs("config-data"))
			}
			scannerOpts = append(scannerOpts, rego.WithEmbeddedPolicies(false))
			scannerOpts = append(scannerOpts, rego.WithPolicyFilesystem(tc.srcFS))
			scannerOpts = append(scannerOpts, rego.WithPolicyDirs("policies"))
			scanner := New(scannerOpts...)

			results, err := scanner.Scan(context.TODO(), &tc.state)
			require.NoError(t, err, tc.name)
			require.Equal(t, tc.expectedResults.totalResults, len(results), tc.name)
			for i := range results.GetFailed() {
				require.Contains(t, tc.expectedResults.summaries, results.GetFailed()[i].Rule().Summary, tc.name)
			}
		})
	}
}

func createFS(files map[string]string) fs.FS {
	fsys := make(fstest.MapFS)
	for path, content := range files {
		fsys[path] = &fstest.MapFile{Data: []byte(content)}
	}
	return fsys
}
