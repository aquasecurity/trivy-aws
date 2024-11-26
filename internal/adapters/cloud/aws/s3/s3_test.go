package s3

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	s3api "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-aws/internal/adapters/cloud/aws"
	"github.com/aquasecurity/trivy-aws/internal/adapters/cloud/aws/test"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/s3"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

type publicAccessBlock struct {
	blockPublicAcls       bool
	blockPublicPolicy     bool
	ignorePublicAcls      bool
	restrictPublicBuckets bool
}

type bucketDetails struct {
	bucketName          string
	acl                 s3types.BucketCannedACL
	encrypted           bool
	loggingEnabled      bool
	loggingTargetBucket string
	versioningEnabled   bool
	publicAccessBlock   *publicAccessBlock
}

func Test_S3BucketACLs(t *testing.T) {

	tests := []struct {
		name    string
		details bucketDetails
	}{
		{
			name: "simple bucket with public-read acl",
			details: bucketDetails{
				bucketName: "test-bucket",
				acl:        s3types.BucketCannedACLPublicRead,
				encrypted:  false,
			},
		},
		{
			name: "simple bucket with authenticated-read acl",
			details: bucketDetails{
				bucketName: "wide-open-bucket",
				acl:        s3types.BucketCannedACLAuthenticatedRead,
				encrypted:  false,
			},
		},
		{
			name: "simple bucket with public-read-write acl",
			details: bucketDetails{
				bucketName: "public-read-write-bucket",
				acl:        s3types.BucketCannedACLPublicReadWrite,
				encrypted:  false,
			},
		},
		{
			name: "simple bucket with private acl and encryption",
			details: bucketDetails{
				bucketName: "private-bucket",
				acl:        s3types.BucketCannedACLPrivate,
				encrypted:  true,
			},
		},
	}

	ra, stack, err := test.CreateLocalstackAdapter(t)
	defer func() { _ = stack.Stop() }()
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bootstrapBucket(t, ra, tt.details)

			testState := &state.State{}
			s3Adapter := &adapter{}
			err = s3Adapter.Adapt(ra, testState)
			require.NoError(t, err)

			require.Len(t, testState.AWS.S3.Buckets, 1)
			var got s3.Bucket
			for _, b := range testState.AWS.S3.Buckets {
				if b.Name.Value() == tt.details.bucketName {
					got = b
					break
				}
			}

			assert.Equal(t, tt.details.bucketName, got.Name.Value())
			assert.Equal(t, string(tt.details.acl), got.ACL.Value())
			if tt.details.encrypted {
				// Amazon S3 now applies server-side encryption with Amazon S3 managed keys (SSE-S3)
				assert.Equal(t, string(s3types.ServerSideEncryptionAes256), got.Encryption.Algorithm.Value())
			}
			removeBucket(t, ra, tt.details)
		})
	}
}

func Test_S3BucketLogging(t *testing.T) {

	tests := []struct {
		name    string
		details bucketDetails
	}{
		{
			name: "simple bucket with no logging enabled",
			details: bucketDetails{
				bucketName:     "test-bucket",
				acl:            "public-read",
				loggingEnabled: false,
			},
		},
		{
			name: "simple bucket with logging enabled",
			details: bucketDetails{
				bucketName:          "test-bucket",
				acl:                 "public-read",
				loggingEnabled:      true,
				loggingTargetBucket: "access-logs",
			},
		},
	}

	ra, stack, err := test.CreateLocalstackAdapter(t)
	defer func() { _ = stack.Stop() }()
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bootstrapBucket(t, ra, tt.details)

			testState := &state.State{}
			s3Adapter := &adapter{}
			err = s3Adapter.Adapt(ra, testState)
			require.NoError(t, err)

			if tt.details.loggingEnabled {
				assert.Len(t, testState.AWS.S3.Buckets, 2)
			} else {
				assert.Len(t, testState.AWS.S3.Buckets, 1)
			}

			got := findBucketByName(testState.AWS.S3.Buckets, tt.details.bucketName)

			assert.Equal(t, tt.details.bucketName, got.Name.Value())
			if tt.details.loggingEnabled {
				assert.Equal(t, tt.details.loggingTargetBucket, got.Logging.TargetBucket.Value())
				assert.Equal(t, tt.details.loggingEnabled, got.Logging.Enabled.Value())
			} else {
				assert.False(t, got.Logging.Enabled.Value())
			}
			removeBucket(t, ra, tt.details)
		})
	}
}

func Test_S3BucketVersioning(t *testing.T) {

	tests := []struct {
		name    string
		details bucketDetails
	}{
		{
			name: "simple bucket with no versioning enabled",
			details: bucketDetails{
				bucketName:        "test-bucket-no-versioning",
				acl:               "public-read",
				versioningEnabled: false,
			},
		},
		{
			name: "simple bucket with versioning enabled",
			details: bucketDetails{
				bucketName:        "test-bucket-versioning",
				acl:               "public-read",
				versioningEnabled: true,
			},
		},
	}

	ra, stack, err := test.CreateLocalstackAdapter(t)
	defer func() { _ = stack.Stop() }()
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bootstrapBucket(t, ra, tt.details)

			testState := &state.State{}
			s3Adapter := &adapter{}
			err = s3Adapter.Adapt(ra, testState)
			require.NoError(t, err)

			assert.Len(t, testState.AWS.S3.Buckets, 1)
			got := findBucketByName(testState.AWS.S3.Buckets, tt.details.bucketName)

			assert.Equal(t, tt.details.bucketName, got.Name.Value())
			if tt.details.loggingEnabled {
				assert.Equal(t, tt.details.loggingTargetBucket, got.Logging.TargetBucket.Value())
				assert.Equal(t, tt.details.loggingEnabled, got.Logging.Enabled.Value())
			} else {
				assert.False(t, got.Logging.Enabled.Value())
			}
			removeBucket(t, ra, tt.details)
		})
	}
}

func Test_S3PublicAccessBlock(t *testing.T) {

	tests := []struct {
		name    string
		details bucketDetails
	}{
		{
			name: "simple bucket with public access block that blocks public acls",
			details: bucketDetails{
				bucketName: "test-bucket-public-access-block",
				publicAccessBlock: &publicAccessBlock{
					blockPublicAcls: true,
				},
			},
		},
		{
			name: "simple bucket with public access block that ignore public acls",
			details: bucketDetails{
				bucketName: "test-bucket-public-access-block",
				publicAccessBlock: &publicAccessBlock{
					ignorePublicAcls: true,
				},
			},
		},
		{
			name: "simple bucket with public access block that restricts public buckets",
			details: bucketDetails{
				bucketName: "test-bucket-public-access-block",
				publicAccessBlock: &publicAccessBlock{
					restrictPublicBuckets: true,
				},
			},
		},
		{
			name: "simple bucket with public access block that blocks public policies",
			details: bucketDetails{
				bucketName: "test-bucket-public-access-block",
				publicAccessBlock: &publicAccessBlock{
					blockPublicPolicy: true,
				},
			},
		},
	}

	ra, stack, err := test.CreateLocalstackAdapter(t)
	defer func() { _ = stack.Stop() }()
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bootstrapBucket(t, ra, tt.details)

			testState := &state.State{}
			s3Adapter := &adapter{}
			err = s3Adapter.Adapt(ra, testState)
			require.NoError(t, err)

			assert.Len(t, testState.AWS.S3.Buckets, 1)
			got := findBucketByName(testState.AWS.S3.Buckets, tt.details.bucketName)

			assert.Equal(t, tt.details.bucketName, got.Name.Value())
			if tt.details.publicAccessBlock != nil {
				assert.Equal(t, tt.details.publicAccessBlock.blockPublicAcls, got.PublicAccessBlock.BlockPublicACLs.Value())
				assert.Equal(t, tt.details.publicAccessBlock.ignorePublicAcls, got.PublicAccessBlock.IgnorePublicACLs.Value())
				assert.Equal(t, tt.details.publicAccessBlock.restrictPublicBuckets, got.PublicAccessBlock.RestrictPublicBuckets.Value())
				assert.Equal(t, tt.details.publicAccessBlock.blockPublicPolicy, got.PublicAccessBlock.BlockPublicPolicy.Value())
			} else {
				require.Nil(t, got.PublicAccessBlock)
			}
			removeBucket(t, ra, tt.details)
		})
	}
}

func bootstrapBucket(t *testing.T, ra *aws.RootAdapter, spec bucketDetails) {

	api := s3api.NewFromConfig(ra.SessionConfig())

	_, err := api.CreateBucket(ra.Context(), &s3api.CreateBucketInput{
		Bucket: awssdk.String(spec.bucketName),
		ACL:    spec.acl,
	})
	require.NoError(t, err)

	if spec.encrypted {
		bootstrapBucketEncryption(t, api, ra.Context(), spec)
	}

	if spec.loggingEnabled {
		bootstrapBucketLogging(t, api, ra.Context(), spec)
	}

	if spec.versioningEnabled {
		bootstrapBucketVersioning(t, api, ra.Context(), spec)
	}

	if spec.publicAccessBlock != nil {
		createPublicAccessBlock(t, api, ra.Context(), spec)
	}
}

func bootstrapBucketEncryption(t *testing.T, api *s3api.Client, ctx context.Context, spec bucketDetails) {
	_, err := api.PutBucketEncryption(ctx, &s3api.PutBucketEncryptionInput{
		Bucket: awssdk.String(spec.bucketName),
		ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
			Rules: []s3types.ServerSideEncryptionRule{
				{
					ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
						SSEAlgorithm: s3types.ServerSideEncryptionAes256,
					},
					BucketKeyEnabled: awssdk.Bool(true),
				},
			},
		},
	})
	require.NoError(t, err)

}

func bootstrapBucketLogging(t *testing.T, api *s3api.Client, ctx context.Context, spec bucketDetails) {
	_, err := api.CreateBucket(ctx, &s3api.CreateBucketInput{
		Bucket: &spec.loggingTargetBucket,
	})
	require.NoError(t, err)

	_, err = api.PutBucketLogging(ctx, &s3api.PutBucketLoggingInput{
		Bucket: awssdk.String(spec.bucketName),
		BucketLoggingStatus: &s3types.BucketLoggingStatus{
			LoggingEnabled: &s3types.LoggingEnabled{
				TargetBucket: awssdk.String(spec.loggingTargetBucket),
				TargetPrefix: awssdk.String("/logs"),
				TargetGrants: []s3types.TargetGrant{
					{
						Permission: s3types.BucketLogsPermissionWrite,
						Grantee: &s3types.Grantee{
							Type: s3types.TypeGroup,
							URI:  awssdk.String("http://acs.amazonaws.com/groups/s3/LogDelivery"),
						},
					},
				},
			},
		},
	})
	require.NoError(t, err)
}

func bootstrapBucketVersioning(t *testing.T, api *s3api.Client, ctx context.Context, spec bucketDetails) {
	_, err := api.PutBucketVersioning(ctx, &s3api.PutBucketVersioningInput{
		Bucket: awssdk.String(spec.bucketName),
		VersioningConfiguration: &s3types.VersioningConfiguration{
			Status: s3types.BucketVersioningStatusEnabled,
		},
	})
	require.NoError(t, err)
}

func createPublicAccessBlock(t *testing.T, api *s3api.Client, ctx context.Context, spec bucketDetails) {
	_, err := api.PutPublicAccessBlock(ctx, &s3api.PutPublicAccessBlockInput{
		Bucket: awssdk.String(spec.bucketName),
		PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
			BlockPublicAcls:       awssdk.Bool(spec.publicAccessBlock.blockPublicAcls),
			IgnorePublicAcls:      awssdk.Bool(spec.publicAccessBlock.ignorePublicAcls),
			RestrictPublicBuckets: awssdk.Bool(spec.publicAccessBlock.restrictPublicBuckets),
			BlockPublicPolicy:     awssdk.Bool(spec.publicAccessBlock.blockPublicPolicy),
		},
	})
	require.NoError(t, err)
}

func removeBucket(t *testing.T, ra *aws.RootAdapter, spec bucketDetails) {

	api := s3api.NewFromConfig(ra.SessionConfig())

	_, err := api.DeleteBucket(ra.Context(), &s3api.DeleteBucketInput{
		Bucket: awssdk.String(spec.bucketName),
	})
	require.NoError(t, err)
}

func findBucketByName(buckets []s3.Bucket, name string) s3.Bucket {
	for _, b := range buckets {
		if b.Name.Value() == name {
			return b
		}
	}
	return s3.Bucket{}
}
