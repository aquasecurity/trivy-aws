package test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/stretchr/testify/require"

	localstack "github.com/aquasecurity/go-mock-aws"
	"github.com/aquasecurity/trivy-aws/internal/adapters/cloud/aws"
	"github.com/aquasecurity/trivy-aws/pkg/progress"
	"github.com/aquasecurity/trivy/pkg/log"
)

func getOrCreateLocalStack(ctx context.Context) (*localstack.Stack, error) {
	_ = os.Setenv("DOCKER_API_VERSION", "1.41")
	stack := localstack.New()

	initScripts, err := localstack.WithInitScriptMount(
		"../test/init-scripts/init-aws.sh",
		"Bootstrap Complete")
	if err != nil {
		return nil, err
	}

	log.New(log.NewHandler(os.Stdout, &log.Options{Level: slog.LevelDebug}))

	err = stack.Start(false, initScripts, localstack.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	return stack, nil
}

func CreateLocalstackAdapter(t *testing.T) (*aws.RootAdapter, *localstack.Stack, error) {
	ctx := context.Background()
	l, err := getOrCreateLocalStack(ctx)
	require.NoError(t, err)

	cfg, err := createTestConfig(ctx, l)
	require.NoError(t, err)

	ra := aws.NewRootAdapter(ctx, cfg, progress.NoProgress, log.New(log.NewHandler(io.Discard, nil)))
	require.NotNil(t, ra)
	return ra, l, err
}

func createTestConfig(ctx context.Context, l *localstack.Stack) (awssdk.Config, error) {
	return config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithEndpointResolverWithOptions(awssdk.EndpointResolverWithOptionsFunc(func(_, _ string, _ ...interface{}) (awssdk.Endpoint, error) {
			return awssdk.Endpoint{
				PartitionID:       "aws",
				SigningRegion:     "us-east-1",
				URL:               l.EndpointURL(),
				HostnameImmutable: true,
			}, nil
		})),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("dummy", "dummy", "dummy")),
	)
}
