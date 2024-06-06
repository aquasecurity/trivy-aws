//go:build integration

package commands

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/localstack"

	"github.com/aquasecurity/trivy/pkg/flag"
)

const (
	localstackVersion = "2.2.0"
)

func TestAwsCommandRun(t *testing.T) {
	tests := []struct {
		name    string
		options flag.Options
		envs    map[string]string
		wantErr string
	}{
		{
			name: "fail without region",
			options: flag.Options{
				RegoOptions: flag.RegoOptions{SkipCheckUpdate: true},
			},
			envs: map[string]string{
				"AWS_ACCESS_KEY_ID":     "test",
				"AWS_SECRET_ACCESS_KEY": "test",
			},
			wantErr: "aws region is required",
		},
		{
			name: "fail without creds",
			envs: map[string]string{
				"AWS_PROFILE": "non-existent-profile",
			},
			options: flag.Options{
				RegoOptions: flag.RegoOptions{SkipCheckUpdate: true},
				AWSOptions: flag.AWSOptions{
					Region: "us-east-1",
				},
			},
			wantErr: "non-existent-profile",
		},
	}

	ctx := context.Background()

	localstackC, addr, err := setupLocalStack(ctx, localstackVersion)
	require.NoError(t, err)
	defer localstackC.Terminate(ctx)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			tt.options.AWSOptions.Endpoint = addr
			tt.options.GlobalOptions.Timeout = time.Minute

			for k, v := range tt.envs {
				t.Setenv(k, v)
			}

			err := Run(context.Background(), tt.options)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			}
			assert.NoError(t, err)
		})
	}

}

func setupLocalStack(ctx context.Context, version string) (*localstack.LocalStackContainer, string, error) {

	if err := os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true"); err != nil {
		return nil, "", err
	}

	container, err := localstack.RunContainer(ctx, testcontainers.CustomizeRequest(
		testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image: "localstack/localstack:" + version,
				HostConfigModifier: func(hostConfig *dockercontainer.HostConfig) {
					hostConfig.AutoRemove = true
				},
			},
		},
	))
	if err != nil {
		return nil, "", err
	}

	p, err := container.MappedPort(ctx, "4566/tcp")
	if err != nil {
		return nil, "", err
	}

	provider, err := testcontainers.NewDockerProvider()
	if err != nil {
		return nil, "", err
	}
	defer provider.Close()

	host, err := provider.DaemonHost(ctx)
	if err != nil {
		return nil, "", err
	}

	return container, fmt.Sprintf("http://%s:%d", host, p.Int()), nil
}
