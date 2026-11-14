package test

import (
	"bytes"
	"io"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/aquasecurity/trivy-aws/internal/adapters/cloud/aws"
)

const (
	emulatorPort = "9297"
	// emulatorDir is where the emulator writes its credentials and certificate inside the container.
	emulatorDir = "/home/emulator/.aws/emulator/" + emulatorPort
)

// CreateEmulatorAdapter starts AWS Emulator in a container and returns an adapter connected to it.
// The image is built by "make emulator-image" and passed in AWS_EMULATOR_IMAGE.
// Without it the test is skipped, but in CI it fails so that the tests are not lost unnoticed.
// The container is removed when the test ends.
func CreateEmulatorAdapter(t *testing.T) *aws.RootAdapter {
	image := os.Getenv("AWS_EMULATOR_IMAGE")
	if image == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("AWS_EMULATOR_IMAGE is not set, run the tests with \"make test\"")
		}
		t.Skip("AWS_EMULATOR_IMAGE is not set, run the tests with \"make test\"")
	}

	ctx := t.Context()

	ctr, err := testcontainers.Run(ctx, image,
		testcontainers.WithExposedPorts(emulatorPort+"/tcp"),
		testcontainers.WithWaitStrategy(wait.ForLog("emulator server information")),
	)
	testcontainers.CleanupContainer(t, ctr)
	require.NoError(t, err)

	endpoint, err := ctr.PortEndpoint(ctx, emulatorPort+"/tcp", "https")
	require.NoError(t, err)

	cfg, err := createTestConfig(ctx, endpoint,
		config.WithCredentialsProvider(emulatorCredentials(t, ctr)),
		config.WithCustomCABundle(bytes.NewReader(copyFromContainer(t, ctr, "ca.pem"))),
	)
	require.NoError(t, err)

	return newRootAdapter(ctx, cfg)
}

// emulatorCredentials returns the keys that the emulator generated at startup.
// It accepts only requests signed with them.
func emulatorCredentials(t *testing.T, ctr testcontainers.Container) credentials.StaticCredentialsProvider {
	file := filepath.Join(t.TempDir(), "credentials")
	require.NoError(t, os.WriteFile(file, copyFromContainer(t, ctr, "emulator_credentials"), 0o600))

	sc, err := config.LoadSharedConfigProfile(t.Context(), "default", func(o *config.LoadSharedConfigOptions) {
		o.ConfigFiles = []string{}
		o.CredentialsFiles = []string{file}
	})
	require.NoError(t, err)

	return credentials.NewStaticCredentialsProvider(sc.Credentials.AccessKeyID, sc.Credentials.SecretAccessKey, "")
}

func copyFromContainer(t *testing.T, ctr testcontainers.Container, name string) []byte {
	rc, err := ctr.CopyFileFromContainer(t.Context(), path.Join(emulatorDir, name))
	require.NoError(t, err)
	defer rc.Close()

	b, err := io.ReadAll(rc)
	require.NoError(t, err)
	return b
}
