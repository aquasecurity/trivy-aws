package efs

import (
	api "github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/efs/types"

	"github.com/aquasecurity/trivy-aws/internal/adapters/cloud/aws"
	"github.com/aquasecurity/trivy-aws/pkg/concurrency"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/efs"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type adapter struct {
	*aws.RootAdapter
	api *api.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "efs"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.EFS.FileSystems, err = a.getFilesystems()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getFilesystems() ([]efs.FileSystem, error) {

	a.Tracker().SetServiceLabel("Discovering filesystems...")

	var input api.DescribeFileSystemsInput
	var apiFilesystems []types.FileSystemDescription
	for {
		output, err := a.api.DescribeFileSystems(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiFilesystems = append(apiFilesystems, output.FileSystems...)
		a.Tracker().SetTotalResources(len(apiFilesystems))
		if output.NextMarker == nil {
			break
		}
		input.Marker = output.NextMarker
	}

	a.Tracker().SetServiceLabel("Adapting filesystems...")
	return concurrency.Adapt(apiFilesystems, a.RootAdapter, a.adaptFilesystem), nil
}

func (a *adapter) adaptFilesystem(apiFilesystem types.FileSystemDescription) (*efs.FileSystem, error) {
	metadata := a.CreateMetadataFromARN(*apiFilesystem.FileSystemArn)
	encrypted := trivyTypes.BoolDefault(false, metadata)
	if apiFilesystem.Encrypted != nil {
		encrypted = trivyTypes.Bool(*apiFilesystem.Encrypted, metadata)
	}
	return &efs.FileSystem{
		Metadata:  metadata,
		Encrypted: encrypted,
	}, nil
}
