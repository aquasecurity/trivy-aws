package workspaces

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/workspaces"
	"github.com/aquasecurity/defsec/pkg/state"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	api "github.com/aws/aws-sdk-go-v2/service/workspaces"
	workspaceTypes "github.com/aws/aws-sdk-go-v2/service/workspaces/types"

	"github.com/aquasecurity/trivy-aws/internal/adapters/cloud/aws"
	"github.com/aquasecurity/trivy-aws/pkg/concurrency"
	"github.com/aquasecurity/trivy-aws/pkg/types"
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
	return "workspaces"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.WorkSpaces.WorkSpaces, err = a.getWorkspaces()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getWorkspaces() ([]workspaces.WorkSpace, error) {

	a.Tracker().SetServiceLabel("Discovering workspaces...")

	var apiWorkspaces []workspaceTypes.Workspace
	var input api.DescribeWorkspacesInput
	for {
		output, err := a.api.DescribeWorkspaces(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiWorkspaces = append(apiWorkspaces, output.Workspaces...)
		a.Tracker().SetTotalResources(len(apiWorkspaces))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting workspaces...")
	return concurrency.Adapt(apiWorkspaces, a.RootAdapter, a.adaptWorkspace), nil
}

func (a *adapter) adaptWorkspace(apiWorkspace workspaceTypes.Workspace) (*workspaces.WorkSpace, error) {

	metadata := a.CreateMetadata("workspace/" + awssdk.ToString(apiWorkspace.WorkspaceId))
	return &workspaces.WorkSpace{
		Metadata: metadata,
		RootVolume: workspaces.Volume{
			Metadata: metadata,
			Encryption: workspaces.Encryption{
				Metadata: metadata,
				Enabled:  types.ToBool(apiWorkspace.RootVolumeEncryptionEnabled, metadata),
			},
		},
		UserVolume: workspaces.Volume{
			Metadata: metadata,
			Encryption: workspaces.Encryption{
				Metadata: metadata,
				Enabled:  types.ToBool(apiWorkspace.UserVolumeEncryptionEnabled, metadata),
			},
		},
	}, nil
}
