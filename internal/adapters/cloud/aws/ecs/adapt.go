package ecs

import (
	ecsapi "github.com/aws/aws-sdk-go-v2/service/ecs"

	"github.com/aquasecurity/trivy-aws/internal/adapters/cloud/aws"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

type adapter struct {
	*aws.RootAdapter
	api *ecsapi.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "ecs"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = ecsapi.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.ECS.TaskDefinitions, err = a.getTaskDefinitions()
	if err != nil {
		return err
	}

	state.AWS.ECS.Clusters, err = a.getClusters()
	if err != nil {
		return err
	}

	return nil
}
