package ecs

import (
	"github.com/aquasecurity/defsec/pkg/state"
	ecsapi "github.com/aws/aws-sdk-go-v2/service/ecs"

	"github.com/nikpivkin/trivy-aws/internal/adapters"
)

type adapter struct {
	*adapters.RootAdapter
	api *ecsapi.Client
}

func init() {
	adapters.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "ecs"
}

func (a *adapter) Adapt(root *adapters.RootAdapter, state *state.State) error {

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
