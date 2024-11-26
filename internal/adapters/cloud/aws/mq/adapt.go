package mq

import (
	api "github.com/aws/aws-sdk-go-v2/service/mq"
	mqTypes "github.com/aws/aws-sdk-go-v2/service/mq/types"

	"github.com/aquasecurity/trivy-aws/internal/adapters/cloud/aws"
	"github.com/aquasecurity/trivy-aws/pkg/concurrency"
	"github.com/aquasecurity/trivy-aws/pkg/types"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/mq"
	"github.com/aquasecurity/trivy/pkg/iac/state"
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
	return "mq"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.MQ.Brokers, err = a.getBrokers()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getBrokers() ([]mq.Broker, error) {

	a.Tracker().SetServiceLabel("Discovering brokers...")

	var apiBrokers []mqTypes.BrokerSummary
	var input api.ListBrokersInput
	for {
		output, err := a.api.ListBrokers(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiBrokers = append(apiBrokers, output.BrokerSummaries...)
		a.Tracker().SetTotalResources(len(apiBrokers))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting brokers...")
	return concurrency.Adapt(apiBrokers, a.RootAdapter, a.adaptBroker), nil
}

func (a *adapter) adaptBroker(apiBroker mqTypes.BrokerSummary) (*mq.Broker, error) {

	metadata := a.CreateMetadataFromARN(*apiBroker.BrokerArn)

	output, err := a.api.DescribeBroker(a.Context(), &api.DescribeBrokerInput{
		BrokerId: apiBroker.BrokerId,
	})
	if err != nil {
		return nil, err
	}

	return &mq.Broker{
		Metadata:     metadata,
		PublicAccess: types.ToBool(output.PubliclyAccessible, metadata),
		Logging: mq.Logging{
			Metadata: metadata,
			General:  types.ToBool(output.Logs.General, metadata),
			Audit:    types.ToBool(output.Logs.Audit, metadata),
		},
	}, nil
}
