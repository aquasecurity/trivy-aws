package ssm

import (
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	api "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretsmanagerTypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/aquasecurity/trivy-aws/internal/adapters/cloud/aws"
	"github.com/aquasecurity/trivy-aws/pkg/concurrency"
	"github.com/aquasecurity/trivy-aws/pkg/types"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ssm"
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
	return "ssm"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.SSM.Secrets, err = a.getSecrets()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getSecrets() ([]ssm.Secret, error) {

	a.Tracker().SetServiceLabel("Discovering secrets...")

	var apiSecrets []secretsmanagerTypes.SecretListEntry
	var input api.ListSecretsInput
	for {
		output, err := a.api.ListSecrets(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiSecrets = append(apiSecrets, output.SecretList...)
		a.Tracker().SetTotalResources(len(apiSecrets))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting secrets...")
	return concurrency.Adapt(apiSecrets, a.RootAdapter, a.adaptSecret), nil
}

func (a *adapter) adaptSecret(apiSecret secretsmanagerTypes.SecretListEntry) (*ssm.Secret, error) {

	metadata := a.CreateMetadataFromARN(awssdk.ToString(apiSecret.ARN))

	return &ssm.Secret{
		Metadata: metadata,
		KMSKeyID: types.ToString(apiSecret.KmsKeyId, metadata),
	}, nil
}
