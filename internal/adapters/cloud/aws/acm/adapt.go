package acm

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/acm"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	api "github.com/aws/aws-sdk-go-v2/service/acm"
	acmTypes "github.com/aws/aws-sdk-go-v2/service/acm/types"

	"github.com/aquasecurity/trivy-aws/internal/adapters/cloud/aws"
	"github.com/aquasecurity/trivy-aws/pkg/concurrency"
	"github.com/aquasecurity/trivy-aws/pkg/types"
	iactypes "github.com/aquasecurity/trivy/pkg/iac/types"
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
	return "acm"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {
	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.ACM.Certificates, err = a.getCertificates()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getCertificates() ([]acm.Certificate, error) {
	a.Tracker().SetServiceLabel("Discovering certificates...")

	var apiCertificates []acmTypes.CertificateSummary
	var input api.ListCertificatesInput
	for {
		output, err := a.api.ListCertificates(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiCertificates = append(apiCertificates, output.CertificateSummaryList...)
		a.Tracker().SetTotalResources(len(apiCertificates))
		if awssdk.ToString(output.NextToken) == "" {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting certificates...")
	return concurrency.Adapt(apiCertificates, a.RootAdapter, a.adaptCertificate), nil
}

func (a *adapter) adaptCertificate(apiCertificate acmTypes.CertificateSummary) (*acm.Certificate, error) {
	metadata := a.CreateMetadataFromARN(awssdk.ToString(apiCertificate.CertificateArn))

	return &acm.Certificate{
		Metadata:       metadata,
		CertificateArn: types.ToString(apiCertificate.CertificateArn, metadata),
		NotAfter:       iactypes.Time(*apiCertificate.NotAfter, metadata),
	}, nil
}
