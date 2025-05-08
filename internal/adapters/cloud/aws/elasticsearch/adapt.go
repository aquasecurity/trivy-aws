package elasticsearch

import (
	api "github.com/aws/aws-sdk-go-v2/service/elasticsearchservice"
	"github.com/aws/aws-sdk-go-v2/service/elasticsearchservice/types"

	"github.com/aquasecurity/trivy-aws/internal/adapters/cloud/aws"
	"github.com/aquasecurity/trivy-aws/pkg/concurrency"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/elasticsearch"
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
	return "elasticsearch"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Elasticsearch.Domains, err = a.getDomains()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getDomains() ([]elasticsearch.Domain, error) {

	a.Tracker().SetServiceLabel("Discovering domains...")

	var input api.ListDomainNamesInput
	output, err := a.api.ListDomainNames(a.Context(), &input)
	if err != nil {
		return nil, err
	}
	apiDomains := output.DomainNames
	a.Tracker().SetTotalResources(len(apiDomains))

	a.Tracker().SetServiceLabel("Adapting domains...")
	return concurrency.Adapt(apiDomains, a.RootAdapter, a.adaptDomain), nil
}

func (a *adapter) adaptDomain(apiDomain types.DomainInfo) (*elasticsearch.Domain, error) {
	metadata := a.CreateMetadata(*apiDomain.DomainName)

	output, err := a.api.DescribeElasticsearchDomain(a.Context(), &api.DescribeElasticsearchDomainInput{
		DomainName: apiDomain.DomainName,
	})
	if err != nil {
		return nil, err
	}
	status := output.DomainStatus

	var auditEnabled bool
	var transitEncryption bool
	var atRestEncryption bool
	var enforceHTTPS, dedicatedMasterEnabled bool
	var tlsPolicy, cloudWatchLogGroupArn, kmskeyID, vpcID string

	if status.ElasticsearchClusterConfig != nil {
		dedicatedMasterEnabled = *status.ElasticsearchClusterConfig.DedicatedMasterEnabled
	}

	if status.VPCOptions != nil && status.VPCOptions.VPCId != nil {
		vpcID = *status.VPCOptions.VPCId
	}

	if status.LogPublishingOptions != nil {
		if audit, ok := status.LogPublishingOptions["AUDIT_LOGS"]; ok && audit.Enabled != nil {
			auditEnabled = *audit.Enabled
			if audit.CloudWatchLogsLogGroupArn != nil {
				cloudWatchLogGroupArn = *audit.CloudWatchLogsLogGroupArn
			}
		}
	}

	if status.NodeToNodeEncryptionOptions != nil && status.NodeToNodeEncryptionOptions.Enabled != nil {
		transitEncryption = *status.NodeToNodeEncryptionOptions.Enabled
	}

	if status.EncryptionAtRestOptions != nil && status.EncryptionAtRestOptions.Enabled != nil {
		atRestEncryption = *status.EncryptionAtRestOptions.Enabled
		if status.EncryptionAtRestOptions.KmsKeyId != nil {
			kmskeyID = *status.EncryptionAtRestOptions.KmsKeyId
		}
	}

	if status.DomainEndpointOptions != nil {
		tlsPolicy = string(status.DomainEndpointOptions.TLSSecurityPolicy)
		if status.DomainEndpointOptions.EnforceHTTPS != nil {
			enforceHTTPS = *status.DomainEndpointOptions.EnforceHTTPS
		}
	}

	var currentVersion, newVersion, updatestatus string
	var updateAvailable bool

	if status.ServiceSoftwareOptions != nil {
		currentVersion = *status.ServiceSoftwareOptions.CurrentVersion
		newVersion = *status.ServiceSoftwareOptions.NewVersion
		updateAvailable = *status.ServiceSoftwareOptions.UpdateAvailable
		updatestatus = string(status.ServiceSoftwareOptions.UpdateStatus)
	}

	return &elasticsearch.Domain{
		Metadata:               metadata,
		DomainName:             trivyTypes.String(*apiDomain.DomainName, metadata),
		AccessPolicies:         trivyTypes.String(*status.AccessPolicies, metadata),
		DedicatedMasterEnabled: trivyTypes.Bool(dedicatedMasterEnabled, metadata),
		VpcId:                  trivyTypes.String(vpcID, metadata),
		LogPublishing: elasticsearch.LogPublishing{
			Metadata:              metadata,
			AuditEnabled:          trivyTypes.Bool(auditEnabled, metadata),
			CloudWatchLogGroupArn: trivyTypes.String(cloudWatchLogGroupArn, metadata),
		},
		TransitEncryption: elasticsearch.TransitEncryption{
			Metadata: metadata,
			Enabled:  trivyTypes.Bool(transitEncryption, metadata),
		},
		AtRestEncryption: elasticsearch.AtRestEncryption{
			Metadata: metadata,
			Enabled:  trivyTypes.Bool(atRestEncryption, metadata),
			KmsKeyId: trivyTypes.String(kmskeyID, metadata),
		},
		Endpoint: elasticsearch.Endpoint{
			Metadata:     metadata,
			EnforceHTTPS: trivyTypes.Bool(enforceHTTPS, metadata),
			TLSPolicy:    trivyTypes.String(tlsPolicy, metadata),
		},
		ServiceSoftwareOptions: elasticsearch.ServiceSoftwareOptions{
			Metadata:        metadata,
			CurrentVersion:  trivyTypes.String(currentVersion, metadata),
			NewVersion:      trivyTypes.String(newVersion, metadata),
			UpdateAvailable: trivyTypes.Bool(updateAvailable, metadata),
			UpdateStatus:    trivyTypes.String(updatestatus, metadata),
		},
	}, nil
}
