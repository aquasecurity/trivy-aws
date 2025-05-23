package msk

import (
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	api "github.com/aws/aws-sdk-go-v2/service/kafka"
	"github.com/aws/aws-sdk-go-v2/service/kafka/types"

	"github.com/aquasecurity/trivy-aws/internal/adapters/cloud/aws"
	"github.com/aquasecurity/trivy-aws/pkg/concurrency"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/msk"
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
	return "msk"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.MSK.Clusters, err = a.getClusters()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getClusters() ([]msk.Cluster, error) {

	a.Tracker().SetServiceLabel("Discovering clusters...")

	var apiClusters []types.ClusterInfo
	var input api.ListClustersInput
	for {
		output, err := a.api.ListClusters(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiClusters = append(apiClusters, output.ClusterInfoList...)
		a.Tracker().SetTotalResources(len(apiClusters))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting clusters...")
	return concurrency.Adapt(apiClusters, a.RootAdapter, a.adaptCluster), nil
}

func (a *adapter) adaptCluster(apiCluster types.ClusterInfo) (*msk.Cluster, error) {

	metadata := a.CreateMetadataFromARN(*apiCluster.ClusterArn)

	var encInTransitClientBroker, encAtRestKMSKeyID string
	var encAtRestEnabled bool
	if apiCluster.EncryptionInfo != nil {
		if apiCluster.EncryptionInfo.EncryptionInTransit != nil {
			encInTransitClientBroker = string(apiCluster.EncryptionInfo.EncryptionInTransit.ClientBroker)
		}

		if apiCluster.EncryptionInfo.EncryptionAtRest != nil {
			encAtRestKMSKeyID = *apiCluster.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId
			encAtRestEnabled = true
		}
	}

	var logS3, logCW, logFH bool
	if apiCluster.LoggingInfo != nil && apiCluster.LoggingInfo.BrokerLogs != nil {
		logs := apiCluster.LoggingInfo.BrokerLogs
		if logs.S3 != nil {
			logS3 = awssdk.ToBool(logs.S3.Enabled)
		}
		if logs.CloudWatchLogs != nil {
			logCW = awssdk.ToBool(logs.CloudWatchLogs.Enabled)
		}
		if logs.Firehose != nil {
			logFH = awssdk.ToBool(logs.Firehose.Enabled)
		}
	}

	return &msk.Cluster{
		Metadata: metadata,
		EncryptionInTransit: msk.EncryptionInTransit{
			Metadata:     metadata,
			ClientBroker: trivyTypes.String(encInTransitClientBroker, metadata),
		},
		EncryptionAtRest: msk.EncryptionAtRest{
			Metadata:  metadata,
			KMSKeyARN: trivyTypes.String(encAtRestKMSKeyID, metadata),
			Enabled:   trivyTypes.Bool(encAtRestEnabled, metadata),
		},
		Logging: msk.Logging{
			Metadata: metadata,
			Broker: msk.BrokerLogging{
				Metadata: metadata,
				S3: msk.S3Logging{
					Metadata: metadata,
					Enabled:  trivyTypes.Bool(logS3, metadata),
				},
				Cloudwatch: msk.CloudwatchLogging{
					Metadata: metadata,
					Enabled:  trivyTypes.Bool(logCW, metadata),
				},
				Firehose: msk.FirehoseLogging{
					Metadata: metadata,
					Enabled:  trivyTypes.Bool(logFH, metadata),
				},
			},
		},
	}, nil
}
