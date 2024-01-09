package redshift

import (
	"strings"

	"github.com/aquasecurity/defsec/pkg/providers/aws/redshift"
	"github.com/aquasecurity/defsec/pkg/state"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	api "github.com/aws/aws-sdk-go-v2/service/redshift"
	redshiftTypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"

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
	return "redshift"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Redshift.Clusters, err = a.getClusters()
	if err != nil {
		return err
	}

	state.AWS.Redshift.ReservedNodes, err = a.getReservedNodes()
	if err != nil {
		return err
	}

	state.AWS.Redshift.ClusterParameters, err = a.getParameters()
	if err != nil {
		return err
	}

	// this can error is classic resources are used where disabled
	state.AWS.Redshift.SecurityGroups, err = a.getSecurityGroups()
	if err != nil {
		a.Debug("Failed to adapt security groups: %s", err)
		return nil
	}

	return nil
}

func (a *adapter) getClusters() ([]redshift.Cluster, error) {

	a.Tracker().SetServiceLabel("Discovering clusters...")

	var apiClusters []redshiftTypes.Cluster
	var input api.DescribeClustersInput
	for {
		output, err := a.api.DescribeClusters(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiClusters = append(apiClusters, output.Clusters...)
		a.Tracker().SetTotalResources(len(apiClusters))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting clusters...")
	return concurrency.Adapt(apiClusters, a.RootAdapter, a.adaptCluster), nil
}

func (a *adapter) adaptCluster(apiCluster redshiftTypes.Cluster) (*redshift.Cluster, error) {

	metadata := a.CreateMetadataFromARN(awssdk.ToString(apiCluster.ClusterNamespaceArn))

	output, err := a.api.DescribeLoggingStatus(a.Context(), &api.DescribeLoggingStatusInput{
		ClusterIdentifier: apiCluster.ClusterIdentifier,
	})
	if err != nil {
		output = nil
	}

	return &redshift.Cluster{
		Metadata:                         metadata,
		ClusterIdentifier:                types.ToString(apiCluster.ClusterIdentifier, metadata),
		AllowVersionUpgrade:              types.ToBool(apiCluster.AllowVersionUpgrade, metadata),
		NumberOfNodes:                    types.ToInt(apiCluster.NumberOfNodes, metadata),
		NodeType:                         types.ToString(apiCluster.NodeType, metadata),
		PubliclyAccessible:               types.ToBool(apiCluster.PubliclyAccessible, metadata),
		VpcId:                            types.ToString(apiCluster.VpcId, metadata),
		MasterUsername:                   types.ToString(apiCluster.MasterUsername, metadata),
		AutomatedSnapshotRetentionPeriod: types.ToInt(apiCluster.ManualSnapshotRetentionPeriod, metadata),
		LoggingEnabled:                   types.ToBool(output.LoggingEnabled, metadata),
		EndPoint: redshift.EndPoint{
			Metadata: metadata,
			Port:     types.ToInt(apiCluster.Endpoint.Port, metadata),
		},
		Encryption: redshift.Encryption{
			Metadata: metadata,
			Enabled:  types.ToBool(apiCluster.Encrypted, metadata),
			KMSKeyID: types.ToString(apiCluster.KmsKeyId, metadata),
		},
		SubnetGroupName: types.ToString(apiCluster.ClusterSubnetGroupName, metadata),
	}, nil
}

func (a *adapter) getSecurityGroups() ([]redshift.SecurityGroup, error) {

	a.Tracker().SetServiceLabel("Discovering security groups...")

	var apiGroups []redshiftTypes.ClusterSecurityGroup
	var input api.DescribeClusterSecurityGroupsInput
	for {
		output, err := a.api.DescribeClusterSecurityGroups(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiGroups = append(apiGroups, output.ClusterSecurityGroups...)
		a.Tracker().SetTotalResources(len(apiGroups))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting security groups...")
	return concurrency.Adapt(apiGroups, a.RootAdapter, a.adaptSecurityGroup), nil
}

func (a *adapter) adaptSecurityGroup(apiSG redshiftTypes.ClusterSecurityGroup) (*redshift.SecurityGroup, error) {

	metadata := a.CreateMetadata("securitygroup:" + awssdk.ToString(apiSG.ClusterSecurityGroupName))

	return &redshift.SecurityGroup{
		Metadata:    metadata,
		Description: types.ToString(apiSG.Description, metadata),
	}, nil
}

func (a *adapter) getReservedNodes() ([]redshift.ReservedNode, error) {

	a.Tracker().SetServiceLabel("Discovering reserved nodes...")

	var apiReservednodes []redshiftTypes.ReservedNode
	var input api.DescribeReservedNodesInput
	for {
		output, err := a.api.DescribeReservedNodes(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiReservednodes = append(apiReservednodes, output.ReservedNodes...)
		a.Tracker().SetTotalResources(len(apiReservednodes))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting reserved node ...")
	return concurrency.Adapt(apiReservednodes, a.RootAdapter, a.adaptnode), nil
}

func (a *adapter) adaptnode(node redshiftTypes.ReservedNode) (*redshift.ReservedNode, error) {
	metadata := a.CreateMetadata(awssdk.ToString(node.ReservedNodeId))
	return &redshift.ReservedNode{
		Metadata: metadata,
		NodeType: types.ToString(node.NodeType, metadata),
	}, nil
}

func (a *adapter) getParameters() ([]redshift.ClusterParameter, error) {

	a.Tracker().SetServiceLabel("Discovering cluster parameters ...")

	var apiClusters []redshiftTypes.Parameter
	var input api.DescribeClusterParameterGroupsInput
	output, err := a.api.DescribeClusterParameterGroups(a.Context(), &input)
	if err != nil {
		return nil, err
	}
	for _, group := range output.ParameterGroups {
		groupname := *group.ParameterGroupName
		if !strings.HasPrefix(groupname, "default.redshift") {
			output, err := a.api.DescribeClusterParameters(a.Context(), &api.DescribeClusterParametersInput{
				ParameterGroupName: group.ParameterGroupName,
			})
			if err != nil {
				return nil, err
			}
			apiClusters = append(apiClusters, output.Parameters...)
			a.Tracker().SetTotalResources(len(apiClusters))
			if output.Marker == nil {
				break
			}
			input.Marker = output.Marker
		}

	}

	a.Tracker().SetServiceLabel("Adapting cluster parameters...")
	return concurrency.Adapt(apiClusters, a.RootAdapter, a.adaptParameter), nil
}

func (a *adapter) adaptParameter(parameter redshiftTypes.Parameter) (*redshift.ClusterParameter, error) {

	metadata := a.CreateMetadata(awssdk.ToString(parameter.ParameterName))

	return &redshift.ClusterParameter{
		Metadata:       metadata,
		ParameterName:  types.ToString(parameter.ParameterName, metadata),
		ParameterValue: types.ToString(parameter.ParameterValue, metadata),
	}, nil

}
