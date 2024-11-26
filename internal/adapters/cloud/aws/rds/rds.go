package rds

import (
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	rdsApi "github.com/aws/aws-sdk-go-v2/service/rds"
	rdsTypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/aquasecurity/trivy-aws/internal/adapters/cloud/aws"
	"github.com/aquasecurity/trivy-aws/pkg/concurrency"
	"github.com/aquasecurity/trivy-aws/pkg/types"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/rds"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

type adapter struct {
	*aws.RootAdapter
	api *rdsApi.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Name() string {
	return "rds"
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = rdsApi.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.RDS.Instances, err = a.getInstances()
	if err != nil {
		return err
	}

	state.AWS.RDS.Clusters, err = a.getClusters()
	if err != nil {
		return err
	}

	state.AWS.RDS.Classic, err = a.getClassic()
	if err != nil {
		a.Logger().Error("Failed to retrieve classic resource", log.Err(err))
		return nil
	}

	state.AWS.RDS.Snapshots, err = a.getSnapshots()
	if err != nil {
		return err
	}

	state.AWS.RDS.ParameterGroups, err = a.getParameterGroups()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getSnapshots() (snapshots []rds.Snapshots, err error) {
	a.Tracker().SetServiceLabel("Discovering Snapshots...")
	var apiDBSnapshots []rdsTypes.DBSnapshot
	var input rdsApi.DescribeDBSnapshotsInput

	for {
		output, err := a.api.DescribeDBSnapshots(a.Context(), &input)
		if err != nil {
			return nil, err
		}

		apiDBSnapshots = append(apiDBSnapshots, output.DBSnapshots...)
		a.Tracker().SetTotalResources(len(apiDBSnapshots))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}
	a.Tracker().SetServiceLabel("Adapting RDS DB snapshots...")
	return concurrency.Adapt(apiDBSnapshots, a.RootAdapter, a.adaptDBSnapshots), nil
}

func (a *adapter) getInstances() (instances []rds.Instance, err error) {

	a.Tracker().SetServiceLabel("Discovering RDS instances...")
	var apiDBInstances []rdsTypes.DBInstance
	var input rdsApi.DescribeDBInstancesInput

	for {
		output, err := a.api.DescribeDBInstances(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiDBInstances = append(apiDBInstances, output.DBInstances...)
		a.Tracker().SetTotalResources(len(apiDBInstances))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting RDS instances...")
	return concurrency.Adapt(apiDBInstances, a.RootAdapter, a.adaptDBInstance), nil
}

func (a *adapter) getParameterGroups() (parameter []rds.ParameterGroups, err error) {
	a.Tracker().SetServiceLabel(" Parameter...")
	var apiParameter []rdsTypes.DBParameterGroup
	var input rdsApi.DescribeDBParameterGroupsInput

	for {
		output, err := a.api.DescribeDBParameterGroups(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiParameter = append(apiParameter, output.DBParameterGroups...)
		a.Tracker().SetTotalResources(len(apiParameter))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting RDS Parameters Groups")
	return concurrency.Adapt(apiParameter, a.RootAdapter, a.adaptParameterGroup), nil
}

func (a *adapter) getClusters() (clusters []rds.Cluster, err error) {

	a.Tracker().SetServiceLabel("Discovering RDS clusters...")
	var apDBClusters []rdsTypes.DBCluster
	var input rdsApi.DescribeDBClustersInput

	for {
		output, err := a.api.DescribeDBClusters(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apDBClusters = append(apDBClusters, output.DBClusters...)
		a.Tracker().SetTotalResources(len(apDBClusters))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}
	a.Tracker().SetServiceLabel("Adapting RDS clusters...")
	return concurrency.Adapt(apDBClusters, a.RootAdapter, a.adaptCluster), nil
}

func (a *adapter) getClassic() (rds.Classic, error) {

	classic := rds.Classic{
		DBSecurityGroups: nil,
	}

	a.Tracker().SetServiceLabel("Discovering RDS classic instances...")
	var apiDBSGs []rdsTypes.DBSecurityGroup
	var input rdsApi.DescribeDBSecurityGroupsInput

	for {
		output, err := a.api.DescribeDBSecurityGroups(a.Context(), &input)
		if err != nil {
			return classic, err
		}
		apiDBSGs = append(apiDBSGs, output.DBSecurityGroups...)
		a.Tracker().SetTotalResources(len(apiDBSGs))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}
	a.Tracker().SetServiceLabel("Adapting RDS clusters...")
	sgs := concurrency.Adapt(apiDBSGs, a.RootAdapter, a.adaptClassic)

	classic.DBSecurityGroups = sgs
	return classic, nil
}

func (a *adapter) adaptDBInstance(dbInstance rdsTypes.DBInstance) (*rds.Instance, error) {

	metadata := a.CreateMetadata("db:" + awssdk.ToString(dbInstance.DBInstanceIdentifier))

	var TagList []rds.TagList
	if dbInstance.TagList != nil {
		for range dbInstance.TagList {
			TagList = append(TagList, rds.TagList{
				Metadata: metadata,
			})
		}
	}

	var EnabledCloudwatchLogsExports []trivyTypes.StringValue
	for _, ecwe := range dbInstance.EnabledCloudwatchLogsExports {
		EnabledCloudwatchLogsExports = append(EnabledCloudwatchLogsExports, trivyTypes.String(ecwe, metadata))
	}

	var ReadReplicaDBInstanceIdentifiers []trivyTypes.StringValue
	for _, rrdbi := range dbInstance.EnabledCloudwatchLogsExports {
		ReadReplicaDBInstanceIdentifiers = append(ReadReplicaDBInstanceIdentifiers, trivyTypes.String(rrdbi, metadata))
	}

	engine := rds.EngineAurora
	if dbInstance.Engine != nil {
		engine = *dbInstance.Engine
	}

	instance := &rds.Instance{
		Metadata:                  metadata,
		BackupRetentionPeriodDays: types.ToInt(dbInstance.BackupRetentionPeriod, metadata),
		ReplicationSourceARN:      types.ToString(dbInstance.ReadReplicaSourceDBInstanceIdentifier, metadata),
		PerformanceInsights: getPerformanceInsights(
			dbInstance.PerformanceInsightsEnabled,
			dbInstance.PerformanceInsightsKMSKeyId,
			metadata,
		),
		Encryption:                       getInstanceEncryption(awssdk.ToBool(dbInstance.StorageEncrypted), dbInstance.KmsKeyId, metadata),
		PublicAccess:                     types.ToBool(dbInstance.PubliclyAccessible, metadata),
		Engine:                           trivyTypes.String(engine, metadata),
		IAMAuthEnabled:                   types.ToBool(dbInstance.IAMDatabaseAuthenticationEnabled, metadata),
		DeletionProtection:               types.ToBool(dbInstance.DeletionProtection, metadata),
		DBInstanceArn:                    types.ToString(dbInstance.DBInstanceArn, metadata),
		StorageEncrypted:                 types.ToBool(dbInstance.StorageEncrypted, metadata),
		DBInstanceIdentifier:             types.ToString(dbInstance.DBInstanceIdentifier, metadata),
		TagList:                          TagList,
		EnabledCloudwatchLogsExports:     EnabledCloudwatchLogsExports,
		EngineVersion:                    trivyTypes.String(engine, metadata),
		AutoMinorVersionUpgrade:          types.ToBool(dbInstance.AutoMinorVersionUpgrade, metadata),
		MultiAZ:                          types.ToBool(dbInstance.MultiAZ, metadata),
		PubliclyAccessible:               types.ToBool(dbInstance.PubliclyAccessible, metadata),
		LatestRestorableTime:             trivyTypes.TimeUnresolvable(metadata),
		ReadReplicaDBInstanceIdentifiers: ReadReplicaDBInstanceIdentifiers,
	}

	return instance, nil
}

func (a *adapter) adaptCluster(dbCluster rdsTypes.DBCluster) (*rds.Cluster, error) {

	dbClusterMetadata := a.CreateMetadata("cluster:" + awssdk.ToString(dbCluster.DBClusterIdentifier))

	engine := rds.EngineAurora
	if dbCluster.Engine != nil {
		engine = *dbCluster.Engine
	}

	var availabilityZones []trivyTypes.StringValue
	for _, az := range dbCluster.AvailabilityZones {
		availabilityZones = append(availabilityZones, trivyTypes.String(az, dbClusterMetadata))
	}

	cluster := &rds.Cluster{
		Metadata:                  dbClusterMetadata,
		BackupRetentionPeriodDays: types.ToInt(dbCluster.BackupRetentionPeriod, dbClusterMetadata),
		ReplicationSourceARN:      types.ToString(dbCluster.ReplicationSourceIdentifier, dbClusterMetadata),
		PerformanceInsights: getPerformanceInsights(
			dbCluster.PerformanceInsightsEnabled,
			dbCluster.PerformanceInsightsKMSKeyId,
			dbClusterMetadata,
		),
		Encryption:           getInstanceEncryption(awssdk.ToBool(dbCluster.StorageEncrypted), dbCluster.KmsKeyId, dbClusterMetadata),
		PublicAccess:         types.ToBool(dbCluster.PubliclyAccessible, dbClusterMetadata),
		Engine:               trivyTypes.String(engine, dbClusterMetadata),
		LatestRestorableTime: trivyTypes.TimeUnresolvable(dbClusterMetadata),
		AvailabilityZones:    availabilityZones,
		DeletionProtection:   types.ToBool(dbCluster.DeletionProtection, dbClusterMetadata),
	}

	return cluster, nil
}

func (a *adapter) adaptParameterGroup(dbParameterGroup rdsTypes.DBParameterGroup) (*rds.ParameterGroups, error) {

	metadata := a.CreateMetadata("dbparametergroup:" + awssdk.ToString(dbParameterGroup.DBParameterGroupArn))
	var parameter []rds.Parameters
	output, err := a.api.DescribeDBParameters(a.Context(), &rdsApi.DescribeDBParametersInput{
		DBParameterGroupName: dbParameterGroup.DBParameterGroupName,
	})
	if err != nil {
		return nil, err
	}

	for _, r := range output.Parameters {

		parameter = append(parameter, rds.Parameters{
			Metadata:       metadata,
			ParameterName:  types.ToString(r.ParameterName, metadata),
			ParameterValue: types.ToString(r.ParameterValue, metadata),
		})
	}

	return &rds.ParameterGroups{
		Metadata:               metadata,
		Parameters:             parameter,
		DBParameterGroupName:   trivyTypes.String(awssdk.ToString(dbParameterGroup.DBParameterGroupName), metadata),
		DBParameterGroupFamily: trivyTypes.String(awssdk.ToString(dbParameterGroup.DBParameterGroupFamily), metadata),
	}, nil

}

func (a *adapter) adaptDBSnapshots(dbSnapshots rdsTypes.DBSnapshot) (*rds.Snapshots, error) {
	metadata := a.CreateMetadata("dbsnapshots" + awssdk.ToString(dbSnapshots.DBSnapshotArn))

	var SnapshotAttributes []rds.DBSnapshotAttributes
	output, err := a.api.DescribeDBSnapshotAttributes(a.Context(), &rdsApi.DescribeDBSnapshotAttributesInput{
		DBSnapshotIdentifier: dbSnapshots.DBSnapshotIdentifier,
	})
	if err != nil {
		return nil, err
	}
	if output.DBSnapshotAttributesResult != nil {
		for _, r := range output.DBSnapshotAttributesResult.DBSnapshotAttributes {

			var AV []trivyTypes.StringValue
			if r.AttributeValues != nil {
				for _, Values := range r.AttributeValues {
					AV = append(AV, trivyTypes.String(Values, metadata))
				}
			}
			SnapshotAttributes = append(SnapshotAttributes, rds.DBSnapshotAttributes{
				Metadata:        metadata,
				AttributeValues: AV,
			})
		}

	}

	snapshots := &rds.Snapshots{
		Metadata:             metadata,
		DBSnapshotIdentifier: types.ToString(dbSnapshots.DBSnapshotIdentifier, metadata),
		DBSnapshotArn:        types.ToString(dbSnapshots.DBSnapshotArn, metadata),
		Encrypted:            types.ToBool(dbSnapshots.Encrypted, metadata),
		KmsKeyId:             trivyTypes.String("", metadata),
		SnapshotAttributes:   SnapshotAttributes,
	}

	// KMSKeyID is only set if Encryption is enabled
	if snapshots.Encrypted.IsTrue() {
		snapshots.KmsKeyId = trivyTypes.StringDefault(awssdk.ToString(dbSnapshots.KmsKeyId), metadata)
	}

	return snapshots, nil
}

func (a *adapter) adaptClassic(dbSecurityGroup rdsTypes.DBSecurityGroup) (*rds.DBSecurityGroup, error) {

	dbSecurityGroupMetadata := a.CreateMetadata("secgrp:" + awssdk.ToString(dbSecurityGroup.DBSecurityGroupName))

	dbsg := &rds.DBSecurityGroup{
		Metadata: dbSecurityGroupMetadata,
	}

	return dbsg, nil
}

func getInstanceEncryption(storageEncrypted bool, kmsKeyID *string, metadata trivyTypes.Metadata) rds.Encryption {
	encryption := rds.Encryption{
		Metadata:       metadata,
		EncryptStorage: trivyTypes.BoolDefault(storageEncrypted, metadata),
		KMSKeyID:       types.ToString(kmsKeyID, metadata),
	}

	return encryption
}

func getPerformanceInsights(enabled *bool, kmsKeyID *string, metadata trivyTypes.Metadata) rds.PerformanceInsights {
	performanceInsights := rds.PerformanceInsights{
		Metadata: metadata,
		Enabled:  types.ToBool(enabled, metadata),
		KMSKeyID: types.ToString(kmsKeyID, metadata),
	}

	return performanceInsights
}
