package cloudwatch

import (
	cwApi "github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwTypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	api "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"

	"github.com/aquasecurity/trivy-aws/internal/adapters/cloud/aws"
	"github.com/aquasecurity/trivy-aws/pkg/concurrency"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudwatch"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type adapter struct {
	*aws.RootAdapter
	logsClient   *api.Client
	alarmsClient *cwApi.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "cloudwatch"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.logsClient = api.NewFromConfig(root.SessionConfig())
	a.alarmsClient = cwApi.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.CloudWatch.LogGroups, err = a.getLogGroups()
	if err != nil {
		return err
	}
	state.AWS.CloudWatch.Alarms, err = a.getAlarms()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getAlarms() ([]cloudwatch.Alarm, error) {

	a.Tracker().SetServiceLabel("Discovering alarms...")
	var apiAlarms []cwTypes.MetricAlarm

	var input cwApi.DescribeAlarmsInput
	for {
		output, err := a.alarmsClient.DescribeAlarms(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiAlarms = append(apiAlarms, output.MetricAlarms...)
		a.Tracker().SetTotalResources(len(apiAlarms))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting log groups...")
	return concurrency.Adapt(apiAlarms, a.RootAdapter, a.adaptAlarm), nil
}

func (a *adapter) getLogGroups() ([]cloudwatch.LogGroup, error) {

	a.Tracker().SetServiceLabel("Discovering log groups...")

	var apiLogGroups []types.LogGroup
	var input api.DescribeLogGroupsInput
	for {
		output, err := a.logsClient.DescribeLogGroups(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiLogGroups = append(apiLogGroups, output.LogGroups...)
		a.Tracker().SetTotalResources(len(apiLogGroups))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting log groups...")
	return concurrency.Adapt(apiLogGroups, a.RootAdapter, a.adaptLogGroup), nil
}

func (a *adapter) adaptLogGroup(group types.LogGroup) (*cloudwatch.LogGroup, error) {

	metadata := a.CreateMetadataFromARN(*group.Arn)

	var kmsKeyId string
	var retentionInDays int

	if group.KmsKeyId != nil {
		kmsKeyId = *group.KmsKeyId
	}

	if group.RetentionInDays != nil {
		retentionInDays = int(*group.RetentionInDays)
	}

	var metricFilters []cloudwatch.MetricFilter
	var err error
	if *group.MetricFilterCount > 0 {
		metricFilters, err = a.getMetricFilters(group.LogGroupName, metadata)
		if err != nil {
			return nil, err
		}

	}

	arn := trivyTypes.StringDefault("", metadata)
	if group.Arn != nil {
		arn = trivyTypes.String(*group.Arn, metadata)
	}

	name := trivyTypes.StringDefault("", metadata)
	if group.LogGroupName != nil {
		name = trivyTypes.String(*group.LogGroupName, metadata)
	}

	return &cloudwatch.LogGroup{
		Metadata:        metadata,
		Arn:             arn,
		Name:            name,
		KMSKeyID:        trivyTypes.String(kmsKeyId, metadata),
		RetentionInDays: trivyTypes.Int(retentionInDays, metadata),
		MetricFilters:   metricFilters,
	}, nil
}

func (a *adapter) adaptAlarm(alarm cwTypes.MetricAlarm) (*cloudwatch.Alarm, error) {

	metadata := a.CreateMetadataFromARN(*alarm.AlarmArn)

	var dimensions []cloudwatch.AlarmDimension
	for _, dimension := range alarm.Dimensions {

		name := trivyTypes.StringDefault("", metadata)
		if dimension.Name != nil {
			name = trivyTypes.String(*dimension.Name, metadata)
		}

		value := trivyTypes.StringDefault("", metadata)
		if dimension.Value != nil {
			value = trivyTypes.String(*dimension.Value, metadata)
		}

		dimensions = append(dimensions, cloudwatch.AlarmDimension{
			Metadata: metadata,
			Name:     name,
			Value:    value,
		})
	}

	var metrics []cloudwatch.MetricDataQuery
	for _, metric := range alarm.Metrics {

		id := trivyTypes.StringDefault("", metadata)
		if metric.Id != nil {
			id = trivyTypes.String(*metric.Id, metadata)
		}

		expression := trivyTypes.StringDefault("", metadata)
		if metric.Expression != nil {
			expression = trivyTypes.String(*metric.Expression, metadata)
		}

		metrics = append(metrics, cloudwatch.MetricDataQuery{
			Metadata:   metadata,
			ID:         id,
			Expression: expression,
		})
	}

	name := trivyTypes.StringDefault("", metadata)
	if alarm.AlarmName != nil {
		name = trivyTypes.String(*alarm.AlarmName, metadata)
	}

	metric := trivyTypes.StringDefault("", metadata)
	if alarm.MetricName != nil {
		metric = trivyTypes.String(*alarm.MetricName, metadata)
	}

	return &cloudwatch.Alarm{
		Metadata:   metadata,
		AlarmName:  name,
		MetricName: metric,
		Dimensions: dimensions,
		Metrics:    metrics,
	}, nil
}

func (a *adapter) getMetricFilters(name *string, metadata trivyTypes.Metadata) ([]cloudwatch.MetricFilter, error) {

	var apiMetricFilters []types.MetricFilter
	input := api.DescribeMetricFiltersInput{
		LogGroupName: name,
	}
	for {
		output, err := a.logsClient.DescribeMetricFilters(a.Context(), &input)
		if err != nil {
			return nil, err
		}

		apiMetricFilters = append(apiMetricFilters, output.MetricFilters...)
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	var metricFilters []cloudwatch.MetricFilter
	for _, mf := range apiMetricFilters {

		name := trivyTypes.StringDefault("", metadata)
		if mf.FilterName != nil {
			name = trivyTypes.String(*mf.FilterName, metadata)
		}

		pattern := trivyTypes.StringDefault("", metadata)
		if mf.FilterPattern != nil {
			pattern = trivyTypes.String(*mf.FilterPattern, metadata)
		}
		metricFilters = append(metricFilters, cloudwatch.MetricFilter{
			Metadata:      metadata,
			FilterName:    name,
			FilterPattern: pattern,
		})

	}

	return metricFilters, nil
}
