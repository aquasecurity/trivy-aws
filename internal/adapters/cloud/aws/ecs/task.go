package ecs

import (
	"strconv"

	ecsapi "github.com/aws/aws-sdk-go-v2/service/ecs"

	"github.com/aquasecurity/trivy-aws/pkg/concurrency"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ecs"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func (a *adapter) getTaskDefinitions() ([]ecs.TaskDefinition, error) {
	var definitionARNs []string

	a.Tracker().SetServiceLabel("Discovering task definitions...")
	input := &ecsapi.ListTaskDefinitionsInput{}
	for {
		output, err := a.api.ListTaskDefinitions(a.Context(), input)
		if err != nil {
			return nil, err
		}
		definitionARNs = append(definitionARNs, output.TaskDefinitionArns...)
		a.Tracker().SetTotalResources(len(definitionARNs))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting task definitions...")
	return concurrency.Adapt(definitionARNs, a.RootAdapter, a.adaptTaskDefinition), nil
}

func (a *adapter) adaptTaskDefinition(arn string) (*ecs.TaskDefinition, error) {

	output, err := a.api.DescribeTaskDefinition(a.Context(), &ecsapi.DescribeTaskDefinitionInput{
		TaskDefinition: &arn,
	})
	if err != nil {
		return nil, err
	}

	metadata := a.CreateMetadataFromARN(arn)

	var containerDefinitions []ecs.ContainerDefinition
	for _, apiContainer := range output.TaskDefinition.ContainerDefinitions {
		var portMappings []ecs.PortMapping
		for _, apiMapping := range apiContainer.PortMappings {
			var containerPort int
			var hostPort int
			if apiMapping.ContainerPort != nil {
				containerPort = int(*apiMapping.ContainerPort)
			}
			if apiMapping.HostPort != nil {
				hostPort = int(*apiMapping.HostPort)
			}
			portMappings = append(portMappings, ecs.PortMapping{
				ContainerPort: trivyTypes.Int(containerPort, metadata),
				HostPort:      trivyTypes.Int(hostPort, metadata),
			})
		}

		var name string
		var image string
		var cpu string
		var memory string
		var essential bool
		var envVars []ecs.EnvVar

		if apiContainer.Name != nil {
			name = *apiContainer.Name
		}
		if apiContainer.Image != nil {
			image = *apiContainer.Image
		}
		cpu = strconv.Itoa(int(apiContainer.Cpu))
		if apiContainer.Memory != nil {
			memory = strconv.Itoa(int(*apiContainer.Memory))
		}
		if apiContainer.Essential != nil {
			essential = *apiContainer.Essential
		}

		for _, env := range apiContainer.Environment {
			envVars = append(envVars, ecs.EnvVar{
				Name:  trivyTypes.String(*env.Name, metadata),
				Value: trivyTypes.String(*env.Value, metadata),
			})
		}

		containerDefinitions = append(containerDefinitions, ecs.ContainerDefinition{
			Metadata:     metadata,
			Name:         trivyTypes.String(name, metadata),
			Image:        trivyTypes.String(image, metadata),
			CPU:          trivyTypes.String(cpu, metadata),
			Memory:       trivyTypes.String(memory, metadata),
			Essential:    trivyTypes.Bool(essential, metadata),
			PortMappings: portMappings,
			Environment:  envVars,
			Privileged:   trivyTypes.Bool(apiContainer.Privileged != nil && *apiContainer.Privileged, metadata),
		})
	}

	var volumes []ecs.Volume
	for _, apiVolume := range output.TaskDefinition.Volumes {
		encrypted := apiVolume.EfsVolumeConfiguration != nil && string(apiVolume.EfsVolumeConfiguration.TransitEncryption) == "ENABLED"
		volumes = append(volumes, ecs.Volume{
			Metadata: metadata,
			EFSVolumeConfiguration: ecs.EFSVolumeConfiguration{
				Metadata:                 metadata,
				TransitEncryptionEnabled: trivyTypes.Bool(encrypted, metadata),
			},
		})
	}

	return &ecs.TaskDefinition{
		Metadata:             metadata,
		Volumes:              volumes,
		ContainerDefinitions: containerDefinitions,
	}, nil
}
