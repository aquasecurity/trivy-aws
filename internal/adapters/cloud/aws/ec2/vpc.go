package ec2

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	ec2api "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/aquasecurity/trivy-aws/pkg/concurrency"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func (a *adapter) getSecurityGroups() (securityGroups []ec2.SecurityGroup, err error) {

	a.Tracker().SetServiceLabel("Discovering security groups...")

	var apiSecurityGroups []types.SecurityGroup
	var input ec2api.DescribeSecurityGroupsInput

	for {
		output, err := a.client.DescribeSecurityGroups(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiSecurityGroups = append(apiSecurityGroups, output.SecurityGroups...)
		a.Tracker().SetTotalResources(len(apiSecurityGroups))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting security groups...")
	return concurrency.Adapt(apiSecurityGroups, a.RootAdapter, a.adaptSecurityGroup), nil
}

func (a *adapter) getNetworkACLs() (nacls []ec2.NetworkACL, err error) {

	a.Tracker().SetServiceLabel("Discovering network ACLs...")
	var apiNetworkACLs []types.NetworkAcl
	var input ec2api.DescribeNetworkAclsInput

	for {
		output, err := a.client.DescribeNetworkAcls(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiNetworkACLs = append(apiNetworkACLs, output.NetworkAcls...)
		a.Tracker().SetTotalResources(len(apiNetworkACLs))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}
	a.Tracker().SetServiceLabel("Adapting network ACLs...")
	return concurrency.Adapt(apiNetworkACLs, a.RootAdapter, a.adaptNetworkACL), nil
}

func (a *adapter) getVPCs() (defaultVpcs []ec2.VPC, err error) {

	a.Tracker().SetServiceLabel("Discovering VPCs...")
	var apiVPCs []types.Vpc
	var input ec2api.DescribeVpcsInput

	for {
		output, err := a.client.DescribeVpcs(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiVPCs = append(apiVPCs, output.Vpcs...)
		a.Tracker().SetTotalResources(len(apiVPCs))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting VPCs...")
	return concurrency.Adapt(apiVPCs, a.RootAdapter, a.adaptVPC), nil
}

func (a *adapter) adaptSecurityGroup(apiSecurityGroup types.SecurityGroup) (*ec2.SecurityGroup, error) {

	sgMetadata := a.CreateMetadata("security-group/" + *apiSecurityGroup.GroupId)

	sg := &ec2.SecurityGroup{
		Metadata:    sgMetadata,
		IsDefault:   trivyTypes.BoolDefault(apiSecurityGroup.GroupName != nil && *apiSecurityGroup.GroupName == "default", sgMetadata),
		Description: trivyTypes.String(aws.ToString(apiSecurityGroup.Description), sgMetadata),
		VPCID:       trivyTypes.StringDefault("", sgMetadata),
	}

	if apiSecurityGroup.VpcId != nil {
		sg.VPCID = trivyTypes.String(*apiSecurityGroup.VpcId, sgMetadata)
	}

	for _, ingress := range apiSecurityGroup.IpPermissions {

		for _, ipRange := range ingress.IpRanges {
			sg.IngressRules = append(sg.IngressRules, ec2.SecurityGroupRule{
				Metadata:    sgMetadata,
				Description: trivyTypes.String(aws.ToString(ipRange.Description), sgMetadata),
				CIDRs:       []trivyTypes.StringValue{trivyTypes.String(aws.ToString(ipRange.CidrIp), sgMetadata)},
			})
		}
	}

	for _, egress := range apiSecurityGroup.IpPermissions {

		for _, ipRange := range egress.IpRanges {
			sg.EgressRules = append(sg.EgressRules, ec2.SecurityGroupRule{
				Metadata:    sgMetadata,
				Description: trivyTypes.String(aws.ToString(ipRange.Description), sgMetadata),
				CIDRs:       []trivyTypes.StringValue{trivyTypes.String(aws.ToString(ipRange.CidrIp), sgMetadata)},
			})
		}
	}

	return sg, nil

}

func (a *adapter) adaptNetworkACL(apiNacl types.NetworkAcl) (*ec2.NetworkACL, error) {

	naclMetadata := a.CreateMetadata("network-acl/" + *apiNacl.NetworkAclId)

	nacl := &ec2.NetworkACL{
		Metadata:      naclMetadata,
		IsDefaultRule: trivyTypes.BoolDefault(false, naclMetadata),
	}

	for _, entry := range apiNacl.Entries {
		naclType := "ingress"
		if aws.ToBool(entry.Egress) {
			naclType = "egress"
		}

		nacl.Rules = append(nacl.Rules, ec2.NetworkACLRule{
			Metadata: naclMetadata,
			Action:   trivyTypes.String(string(entry.RuleAction), naclMetadata),
			Protocol: trivyTypes.String(aws.ToString(entry.Protocol), naclMetadata),
			Type:     trivyTypes.String(naclType, naclMetadata),
			CIDRs:    []trivyTypes.StringValue{trivyTypes.String(aws.ToString(entry.CidrBlock), naclMetadata)},
		})
	}
	return nacl, nil
}

func (a *adapter) adaptVPC(v types.Vpc) (*ec2.VPC, error) {

	vpcMetadata := a.CreateMetadata("vpc/" + *v.VpcId)
	vpc := &ec2.VPC{
		Metadata:        vpcMetadata,
		ID:              trivyTypes.String(*v.VpcId, vpcMetadata),
		IsDefault:       trivyTypes.BoolDefault(false, vpcMetadata),
		FlowLogsEnabled: trivyTypes.BoolDefault(false, vpcMetadata),
		SecurityGroups:  nil, // we link these up afterwards
	}

	if v.IsDefault != nil {
		vpc.IsDefault = trivyTypes.BoolDefault(*v.IsDefault, vpcMetadata)
	}

	logs, err := a.client.DescribeFlowLogs(a.Context(), &ec2api.DescribeFlowLogsInput{
		Filter: []types.Filter{
			{
				Name:   aws.String("resource-id"),
				Values: []string{*v.VpcId},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	if logs != nil && len(logs.FlowLogs) > 0 {
		vpc.FlowLogsEnabled = trivyTypes.BoolDefault(true, vpcMetadata)
	}

	return vpc, nil

}
