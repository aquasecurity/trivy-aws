package types

import (
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func ToString(p *string, m trivyTypes.Metadata) trivyTypes.StringValue {
	if p == nil {
		return trivyTypes.StringDefault("", m)
	}
	return trivyTypes.String(*p, m)
}

func ToBool(p *bool, m trivyTypes.Metadata) trivyTypes.BoolValue {
	if p == nil {
		return trivyTypes.BoolDefault(false, m)
	}
	return trivyTypes.Bool(*p, m)
}

func ToInt(p *int32, m trivyTypes.Metadata) trivyTypes.IntValue {
	if p == nil {
		return trivyTypes.IntDefault(0, m)
	}
	return trivyTypes.IntFromInt32(*p, m)
}
