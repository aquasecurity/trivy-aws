package types

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

func ToString(p *string, m defsecTypes.MisconfigMetadata) defsecTypes.StringValue {
	if p == nil {
		return defsecTypes.StringDefault("", m)
	}
	return defsecTypes.String(*p, m)
}

func ToBool(p *bool, m defsecTypes.MisconfigMetadata) defsecTypes.BoolValue {
	if p == nil {
		return defsecTypes.BoolDefault(false, m)
	}
	return defsecTypes.Bool(*p, m)
}

func ToInt(p *int32, m defsecTypes.MisconfigMetadata) defsecTypes.IntValue {
	if p == nil {
		return defsecTypes.IntDefault(0, m)
	}
	return defsecTypes.IntFromInt32(*p, m)
}
