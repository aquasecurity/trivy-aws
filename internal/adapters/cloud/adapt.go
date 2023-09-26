package cloud

import (
	"context"

	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/trivy-aws/internal/adapters/cloud/aws"
	"github.com/aquasecurity/trivy-aws/internal/adapters/cloud/options"
)

// Adapt ...
func Adapt(ctx context.Context, opt options.Options) (*state.State, error) {
	cloudState := &state.State{}
	err := aws.Adapt(ctx, cloudState, opt)
	return cloudState, err
}
