package options

import (
	"github.com/aquasecurity/trivy/pkg/iac/debug"

	"github.com/aquasecurity/trivy-aws/pkg/concurrency"
	"github.com/aquasecurity/trivy-aws/pkg/progress"
)

type Options struct {
	ProgressTracker     progress.Tracker
	Region              string
	Endpoint            string
	Services            []string
	DebugWriter         debug.Logger
	ConcurrencyStrategy concurrency.Strategy
}
