package options

import (
	"github.com/aquasecurity/trivy-aws/pkg/concurrency"
	"github.com/aquasecurity/trivy-aws/pkg/progress"
)

type Options struct {
	ProgressTracker     progress.Tracker
	Region              string
	Endpoint            string
	Services            []string
	ConcurrencyStrategy concurrency.Strategy
}
