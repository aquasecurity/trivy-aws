package adapters

import (
	"github.com/aquasecurity/defsec/pkg/debug"

	"github.com/nikpivkin/trivy-aws/pkg/concurrency"
	"github.com/nikpivkin/trivy-aws/pkg/progress"
)

type Options struct {
	ProgressTracker     progress.Tracker
	Region              string
	Endpoint            string
	Services            []string
	DebugWriter         debug.Logger
	ConcurrencyStrategy concurrency.Strategy
}
