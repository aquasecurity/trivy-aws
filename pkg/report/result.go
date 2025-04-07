package report

import (
	"bytes"
	"io"

	"github.com/aquasecurity/tml"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/report/table"
	"github.com/aquasecurity/trivy/pkg/types"
)

func writeResultsForARN(report *Report, results types.Results, output io.Writer, service, arn string, severities []dbTypes.Severity) error {

	// render scan title
	_ = tml.Fprintf(output, "\n<bold>Results for '%s' (%s Account %s)</bold>\n\n", arn, report.Provider, report.AccountID)

	var buf bytes.Buffer
	for _, result := range results {
		var filtered []types.DetectedMisconfiguration
		for _, misconfiguration := range result.Misconfigurations {
			if arn != "" && misconfiguration.CauseMetadata.Resource != arn {
				continue
			}
			if service != "" && misconfiguration.CauseMetadata.Service != service {
				continue
			}
			filtered = append(filtered, misconfiguration)
		}

		if len(filtered) > 0 {
			renderer := table.NewMisconfigRenderer(&buf, severities, false, false, true, nil)
			renderer.Render(result)
		}
	}

	_, _ = buf.WriteTo(output)

	return nil
}
