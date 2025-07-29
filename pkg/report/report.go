package report

import (
	"context"
	"io"
	"os"
	"sort"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/tml"
	"github.com/aquasecurity/trivy/pkg/clock"
	cr "github.com/aquasecurity/trivy/pkg/compliance/report"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	pkgReport "github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	tableFormat = "table"
)

// Report represents an AWS scan report
type Report struct {
	Provider        string
	AccountID       string
	Region          string
	Results         map[string]ResultsAtTime
	ServicesInScope []string
}

type ResultsAtTime struct {
	Results      types.Results
	CreationTime time.Time
}

func New(provider, accountID, region string, defsecResults scan.Results, scopedServices []string) *Report {
	return &Report{
		Provider:        provider,
		AccountID:       accountID,
		Results:         ConvertResults(defsecResults, provider, scopedServices),
		ServicesInScope: scopedServices,
		Region:          region,
	}
}

// Failed returns whether the aws report includes any "failed" results
func (r *Report) Failed() bool {
	for _, set := range r.Results {
		if set.Results.Failed() {
			return true
		}
	}
	return false
}

// Write writes the results in the give format
func Write(ctx context.Context, rep *Report, opt flag.Options, fromCache bool) error {
	output, cleanup, err := opt.OutputWriter(ctx)
	if err != nil {
		return xerrors.Errorf("failed to create output file: %w", err)
	}
	defer func() { _ = cleanup() }()

	if opt.Compliance.Spec.ID != "" {
		return writeCompliance(ctx, rep, opt, output)
	}

	ignoreConf, err := result.ParseIgnoreFile(ctx, opt.IgnoreFile)
	if err != nil {
		return xerrors.Errorf("%s error: %w", opt.IgnoreFile, err)
	}

	var filtered []types.Result

	// filter results
	filtered, err = filterResults(ctx, rep, opt, ignoreConf, filtered)
	if err != nil {
		return err
	}

	// combine results without a target for consistency of the result
	filtered = combineResults(filtered)

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Target < filtered[j].Target
	})

	base := types.Report{
		CreatedAt:    clock.Now(ctx),
		ArtifactName: rep.AccountID,
		ArtifactType: ftypes.TypeAWSAccount,
		Results:      filtered,
	}

	switch opt.Format {
	case tableFormat:
		// Skip table output if quiet flag is set
		if opt.Quiet {
			return nil
		}

		// ensure color/formatting is disabled for pipes/non-pty
		var useANSI bool
		if output == os.Stdout {
			if o, err := os.Stdout.Stat(); err == nil {
				useANSI = (o.Mode() & os.ModeCharDevice) == os.ModeCharDevice
			}
		}
		if !useANSI {
			tml.DisableFormatting()
		}

		switch {
		case len(opt.Services) == 1 && opt.ARN == "":
			if err := writeResourceTable(rep, filtered, output, opt.Services[0]); err != nil {
				return err
			}
		case len(opt.Services) == 1 && opt.ARN != "":
			if err := writeResultsForARN(rep, filtered, output, opt.Services[0], opt.ARN, opt.Severities); err != nil {
				return err
			}
		default:
			if err := writeServiceTable(rep, filtered, output); err != nil {
				return err
			}
		}

		// render cache info
		if fromCache {
			_ = tml.Fprintf(output, "\n<blue>This scan report was loaded from cached results. If you'd like to run a fresh scan, use --update-cache.</blue>\n")
		}

		return nil
	default:
		return pkgReport.Write(ctx, base, opt)
	}
}

func filterResults(ctx context.Context, rep *Report, opt flag.Options, ignoreConf result.IgnoreConfig, filtered []types.Result) ([]types.Result, error) {
	for serviceName, resultsAtTime := range rep.Results {
		// Skip services not in the filter list
		if len(opt.Services) > 0 && !contains(opt.Services, serviceName) {
			continue
		}
		for _, res := range resultsAtTime.Results {
			resCopy := res
			if err := result.FilterResult(ctx, &resCopy, ignoreConf, opt.FilterOpts()); err != nil {
				return nil, err
			}
			sort.Slice(resCopy.Misconfigurations, func(i, j int) bool {
				return resCopy.Misconfigurations[i].CauseMetadata.Resource < resCopy.Misconfigurations[j].CauseMetadata.Resource
			})
			filtered = append(filtered, resCopy)
		}
	}
	return filtered, nil
}

func combineResults(results []types.Result) []types.Result {
	var noTarget types.Result
	var withTarget []types.Result

	for _, r := range results {
		if r.Target == "" {
			if noTarget.MisconfSummary == nil {
				noTarget = r
			} else {
				noTarget.MisconfSummary.Failures += r.MisconfSummary.Failures
				noTarget.MisconfSummary.Successes += r.MisconfSummary.Successes
				noTarget.Misconfigurations = append(noTarget.Misconfigurations, r.Misconfigurations...)
			}
		} else {
			withTarget = append(withTarget, r)
		}
	}

	if noTarget.MisconfSummary != nil {
		misconfs := noTarget.Misconfigurations
		sort.Slice(noTarget.Misconfigurations, func(i, j int) bool {
			return misconfs[i].AVDID < misconfs[j].AVDID
		})
		withTarget = append(withTarget, noTarget)
	}

	return withTarget
}

func writeCompliance(ctx context.Context, rep *Report, opt flag.Options, output io.Writer) error {
	var crr []types.Results
	for _, r := range rep.Results {
		crr = append(crr, r.Results)
	}

	complianceReport, err := cr.BuildComplianceReport(crr, opt.Compliance)
	if err != nil {
		return xerrors.Errorf("compliance report build error: %w", err)
	}

	return cr.Write(ctx, complianceReport, cr.Option{
		Format: opt.Format,
		Report: opt.ReportFormat,
		Output: output,
	})
}
