package commands

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aquasecurity/trivy-aws/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/spf13/cobra"
	"golang.org/x/xerrors"
)

func NewCmd() *cobra.Command {
	reportFlagGroup := flag.NewReportFlagGroup()
	compliance := flag.ComplianceFlag
	compliance.Values = []string{
		types.ComplianceAWSCIS12,
		types.ComplianceAWSCIS14,
	}
	reportFlagGroup.Compliance = &compliance // override usage as the accepted values differ for each subcommand.
	reportFlagGroup.ExitOnEOL = nil          // disable '--exit-on-eol'
	reportFlagGroup.ShowSuppressed = nil     // disable '--show-suppressed'

	awsFlags := &flag.Flags{
		GlobalFlagGroup:  flag.NewGlobalFlagGroup(),
		AWSFlagGroup:     flag.NewAWSFlagGroup(),
		CloudFlagGroup:   flag.NewCloudFlagGroup(),
		MisconfFlagGroup: flag.NewMisconfFlagGroup(),
		RegoFlagGroup:    flag.NewRegoFlagGroup(),
		ReportFlagGroup:  reportFlagGroup,
	}

	services := scanner.AllSupportedServices()
	sort.Strings(services)

	cmd := &cobra.Command{
		Use:     "aws-scan [flags]",
		Aliases: []string{},
		Args:    cobra.ExactArgs(0),
		Short:   "[EXPERIMENTAL] Scan AWS account",
		Long: fmt.Sprintf(`Scan an AWS account for misconfigurations. Trivy uses the same authentication methods as the AWS CLI. See https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html

The following services are supported:

- %s
`, strings.Join(services, "\n- ")),
		Example: `  # basic scanning
  $ trivy aws-scan --region us-east-1

  # limit scan to a single service:
  $ trivy aws-scan --region us-east-1 --service s3

  # limit scan to multiple services:
  $ trivy aws-scan --region us-east-1 --service s3 --service ec2

  # force refresh of cache for fresh results
  $ trivy aws-scan --region us-east-1 --update-cache
`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := awsFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			opts, err := awsFlags.ToOptions(args)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			if opts.Timeout < time.Hour {
				opts.Timeout = time.Hour
				log.Debug("Timeout is set to less than 1 hour - upgrading to 1 hour for this command.")
			}
			return Run(cmd.Context(), opts)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	// cmd.SetFlagErrorFunc(flagErrorFunc)
	awsFlags.AddFlags(cmd)
	// cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, awsFlags.Usages(cmd)))

	return cmd
}
