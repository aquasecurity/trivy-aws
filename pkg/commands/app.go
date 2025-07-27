package commands

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-aws/internal/version"
	"github.com/aquasecurity/trivy-aws/pkg/flag"
	"github.com/aquasecurity/trivy-aws/pkg/scanner"
	trivyflag "github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
)

func NewCmd() *cobra.Command {

	trivyTypes.SupportedCompliances = []trivyTypes.Compliance{
		trivyTypes.ComplianceAWSCIS12,
		trivyTypes.ComplianceAWSCIS14,
	}

	reportFlagGroup := trivyflag.NewReportFlagGroup()
	compliance := trivyflag.ComplianceFlag
	reportFlagGroup.Compliance = &compliance // override usage as the accepted values differ for each subcommand.
	reportFlagGroup.ExitOnEOL = nil          // disable '--exit-on-eol'
	reportFlagGroup.ShowSuppressed = nil     // disable '--show-suppressed'

	globalFlags := trivyflag.NewGlobalFlagGroup()
	awsFlags := &flag.Flags{
		BaseFlags: trivyflag.Flags{
			GlobalFlagGroup:  globalFlags,
			AWSFlagGroup:     trivyflag.NewAWSFlagGroup(),
			MisconfFlagGroup: trivyflag.NewMisconfFlagGroup(),
			RegoFlagGroup:    trivyflag.NewRegoFlagGroup(),
			ReportFlagGroup:  reportFlagGroup,
			DBFlagGroup: &trivyflag.DBFlagGroup{
				NoProgress: trivyflag.NoProgressFlag.Clone(),
			},
		},
		CloudFlagGroup: flag.NewCloudFlagGroup(),
	}

	services := scanner.AllSupportedServices()
	sort.Strings(services)

	cmd := &cobra.Command{
		Use:     "aws [flags]",
		Aliases: []string{},
		Args:    cobra.ExactArgs(0),
		Short:   "[EXPERIMENTAL] Scan AWS account",
		Version: version.Version(),
		Long: fmt.Sprintf(`Scan an AWS account for misconfigurations. It uses the same authentication methods as the AWS CLI. See https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html

The following services are supported:

- %s
`, strings.Join(services, "\n- ")),
		Example: `  # basic scanning
  $ trivy aws --region us-east-1

  # limit scan to a single service:
  $ trivy aws --region us-east-1 --service s3

  # limit scan to multiple services:
  $ trivy aws --region us-east-1 --service s3 --service ec2

  # force refresh of cache for fresh results
  $ trivy aws --region us-east-1 --update-cache
`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// viper.BindPFlag cannot be called in init().
			// cf. https://github.com/spf13/cobra/issues/875
			//     https://github.com/spf13/viper/issues/233
			if err := globalFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}

			// The config path is needed for config initialization.
			// It needs to be obtained before ToOptions().
			configPath := viper.GetString(trivyflag.ConfigFileFlag.ConfigName)

			// Configure environment variables and config file
			// It cannot be called in init() because it must be called after viper.BindPFlags.
			if err := initConfig(configPath, cmd.Flags().Changed(trivyflag.ConfigFileFlag.ConfigName)); err != nil {
				return err
			}

			globalOptions, err := globalFlags.ToOptions()
			if err != nil {
				return err
			}

			// Initialize logger
			log.InitLogger(globalOptions.Debug, globalOptions.Quiet)

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

	cmd.SetVersionTemplate("Version: {{.Version}}\n")
	cmd.Flags().BoolP("version", "v", false, "version for aws plugin")

	globalFlags.AddFlags(cmd)
	awsFlags.AddFlags(cmd)

	return cmd
}

func initConfig(configFile string, pathChanged bool) error {
	// Read from config
	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")
	if err := viper.ReadInConfig(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if !pathChanged {
				log.Debugf("Default config file %q not found, using built in values", log.String("file_path", configFile))
				return nil
			}
		}
		return xerrors.Errorf("config file %q loading error: %s", configFile, err)
	}
	log.Info("Loaded", log.String("file_path", configFile))
	return nil
}
