package scanner

import (
	"context"
	"fmt"
	"io/fs"
	"os"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-aws/pkg/cache"
	"github.com/aquasecurity/trivy-aws/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/misconf"
	"github.com/aquasecurity/trivy/pkg/policy"
)

type AWSScanner struct {
}

func NewScanner() *AWSScanner {
	return &AWSScanner{}
}

func (s *AWSScanner) Scan(ctx context.Context, option flag.Options) (scan.Results, bool, error) {

	awsCache := cache.New(option.CacheDir, option.MaxCacheAge, option.Account, option.Region)
	included, missing := awsCache.ListServices(option.Services)

	var scannerOpts []options.ScannerOption

	noProgress := option.Quiet || option.NoProgress
	if !noProgress {
		tracker := newProgressTracker(os.Stdout)
		defer tracker.Finish()
		scannerOpts = append(scannerOpts, ScannerWithProgressTracker(tracker))
	}

	if len(missing) > 0 {
		scannerOpts = append(scannerOpts, ScannerWithAWSServices(missing...))
	}

	if option.Trace {
		scannerOpts = append(scannerOpts, rego.WithPerResultTracing(true))
	}

	if option.Region != "" {
		scannerOpts = append(
			scannerOpts,
			ScannerWithAWSRegion(option.Region),
		)
	}

	if option.Endpoint != "" {
		scannerOpts = append(
			scannerOpts,
			ScannerWithAWSEndpoint(option.Endpoint),
		)
	}

	var (
		disableEmbedded bool
		policyPaths     []string
		err             error
	)

	c, _ := policy.NewClient(option.CacheDir, option.Quiet, option.MisconfOptions.ChecksBundleRepository)
	downloadedPolicyPaths, err := operation.InitBuiltinChecks(context.Background(), c, option.SkipCheckUpdate, option.RegistryOpts())
	if err != nil {
		if !option.SkipCheckUpdate {
			log.Errorf("Falling back to embedded policies: %s", err)
		}
	} else {
		log.Debug("Policies successfully loaded from disk")
		policyPaths = append(policyPaths, downloadedPolicyPaths)
		disableEmbedded = true
	}

	scannerOpts = append(scannerOpts,
		rego.WithEmbeddedPolicies(!disableEmbedded),
		rego.WithEmbeddedLibraries(!disableEmbedded),
	)

	var policyFS fs.FS
	policyFS, policyPaths, err = misconf.CreatePolicyFS(append(policyPaths, option.RegoOptions.CheckPaths...))
	if err != nil {
		return nil, false, xerrors.Errorf("unable to create policyfs: %w", err)
	}

	scannerOpts = append(scannerOpts,
		rego.WithPolicyFilesystem(policyFS),
		rego.WithPolicyDirs(policyPaths...),
	)

	dataFS, dataPaths, err := misconf.CreateDataFS(option.RegoOptions.DataPaths)
	if err != nil {
		log.Errorf("Could not load config data: %s", err)
	}
	scannerOpts = append(scannerOpts,
		rego.WithDataDirs(dataPaths...),
		rego.WithDataFilesystem(dataFS),
	)

	scannerOpts = addPolicyNamespaces(option.RegoOptions.CheckNamespaces, scannerOpts)

	if option.Compliance.Spec.ID == "" {
		scannerOpts = append(scannerOpts, rego.WithFrameworks(
			framework.Default,
			framework.CIS_AWS_1_2),
		)
	}

	scanner := New(scannerOpts...)

	var freshState *state.State
	if len(missing) > 0 || option.CloudOptions.UpdateCache {
		var err error
		freshState, err = scanner.CreateState(ctx)
		if err != nil {
			return nil, false, err
		}
	}

	fullState, err := createState(freshState, awsCache)
	if err != nil {
		return nil, false, err
	}

	if fullState == nil {
		return nil, false, fmt.Errorf("no resultant state found")
	}

	if err := awsCache.AddServices(fullState, missing); err != nil {
		return nil, false, err
	}

	defsecResults, err := scanner.Scan(ctx, fullState)
	if err != nil {
		return nil, false, err
	}

	return defsecResults, len(included) > 0, nil
}

func createState(freshState *state.State, awsCache *cache.Cache) (*state.State, error) {
	var fullState *state.State
	if previousState, err := awsCache.LoadState(); err == nil {
		if freshState != nil {
			fullState, err = previousState.Merge(freshState)
			if err != nil {
				return nil, err
			}
		} else {
			fullState = previousState
		}
	} else {
		fullState = freshState
	}
	return fullState, nil
}

func addPolicyNamespaces(namespaces []string, scannerOpts []options.ScannerOption) []options.ScannerOption {
	if len(namespaces) > 0 {
		scannerOpts = append(
			scannerOpts,
			rego.WithPolicyNamespaces(namespaces...),
		)
	}
	return scannerOpts
}
