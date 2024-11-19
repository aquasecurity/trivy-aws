package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"

	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	defsecRules "github.com/aquasecurity/trivy/pkg/iac/types/rules"
	"github.com/aquasecurity/trivy/pkg/log"

	adapter "github.com/aquasecurity/trivy-aws/internal/adapters/cloud"
	"github.com/aquasecurity/trivy-aws/internal/adapters/cloud/aws"
	options2 "github.com/aquasecurity/trivy-aws/internal/adapters/cloud/options"
	"github.com/aquasecurity/trivy-aws/pkg/concurrency"
	"github.com/aquasecurity/trivy-aws/pkg/errs"
	"github.com/aquasecurity/trivy-aws/pkg/progress"
)

var _ ConfigurableAWSScanner = (*Scanner)(nil)

type Scanner struct {
	sync.Mutex
	regoScanner         *rego.Scanner
	logger              *log.Logger
	options             []options.ScannerOption
	progressTracker     progress.Tracker
	region              string
	endpoint            string
	services            []string
	frameworks          []framework.Framework
	spec                string
	concurrencyStrategy concurrency.Strategy
	regoOnly            bool
}

func (s *Scanner) SetIncludeDeprecatedChecks(bool) {}

func (s *Scanner) SetRegoOnly(value bool) {
	s.regoOnly = value
}

func (s *Scanner) SetFrameworks(frameworks []framework.Framework) {
	s.frameworks = frameworks
}

func (s *Scanner) SetSpec(spec string) {
	s.spec = spec
}

func (s *Scanner) Name() string {
	return "AWS API"
}

func (s *Scanner) SetProgressTracker(t progress.Tracker) {
	s.progressTracker = t
}

func AllSupportedServices() []string {
	return aws.AllServices()
}

func (s *Scanner) SetAWSRegion(region string) {
	s.region = region
}

func (s *Scanner) SetAWSEndpoint(endpoint string) {
	s.endpoint = endpoint
}

func (s *Scanner) SetAWSServices(services []string) {
	s.services = services
}

func (s *Scanner) SetConcurrencyStrategy(strategy concurrency.Strategy) {
	s.concurrencyStrategy = strategy
}

func New(opts ...options.ScannerOption) *Scanner {

	s := &Scanner{
		options:             opts,
		progressTracker:     progress.NoProgress,
		concurrencyStrategy: concurrency.DefaultStrategy,
		logger:              log.WithPrefix("aws-api-scanner"),
	}

	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Scanner) CreateState(ctx context.Context) (*state.State, error) {
	cloudState, err := adapter.Adapt(ctx, options2.Options{
		ProgressTracker:     s.progressTracker,
		Region:              s.region,
		Endpoint:            s.endpoint,
		Services:            s.services,
		ConcurrencyStrategy: s.concurrencyStrategy,
	})
	if err != nil {
		var adaptionError errs.AdapterError
		if errors.As(err, &adaptionError) {
			s.logger.Error("Errors occurred during the adaptation. See logs above")
		} else {
			return nil, err
		}
	}
	return cloudState, nil
}

func (s *Scanner) ScanWithStateRefresh(ctx context.Context) (results scan.Results, err error) {
	cloudState, err := s.CreateState(ctx)
	if err != nil {
		return nil, err
	}
	return s.Scan(ctx, cloudState)
}

func (s *Scanner) Scan(ctx context.Context, cloudState *state.State) (results scan.Results, err error) {

	if cloudState == nil {
		return nil, fmt.Errorf("cloud state is nil")
	}

	// evaluate go rules
	if !s.regoOnly {
		for _, rule := range s.getRules() {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			if rule.GetRule().RegoPackage != "" {
				continue
			}
			ruleResults := rule.Evaluate(cloudState)
			if len(ruleResults) > 0 {
				s.logger.Debug("Found results",
					log.Int("count", len(ruleResults)), log.String("check", rule.GetRule().AVDID))
				results = append(results, ruleResults...)
			}
		}
	}

	// evaluate rego rules
	regoScanner, err := s.initRegoScanner()
	if err != nil {
		return nil, err
	}

	regoResults, err := regoScanner.ScanInput(ctx, rego.Input{
		Contents: cloudState.ToRego(),
	})
	if err != nil {
		return nil, err
	}
	return append(results, regoResults...), nil
}

func (s *Scanner) getRules() []defsecRules.RegisteredRule {
	if len(s.frameworks) > 0 { // Only for maintaining backwards compat
		return rules.GetRegistered(s.frameworks...)
	}
	return rules.GetSpecRules(s.spec)
}

func (s *Scanner) initRegoScanner() (*rego.Scanner, error) {
	s.Lock()
	defer s.Unlock()

	if s.regoScanner != nil {
		return s.regoScanner, nil
	}

	fsys := os.DirFS("/")
	if runtime.GOOS == "windows" {
		homeDrive := os.Getenv("HOMEDRIVE")
		if homeDrive == "" {
			homeDrive = "C:"
		}
		fsys = os.DirFS(homeDrive + "\\")
	}

	regoScanner := rego.NewScanner(types.SourceCloud, s.options...)
	if err := regoScanner.LoadPolicies(fsys); err != nil {
		return nil, err
	}
	s.regoScanner = regoScanner
	return regoScanner, nil
}
