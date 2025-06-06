package aws

import (
	"context"
	"fmt"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/aquasecurity/trivy-aws/internal/adapters/cloud/options"
	"github.com/aquasecurity/trivy-aws/pkg/concurrency"
	"github.com/aquasecurity/trivy-aws/pkg/errs"
	"github.com/aquasecurity/trivy-aws/pkg/progress"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

var registeredAdapters []ServiceAdapter

func RegisterServiceAdapter(adapter ServiceAdapter) {
	for _, existing := range registeredAdapters {
		if existing.Name() == adapter.Name() {
			panic(fmt.Sprintf("duplicate service adapter: %s", adapter.Name()))
		}
	}
	registeredAdapters = append(registeredAdapters, adapter)
}

type ServiceAdapter interface {
	Name() string
	Provider() string
	Adapt(root *RootAdapter, state *state.State) error
}

type RootAdapter struct {
	ctx                 context.Context
	sessionCfg          aws.Config
	tracker             progress.ServiceTracker
	accountID           string
	currentService      string
	region              string
	logger              *log.Logger
	concurrencyStrategy concurrency.Strategy
}

func NewRootAdapter(ctx context.Context, cfg aws.Config, tracker progress.ServiceTracker, logger *log.Logger) *RootAdapter {
	return &RootAdapter{
		ctx:        ctx,
		tracker:    tracker,
		sessionCfg: cfg,
		region:     cfg.Region,
		logger:     logger,
	}
}

func (a *RootAdapter) Region() string {
	return a.region
}

func (a *RootAdapter) ConcurrencyStrategy() concurrency.Strategy {
	return a.concurrencyStrategy
}

func (a *RootAdapter) SessionConfig() aws.Config {
	return a.sessionCfg
}

func (a *RootAdapter) Context() context.Context {
	return a.ctx
}

func (a *RootAdapter) Tracker() progress.ServiceTracker {
	return a.tracker
}

func (a *RootAdapter) Logger() *log.Logger {
	return a.logger
}

func (a *RootAdapter) CreateMetadata(resource string) types.Metadata {

	// some services don't require region/account id in the ARN
	// see https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#genref-aws-service-namespaces
	namespace := a.accountID
	region := a.region
	switch a.currentService {
	case "s3":
		namespace = ""
		region = ""
	}

	return a.CreateMetadataFromARN((arn.ARN{
		Partition: "aws",
		Service:   a.currentService,
		Region:    region,
		AccountID: namespace,
		Resource:  resource,
	}).String())
}

func (a *RootAdapter) CreateMetadataFromARN(arn string) types.Metadata {
	return types.NewRemoteMetadata(arn)
}

type resolver struct {
	endpoint string
}

func (r *resolver) ResolveEndpoint(_, region string, _ ...interface{}) (aws.Endpoint, error) {
	return aws.Endpoint{
		URL:           r.endpoint,
		SigningRegion: region,
		Source:        aws.EndpointSourceCustom,
	}, nil
}

func createResolver(endpoint string) aws.EndpointResolverWithOptions {
	return &resolver{
		endpoint: endpoint,
	}
}

func AllServices() []string {
	var services []string
	for _, reg := range registeredAdapters {
		services = append(services, reg.Name())
	}
	return services
}

func Adapt(ctx context.Context, state *state.State, opt options.Options) error {
	c := &RootAdapter{
		ctx:                 ctx,
		tracker:             opt.ProgressTracker,
		logger:              log.WithPrefix("adapt-aws"),
		concurrencyStrategy: opt.ConcurrencyStrategy,
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}

	c.sessionCfg = cfg

	if opt.Region != "" {
		c.logger.Info("Using region", log.String("region", opt.Region))
		c.sessionCfg.Region = opt.Region
	}
	if opt.Endpoint != "" {
		c.logger.Info("Using endpoint", log.String("endpoint", opt.Endpoint))
		c.sessionCfg.EndpointResolverWithOptions = createResolver(opt.Endpoint)
	}

	c.logger.Debug("Discovering caller identity...")
	stsClient := sts.NewFromConfig(c.sessionCfg)
	result, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("failed to discover AWS caller identity: %w", err)
	}
	if result.Account == nil {
		return fmt.Errorf("missing account id for aws account")
	}
	c.accountID = *result.Account
	c.logger.Info("AWS account ID", log.String("ID", c.accountID))

	if len(opt.Services) == 0 {
		c.logger.Info("Preparing to run for all registered services...", log.Int("count", len(registeredAdapters)))
		opt.ProgressTracker.SetTotalServices(len(registeredAdapters))
	} else {
		c.logger.Info("Preparing to run for filtered services...", log.Int("count", len(opt.Services)))
		opt.ProgressTracker.SetTotalServices(len(opt.Services))
	}

	c.region = c.sessionCfg.Region

	var adapterErrors []error

	for _, adapter := range registeredAdapters {
		if len(opt.Services) != 0 && !slices.Contains(opt.Services, adapter.Name()) {
			continue
		}
		c.currentService = adapter.Name()
		c.logger.Debug("Running adapter", log.String("service", adapter.Name()))
		opt.ProgressTracker.StartService(adapter.Name())

		if err := adapter.Adapt(c, state); err != nil {
			c.logger.Error("Failed to adapt", log.String("service", adapter.Name()), log.Err(err))
			adapterErrors = append(adapterErrors, fmt.Errorf("failed to adapt service %s: %w", adapter.Name(), err))
		}
		opt.ProgressTracker.FinishService()
	}

	if len(adapterErrors) > 0 {
		return errs.NewAdapterError(adapterErrors)
	}

	return nil
}
