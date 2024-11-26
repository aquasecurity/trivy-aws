package elb

import (
	api "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/aquasecurity/trivy-aws/internal/adapters/cloud/aws"
	"github.com/aquasecurity/trivy-aws/pkg/concurrency"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/elb"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type adapter struct {
	*aws.RootAdapter
	api *api.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "elb"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.ELB.LoadBalancers, err = a.getLoadBalancers()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getLoadBalancers() ([]elb.LoadBalancer, error) {

	a.Tracker().SetServiceLabel("Discovering load balancers...")

	var apiLoadBalancers []types.LoadBalancer
	var input api.DescribeLoadBalancersInput
	for {
		output, err := a.api.DescribeLoadBalancers(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiLoadBalancers = append(apiLoadBalancers, output.LoadBalancers...)
		a.Tracker().SetTotalResources(len(apiLoadBalancers))
		if output.NextMarker == nil {
			break
		}
		input.Marker = output.NextMarker
	}

	a.Tracker().SetServiceLabel("Adapting load balancers...")
	return concurrency.Adapt(apiLoadBalancers, a.RootAdapter, a.adaptLoadBalancer), nil
}

func (a *adapter) adaptLoadBalancer(apiLoadBalancer types.LoadBalancer) (*elb.LoadBalancer, error) {
	metadata := a.CreateMetadataFromARN(*apiLoadBalancer.LoadBalancerArn)

	var dropInvalidHeaders bool
	{
		// routing.http.drop_invalid_header_fields.enabled
		output, err := a.api.DescribeLoadBalancerAttributes(a.Context(), &api.DescribeLoadBalancerAttributesInput{
			LoadBalancerArn: apiLoadBalancer.LoadBalancerArn,
		})
		if err != nil {
			return nil, err
		}
		for _, attr := range output.Attributes {
			if attr.Key != nil && *attr.Key == "routing.http.drop_invalid_header_fields.enabled" {
				dropInvalidHeaders = attr.Value != nil && *attr.Value == "true"
				break
			}
		}
	}

	var listeners []elb.Listener
	{
		input := api.DescribeListenersInput{
			LoadBalancerArn: apiLoadBalancer.LoadBalancerArn,
		}
		for {
			output, err := a.api.DescribeListeners(a.Context(), &input)
			if err != nil {
				return nil, err
			}
			for _, listener := range output.Listeners {
				metadata := a.CreateMetadataFromARN(*listener.ListenerArn)

				var actions []elb.Action
				for _, action := range listener.DefaultActions {
					actions = append(actions, elb.Action{
						Metadata: metadata,
						Type:     trivyTypes.String(string(action.Type), metadata),
					})
				}

				sslPolicy := trivyTypes.StringDefault("", metadata)
				if listener.SslPolicy != nil {
					sslPolicy = trivyTypes.String(*listener.SslPolicy, metadata)
				}

				listeners = append(listeners, elb.Listener{
					Metadata:       metadata,
					Protocol:       trivyTypes.String(string(listener.Protocol), metadata),
					TLSPolicy:      sslPolicy,
					DefaultActions: actions,
				})
			}
			if output.NextMarker == nil {
				break
			}
			input.Marker = output.NextMarker
		}
	}

	return &elb.LoadBalancer{
		Metadata:                metadata,
		Type:                    trivyTypes.String(string(apiLoadBalancer.Type), metadata),
		DropInvalidHeaderFields: trivyTypes.Bool(dropInvalidHeaders, metadata),
		Internal:                trivyTypes.Bool(apiLoadBalancer.Scheme == types.LoadBalancerSchemeEnumInternal, metadata),
		Listeners:               listeners,
	}, nil
}
