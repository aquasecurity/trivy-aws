package sqs

import (
	"fmt"
	"testing"

	localstack "github.com/aquasecurity/go-mock-aws"
	"github.com/aquasecurity/trivy/pkg/providers/aws/sqs"
	"github.com/aquasecurity/trivy/pkg/state"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	sqsapi "github.com/aws/aws-sdk-go-v2/service/sqs"
	sqsTypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-aws/internal/adapters/cloud/aws"
	"github.com/aquasecurity/trivy-aws/internal/adapters/cloud/aws/test"
)

type queueDetails struct {
	queueName         string
	managedEncryption bool
}

func (q queueDetails) QueueURL(region string) string {
	return fmt.Sprintf(
		"http://sqs.%s.localhost.localstack.cloud:%s/000000000000/%s",
		region, localstack.Port, q.queueName,
	)
}

func Test_SQSQueueEncrypted(t *testing.T) {

	tests := []struct {
		name    string
		details queueDetails
	}{
		{
			name: "simple queue with no managed encryption",
			details: queueDetails{
				queueName:         "test-queue",
				managedEncryption: false,
			},
		},
		{
			name: "simple queue with managed encryption",
			details: queueDetails{
				queueName:         "test-encrypted-queue",
				managedEncryption: true,
			},
		},
	}

	ra, stack, err := test.CreateLocalstackAdapter(t)
	defer func() { _ = stack.Stop() }()
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bootstrapSQSQueue(t, ra, tt.details)

			testState := &state.State{}
			sqsAdapter := &adapter{}
			err = sqsAdapter.Adapt(ra, testState)
			require.NoError(t, err)

			assert.Len(t, testState.AWS.SQS.Queues, 1)
			var got sqs.Queue
			queueUrl := tt.details.QueueURL(ra.SessionConfig().Region)
			for _, q := range testState.AWS.SQS.Queues {
				if q.QueueURL.EqualTo(queueUrl) {
					got = q
					break
				}
			}

			assert.Equal(t, tt.details.QueueURL(ra.SessionConfig().Region), got.QueueURL.Value())
			assert.Equal(t, tt.details.managedEncryption, got.Encryption.ManagedEncryption.Value())
			removeQueue(t, ra, tt.details.QueueURL(ra.SessionConfig().Region))
		})
	}
}

func bootstrapSQSQueue(t *testing.T, ra *aws.RootAdapter, spec queueDetails) {

	api := sqsapi.NewFromConfig(ra.SessionConfig())

	queueAttributes := make(map[string]string)
	if spec.managedEncryption {
		queueAttributes[string(sqsTypes.QueueAttributeNameSqsManagedSseEnabled)] = "SSE-SQS"
	}

	queue, err := api.CreateQueue(ra.Context(), &sqsapi.CreateQueueInput{
		QueueName: awssdk.String(spec.queueName),
	})
	require.NoError(t, err)

	_, err = api.SetQueueAttributes(ra.Context(), &sqsapi.SetQueueAttributesInput{
		QueueUrl:   queue.QueueUrl,
		Attributes: queueAttributes,
	})
	require.NoError(t, err)
}

func removeQueue(t *testing.T, ra *aws.RootAdapter, queueURL string) {
	api := sqsapi.NewFromConfig(ra.SessionConfig())
	_, err := api.DeleteQueue(ra.Context(), &sqsapi.DeleteQueueInput{
		QueueUrl: awssdk.String(queueURL),
	})
	require.NoError(t, err)
}
