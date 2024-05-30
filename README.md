# trivy-aws

## Installing Trivy AWS Plugin

```shell
$ trivy plugin install github.com/aquasecurity/trivy-aws
```

## Usage

Scan an AWS account for misconfigurations. Trivy uses the same authentication methods as the AWS CLI. See https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html

The following services are supported:

- accessanalyzer
- api-gateway
- athena
- cloudfront
- cloudtrail
- cloudwatch
- codebuild
- documentdb
- dynamodb
- ec2
- ecr
- ecs
- efs
- eks
- elasticache
- elasticsearch
- elb
- emr
- iam
- kinesis
- kms
- lambda
- mq
- msk
- neptune
- rds
- redshift
- s3
- sns
- sqs
- ssm
- workspaces

```shell
Usage:
  trivy aws-scan [flags]

Examples:
  # basic scanning
  $ trivy aws-scan --region us-east-1

  # limit scan to a single service:
  $ trivy aws-scan --region us-east-1 --service s3

  # limit scan to multiple services:
  $ trivy aws-scan --region us-east-1 --service s3 --service ec2

  # force refresh of cache for fresh results
  $ trivy aws-scan --region us-east-1 --update-cache
```

_trivy-aws_ is the AWS misconfiguration scanning logic for Trivy

Please see [ARCHITECTURE.md](ARCHITECTURE.md) for more information.

_trivy-aws_ is an [Aqua Security](https://aquasec.com) open source project.
Learn about our open source work and portfolio [here](https://www.aquasec.com/products/open-source-projects/).
Join the community, and talk to us about any matter in [GitHub Discussion](https://github.com/aquasecurity/trivy/discussions).
