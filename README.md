# trivy-aws

## Installing Trivy AWS Plugin

The following assumes Trivy is already installed.

See [Installing Trivy](https://trivy.dev/latest/getting-started/installation/)

```shell
$ trivy plugin install github.com/aquasecurity/trivy-aws
```

## Usage

### Prerequisites

1. **AWS Authentication**: Configure AWS credentials using one of these methods:
   - AWS CLI: `aws configure` OR  `aws sso`
   - See [AWS CLI Configuration Guide](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html)

2. **Required Permissions**: Ensure your AWS credentials have read access to the services you want to scan

### Quick Start

```shell
# Scan your default AWS account and region for all severity issues
$ trivy aws

# Show Trivy AWS plugin help, including supported flags
$ trivy aws -h

# Scan your default AWS account and region for only HIGH and CRITICAL severity issues
$ trivy aws -s HIGH,CRITICAL

# Scan your default AWS account for a specific region
$ trivy aws --region us-east-1

# Scan specific services only
$ trivy aws --region us-east-1 --service s3 --service iam
```

### Common Use Cases

```shell
# Security audit of S3 buckets
$ trivy aws --region us-east-1 --service s3

# Check IAM configurations
$ trivy aws --region us-east-1 --service iam

# Full account scan with fresh data
$ trivy aws --region us-east-1 --update-cache

# Scan multiple regions
$ trivy aws --region us-east-1 --region us-west-2

# Scan an alternate account/profile
$ AWS_PROFILE=sandbox trivy aws
```

### Understanding Results

Trivy will output:

- List of Services
- **CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN**: Severity levels of found misconfigurations
- **Resource details**: Specific AWS resources with issues
- **Recommendations**: How to fix identified problems

Example output table:
Scan Overview for AWS Account XXXXXXXXXXXX
┌────────────────┬──────────────────────────────────────────────────┬──────────────┐
│                │                Misconfigurations                 │              │
│                ├──────────┬──────────────┬────────┬─────┬─────────┤              │
│ Service        │ Critical │     High     │ Medium │ Low │ Unknown │ Last Scanned │
├────────────────┼──────────┼──────────────┼────────┼─────┼─────────┼──────────────┤
│ accessanalyzer │        0 │            0 │      0 │   0 │       0 │ just now     │
│ api-gateway    │        0 │            0 │      0 │   0 │       0 │ just now     │
│ athena         │        0 │            2 │      0 │   0 │       0 │ just now     │
│ cloudfront     │        0 │            0 │      0 │   0 │       0 │ just now     │
│ cloudtrail     │        0 │            1 │      0 │   0 │       0 │ just now     │
│ cloudwatch     │        0 │            0 │      0 │  16 │       0 │ just now     │
│ codebuild      │        0 │            0 │      0 │   0 │       0 │ just now     │
│ documentdb     │        0 │            0 │      0 │   0 │       0 │ just now     │
│ dynamodb       │        0 │            0 │      1 │   1 │       0 │ just now     │
│ ec2            │       12 │            6 │      6 │  15 │       0 │ just now     │
│ ecr            │        0 │            0 │      0 │   0 │       0 │ just now     │
│ ecs            │        0 │            0 │      0 │   0 │       0 │ just now     │
│ efs            │        0 │            0 │      0 │   0 │       0 │ just now     │
│ eks            │        0 │            0 │      0 │   0 │       0 │ just now     │
│ elasticache    │        0 │            0 │      0 │   0 │       0 │ just now     │
│ elasticsearch  │        0 │            0 │      0 │   0 │       0 │ just now     │
│ elb            │        1 │            0 │      0 │   0 │       0 │ just now     │
│ emr            │        0 │            0 │      0 │   0 │       0 │ just now     │
│ iam            │        0 │            1 │      6 │   6 │       0 │ just now     │
│ kinesis        │        0 │            0 │      0 │   0 │       0 │ just now     │
│ kms            │        0 │            0 │     12 │   0 │       0 │ just now     │
│ lambda         │        0 │            0 │      0 │   1 │       0 │ just now     │
│ mq             │        0 │            0 │      0 │   0 │       0 │ just now     │
│ msk            │        0 │            0 │      0 │   0 │       0 │ just now     │
│ neptune        │        0 │            0 │      0 │   0 │       0 │ just now     │
│ rds            │        0 │            0 │      0 │   0 │       0 │ just now     │
│ redshift       │        0 │            0 │      0 │   0 │       0 │ just now     │
│ s3             │        0 │           11 │      6 │   8 │       0 │ just now     │
│ sns            │        0 │            1 │      0 │   0 │       0 │ just now     │
│ sqs            │        0 │            0 │      0 │   0 │       0 │ just now     │
│ ssm            │        0 │            0 │      0 │   0 │       0 │ just now     │
│ workspaces     │        0 │            0 │      0 │   0 │       0 │ just now     │
└────────────────┴──────────┴──────────────┴────────┴─────┴─────────┴──────────────┘

### Architecture

Please see [Architecture.md](Architecture.md) for more information.

_trivy-aws_ is an [Aqua Security](https://aquasec.com) open source project.
Learn about our open source work and portfolio at [open-source-projects](https://www.aquasec.com/products/open-source-projects/).
Join the community, and talk to us about any matter in [GitHub Discussion](https://github.com/aquasecurity/trivy/discussions).
