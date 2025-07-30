ERROR	[rego] Error occurred while parsing. Trying to fallback to embedded check	file_path="home/user/.cache/trivy/policy/content/policies/cloud/policies/aws/ec2/specify_ami_owners.rego" err="home/user/.cache/trivy/policy/content/policies/cloud/policies/aws/ec2/specify_ami_owners.rego:30: rego_type_error: undefined ref: input.aws.ec2.requestedamis[__local622__]
	input.aws.ec2.requestedamis[__local622__]
    ^
    have: \"requestedamis\"
    want (one of): [\"instances\" \"launchconfigurations\" \"launchtemplates\" \"networkacls\" \"securitygroups\" \"subnets\" \"volumes\" \"vpcs\"]"
ERROR	[rego] Failed to find embedded check, skipping	file_path="home/user/.cache/trivy/policy/content/policies/cloud/policies/aws/ec2/specify_ami_owners.rego"
ERROR	[rego] Error occurred while parsing	file_path="home/user/.cache/trivy/policy/content/policies/cloud/policies/aws/ec2/specify_ami_owners.rego" err="home/user/.cache/trivy/policy/content/policies/cloud/policies/aws/ec2/specify_ami_owners.rego:30: rego_type_error: undefined ref: input.aws.ec2.requestedamis[__local622__]
	input.aws.ec2.requestedamis[__local622__]
    ^
    have: \"requestedamis\"
    want (one of): [\"instances\" \"launchconfigurations\" \"launchtemplates\" \"networkacls\" \"securitygroups\" \"subnets\" \"volumes\" \"vpcs\"]"

❯ trivy aws -d
2025-07-25T22:25:05-06:00       DEBUG   Default config file "file_path=trivy.yaml" not found, using built in values
2025-07-25T22:25:05-06:00       DEBUG   Cache dir       dir="/home/user/.cache/trivy"
2025-07-25T22:25:05-06:00       DEBUG   Cache dir       dir="/home/user/.cache/trivy"
2025-07-25T22:25:05-06:00       DEBUG   Parsed severities       severities=[UNKNOWN LOW MEDIUM HIGH CRITICAL]
2025-07-25T22:25:05-06:00       DEBUG   Timeout is set to less than 1 hour - upgrading to 1 hour for this command.
2025-07-25T22:25:05-06:00       DEBUG   [aws] Looking for AWS credentials provider...
2025-07-25T22:25:05-06:00       DEBUG   [aws] Looking up AWS caller identity...
2025-07-25T22:25:06-06:00       DEBUG   [aws] Verified AWS credentials for account!     account="671027463601"
2025-07-25T22:25:06-06:00       DEBUG   [aws] No service(s) specified, scanning all services...
2025-07-25T22:25:06-06:00       DEBUG   [aws] Scanning services services=[accessanalyzer api-gateway athena cloudfront cloudtrail codebuild documentdb dynamodb ec2 ecr ecs efs eks elasticache elasticsearch elb emr iam kinesis kms lambda mq msk neptune rds redshift s3 sns sqs ssm workspaces cloudwatch]
2025-07-25T22:25:06-06:00       DEBUG   Policies successfully loaded from disk
2025-07-25T22:25:07-06:00       DEBUG   [rego] Overriding filesystem for checks
2025-07-25T22:25:07-06:00       DEBUG   [rego] Embedded libraries are loaded    count=15
2025-07-25T22:25:07-06:00       DEBUG   [rego] Embedded checks are loaded       count=509
2025-07-25T22:25:07-06:00       DEBUG   [rego] Checks from disk are loaded      count=536
2025-07-25T22:25:07-06:00       DEBUG   [rego] Overriding filesystem for data
2025-07-25T22:25:08-06:00       ERROR   [rego] Error occurred while parsing. Trying to fallback to embedded check       file_path="home/user/.cache/trivy/policy/content/policies/cloud/policies/aws/ec2/specify_ami_owners.rego" err="home/user/.cache/trivy/policy/content/policies/cloud/policies/aws/ec2/specify_ami_owners.rego:30: rego_type_error: undefined ref: input.aws.ec2.requestedamis[__local622__]\n\tinput.aws.ec2.requestedamis[__local622__]\n\t              ^\n\t              have: \"requestedamis\"\n\t              want (one of): [\"instances\" \"launchconfigurations\" \"launchtemplates\" \"networkacls\" \"securitygroups\" \"subnets\" \"volumes\" \"vpcs\"]"
2025-07-25T22:25:08-06:00       ERROR   [rego] Failed to find embedded check, skipping  file_path="home/user/.cache/trivy/policy/content/policies/cloud/policies/aws/ec2/specify_ami_owners.rego"
2025-07-25T22:25:08-06:00       ERROR   [rego] Error occurred while parsing     file_path="home/user/.cache/trivy/policy/content/policies/cloud/policies/aws/ec2/specify_ami_owners.rego" err="home/bryan/.cache/trivy/policy/content/policies/cloud/policies/aws/ec2/specify_ami_owners.rego:30: rego_type_error: undefined ref: input.aws.ec2.requestedamis[__local622__]\n\tinput.aws.ec2.requestedamis[__local622__]\n\t              ^\n\t              have: \"requestedamis\"\n\t              want (one of): [\"instances\" \"launchconfigurations\" \"launchtemplates\" \"networkacls\" \"securitygroups\" \"subnets\" \"volumes\" \"vpcs\"]"
2025-07-25T22:25:08-06:00       DEBUG   [rego] Scanning inputs  count=1
2025-07-25T22:25:24-06:00       DEBUG   [aws] Writing report to output...
