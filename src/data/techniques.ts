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

