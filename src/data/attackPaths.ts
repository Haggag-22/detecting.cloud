export interface AttackPath {
  slug: string;
  title: string;
  overview: string;
  severity: "Critical" | "High" | "Medium";
  steps: string[];
  permissions: string[];
  detectionOpportunities: string[];
  mitigations: string[];
}

export const attackPaths: AttackPath[] = [
  {
    slug: "aws-passrole-abuse",
    title: "AWS PassRole Abuse",
    overview: "Exploit iam:PassRole to escalate privileges by passing high-privilege roles to AWS services like Lambda, EC2, or Glue.",
    severity: "Critical",
    steps: [
      "Enumerate available IAM roles with elevated permissions",
      "Identify services the attacker has CreateFunction or RunInstances access to",
      "Pass the high-privilege role to the target service using iam:PassRole",
      "Execute code through the service using the escalated role",
      "Perform privileged actions (e.g., create admin user, exfiltrate data)",
    ],
    permissions: ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
    detectionOpportunities: [
      "Monitor CloudTrail for PassRole events targeting sensitive roles",
      "Alert on new Lambda functions with administrative roles",
      "Correlate service creation with subsequent privileged API calls",
    ],
    mitigations: [
      "Restrict PassRole to specific role ARNs via resource conditions",
      "Implement permission boundaries on all roles",
      "Use SCPs to limit which roles can be passed",
    ],
  },
  {
    slug: "iam-privilege-escalation",
    title: "IAM Privilege Escalation",
    overview: "Chain IAM misconfigurations to escalate from a low-privilege user to administrator access.",
    severity: "Critical",
    steps: [
      "Enumerate IAM policies attached to the current principal",
      "Identify misconfigured policies (e.g., iam:AttachUserPolicy, iam:CreatePolicyVersion)",
      "Exploit the misconfiguration to grant higher privileges",
      "Verify escalated access by calling privileged APIs",
    ],
    permissions: ["iam:AttachUserPolicy", "iam:CreatePolicyVersion", "iam:PutUserPolicy"],
    detectionOpportunities: [
      "Monitor for IAM policy attachment events",
      "Alert on new policy version creation",
      "Track inline policy changes",
    ],
    mitigations: [
      "Follow least-privilege principles for IAM policies",
      "Use AWS Access Analyzer to identify overly permissive policies",
      "Implement permission boundaries",
    ],
  },
  {
    slug: "lambda-persistence",
    title: "Lambda Persistence",
    overview: "Establish persistent access by deploying backdoor Lambda functions triggered by CloudWatch events or S3 uploads.",
    severity: "High",
    steps: [
      "Create a Lambda function with malicious code",
      "Attach an execution role with necessary permissions",
      "Create an event source mapping or CloudWatch rule as a trigger",
      "The function executes automatically on trigger events",
    ],
    permissions: ["lambda:CreateFunction", "iam:PassRole", "events:PutRule", "events:PutTargets"],
    detectionOpportunities: [
      "Monitor new Lambda function creation",
      "Track CloudWatch Events rule changes",
      "Alert on Lambda functions making external network calls",
    ],
    mitigations: [
      "Restrict Lambda creation to specific roles",
      "Use VPC-attached Lambda functions",
      "Audit event source mappings regularly",
    ],
  },
  {
    slug: "s3-data-exfiltration",
    title: "S3 Data Exfiltration",
    overview: "Exfiltrate sensitive data from S3 buckets using compromised credentials, cross-account replication, or pre-signed URLs.",
    severity: "High",
    steps: [
      "Enumerate accessible S3 buckets",
      "Identify buckets containing sensitive data",
      "Download data directly or configure cross-account replication",
      "Use pre-signed URLs for stealthy exfiltration",
    ],
    permissions: ["s3:GetObject", "s3:ListBucket", "s3:PutBucketReplication"],
    detectionOpportunities: [
      "Monitor for unusual GetObject volume",
      "Alert on bucket policy or replication configuration changes",
      "Track S3 access from unusual source IPs or user agents",
    ],
    mitigations: [
      "Enable S3 data event logging in CloudTrail",
      "Use VPC endpoints to restrict S3 access paths",
      "Implement S3 Block Public Access at the account level",
    ],
  },
];
