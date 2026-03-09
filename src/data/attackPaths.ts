export interface AttackPath {
  slug: string;
  title: string;
  overview: string;
  severity: "Critical" | "High" | "Medium";
  category: "iam-abuse" | "privilege-escalation" | "persistence" | "lateral-movement" | "data-exfiltration";
  tags: string[];
  difficulty: "Beginner" | "Intermediate" | "Advanced";
  provider: "AWS" | "Azure" | "GCP";
  steps: string[];
  permissions: string[];
  detectionOpportunities: string[];
  mitigations: string[];
  relatedDetectionIds: string[];
}

export const attackPaths: AttackPath[] = [
  {
    slug: "aws-passrole-abuse",
    title: "AWS PassRole Abuse",
    overview: "Exploit iam:PassRole to escalate privileges by passing high-privilege roles to AWS services like Lambda, EC2, or Glue.",
    severity: "Critical",
    category: "iam-abuse",
    tags: ["AWS", "IAM", "PassRole", "Privilege Escalation"],
    difficulty: "Intermediate",
    provider: "AWS",
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
    relatedDetectionIds: ["det-001"],
  },
  {
    slug: "assumerole-abuse",
    title: "AssumeRole Abuse",
    overview: "Abuse overly permissive trust policies to assume roles across accounts or within the same account for privilege escalation.",
    severity: "High",
    category: "iam-abuse",
    tags: ["AWS", "IAM", "AssumeRole", "Cross-Account"],
    difficulty: "Intermediate",
    provider: "AWS",
    steps: [
      "Enumerate roles with permissive trust policies",
      "Identify roles that allow assumption from your principal",
      "Call sts:AssumeRole to obtain temporary credentials",
      "Use the assumed role's permissions for lateral movement or escalation",
    ],
    permissions: ["sts:AssumeRole"],
    detectionOpportunities: [
      "Monitor for AssumeRole events from unusual principals",
      "Track cross-account role assumption patterns",
      "Alert on role assumption chains",
    ],
    mitigations: [
      "Use strict trust policy conditions (e.g., ExternalId, MFA)",
      "Limit which principals can assume sensitive roles",
      "Audit trust policies regularly",
    ],
    relatedDetectionIds: ["det-004"],
  },
  {
    slug: "create-policy-version-abuse",
    title: "CreatePolicyVersion Abuse",
    overview: "Exploit iam:CreatePolicyVersion to overwrite an existing managed policy with a more permissive version, granting admin access.",
    severity: "Critical",
    category: "iam-abuse",
    tags: ["AWS", "IAM", "Policy", "Privilege Escalation"],
    difficulty: "Advanced",
    provider: "AWS",
    steps: [
      "Identify a managed policy attached to your user or role",
      "Create a new policy version with elevated permissions (e.g., *:*)",
      "Set the new version as the default",
      "Exercise the newly granted permissions",
    ],
    permissions: ["iam:CreatePolicyVersion"],
    detectionOpportunities: [
      "Monitor for CreatePolicyVersion API calls",
      "Alert when a policy version grants Action: * or Resource: *",
      "Track policy version changes on sensitive policies",
    ],
    mitigations: [
      "Restrict iam:CreatePolicyVersion to trusted administrators",
      "Use SCPs to prevent policy modification",
      "Enable AWS Config rules for policy compliance",
    ],
    relatedDetectionIds: ["det-004"],
  },
  {
    slug: "iam-privilege-escalation",
    title: "IAM Privilege Escalation",
    overview: "Chain IAM misconfigurations to escalate from a low-privilege user to administrator access.",
    severity: "Critical",
    category: "privilege-escalation",
    tags: ["AWS", "IAM", "Privilege Escalation", "Misconfiguration"],
    difficulty: "Intermediate",
    provider: "AWS",
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
    relatedDetectionIds: ["det-001", "det-004"],
  },
  {
    slug: "lambda-privilege-escalation",
    title: "Lambda Privilege Escalation",
    overview: "Use Lambda function creation combined with PassRole to execute code with elevated IAM permissions.",
    severity: "High",
    category: "privilege-escalation",
    tags: ["AWS", "Lambda", "Privilege Escalation", "Serverless"],
    difficulty: "Intermediate",
    provider: "AWS",
    steps: [
      "Identify a high-privilege execution role for Lambda",
      "Create a Lambda function and pass the high-privilege role",
      "Deploy code that performs privileged actions",
      "Invoke the function to execute with escalated permissions",
    ],
    permissions: ["lambda:CreateFunction", "iam:PassRole", "lambda:InvokeFunction"],
    detectionOpportunities: [
      "Alert on Lambda function creation with administrative roles",
      "Monitor for PassRole to Lambda service principal",
      "Track Lambda invocations making privileged API calls",
    ],
    mitigations: [
      "Restrict Lambda execution roles via permission boundaries",
      "Limit PassRole to specific Lambda role ARNs",
      "Audit Lambda functions and their associated roles",
    ],
    relatedDetectionIds: ["det-001", "det-005"],
  },
  {
    slug: "ec2-metadata-abuse",
    title: "EC2 Metadata Abuse",
    overview: "Access the EC2 instance metadata service (IMDS) to steal IAM role credentials attached to the instance.",
    severity: "High",
    category: "privilege-escalation",
    tags: ["AWS", "EC2", "IMDS", "Credential Theft"],
    difficulty: "Beginner",
    provider: "AWS",
    steps: [
      "Gain code execution on an EC2 instance (e.g., via SSRF or RCE)",
      "Query the instance metadata service at 169.254.169.254",
      "Retrieve temporary IAM credentials from the metadata endpoint",
      "Use credentials to make authenticated AWS API calls",
    ],
    permissions: [],
    detectionOpportunities: [
      "Monitor for IMDSv1 usage and enforce IMDSv2",
      "Track credential usage from unexpected source IPs",
      "Alert on API calls from EC2 instances to unusual services",
    ],
    mitigations: [
      "Enforce IMDSv2 (require token-based access)",
      "Apply least-privilege IAM roles to EC2 instances",
      "Use VPC endpoints to restrict metadata access",
    ],
    relatedDetectionIds: [],
  },
  {
    slug: "lambda-persistence",
    title: "Lambda Persistence",
    overview: "Establish persistent access by deploying backdoor Lambda functions triggered by CloudWatch events or S3 uploads.",
    severity: "High",
    category: "persistence",
    tags: ["AWS", "Lambda", "Persistence", "Serverless", "Backdoor"],
    difficulty: "Advanced",
    provider: "AWS",
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
    relatedDetectionIds: ["det-005"],
  },
  {
    slug: "iam-backdoor-policies",
    title: "IAM Backdoor Policies",
    overview: "Create hidden IAM users, access keys, or inline policies that provide persistent access even after the original compromise is remediated.",
    severity: "Critical",
    category: "persistence",
    tags: ["AWS", "IAM", "Persistence", "Backdoor", "Access Keys"],
    difficulty: "Intermediate",
    provider: "AWS",
    steps: [
      "Create a new IAM user with a non-obvious name",
      "Attach an administrative inline policy",
      "Generate access keys for programmatic access",
      "Store credentials externally for persistent re-entry",
    ],
    permissions: ["iam:CreateUser", "iam:PutUserPolicy", "iam:CreateAccessKey"],
    detectionOpportunities: [
      "Monitor for new IAM user creation",
      "Alert on inline policy attachments",
      "Track access key creation events",
    ],
    mitigations: [
      "Use SCPs to restrict IAM user creation",
      "Audit IAM users and access keys regularly",
      "Implement alerting on any IAM changes",
    ],
    relatedDetectionIds: ["det-004"],
  },
  {
    slug: "s3-data-exfiltration",
    title: "S3 Data Exfiltration",
    overview: "Exfiltrate sensitive data from S3 buckets using compromised credentials, cross-account replication, or pre-signed URLs.",
    severity: "High",
    category: "data-exfiltration",
    tags: ["AWS", "S3", "Data Exfiltration", "Cloud Storage"],
    difficulty: "Beginner",
    provider: "AWS",
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
    relatedDetectionIds: ["det-003"],
  },
];

export const attackPathCategories = {
  "iam-abuse": { label: "IAM Abuse", description: "Abuse of identity and access management" },
  "privilege-escalation": { label: "Privilege Escalation", description: "Techniques to gain higher privileges" },
  "persistence": { label: "Persistence", description: "Techniques to maintain long-term access" },
  "lateral-movement": { label: "Lateral Movement", description: "Moving across cloud accounts and services" },
  "data-exfiltration": { label: "Data Exfiltration", description: "Stealing data from cloud resources" },
} as const;
