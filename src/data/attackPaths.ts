// Attack Paths — chains of reusable technique nodes.
// Each attack path represents a realistic attacker progression through AWS services.

export interface AttackPathStep {
  techniqueId: string;
  /** Optional context describing how this technique is used in this specific chain */
  context?: string;
}

export interface AttackPath {
  slug: string;
  title: string;
  description: string;
  severity: "Critical" | "High" | "Medium";
  tags: string[];
  /** Ordered chain of technique steps */
  steps: AttackPathStep[];
}

export const attackPaths: AttackPath[] = [
  {
    slug: "ec2-imds-to-s3-exfiltration",
    title: "EC2 IMDS to S3 Exfiltration",
    description:
      "An attacker gains code execution on an EC2 instance, steals IAM credentials via the Instance Metadata Service, assumes a cross-account role, and exfiltrates sensitive data from S3.",
    severity: "Critical",
    tags: ["EC2", "IAM", "STS", "S3", "IMDS", "Data Exfiltration"],
    steps: [
      { techniqueId: "tech-imds-credential-theft", context: "Gain initial credentials by querying the EC2 metadata endpoint" },
      { techniqueId: "tech-assumerole-abuse", context: "Use stolen credentials to assume a role with S3 access" },
      { techniqueId: "tech-s3-data-download", context: "Exfiltrate sensitive objects from target S3 buckets" },
    ],
  },
  {
    slug: "passrole-lambda-escalation",
    title: "PassRole Lambda Privilege Escalation",
    description:
      "An attacker with iam:PassRole and lambda:CreateFunction creates a Lambda function with an admin role, executes code to create backdoor credentials, and establishes persistent access.",
    severity: "Critical",
    tags: ["IAM", "Lambda", "PassRole", "Privilege Escalation", "Persistence"],
    steps: [
      { techniqueId: "tech-passrole-abuse", context: "Pass an administrative role to a new Lambda function" },
      { techniqueId: "tech-lambda-code-execution", context: "Deploy and invoke the Lambda function with admin privileges" },
      { techniqueId: "tech-iam-user-creation", context: "Create a backdoor IAM user with admin inline policy" },
      { techniqueId: "tech-access-key-creation", context: "Generate access keys for persistent programmatic access" },
    ],
  },
  {
    slug: "iam-policy-escalation-chain",
    title: "IAM Policy Escalation Chain",
    description:
      "An attacker exploits iam:CreatePolicyVersion to grant themselves admin access, then uses the elevated permissions to assume sensitive roles across the organization.",
    severity: "Critical",
    tags: ["IAM", "STS", "Policy", "Privilege Escalation", "Cross-Account"],
    steps: [
      { techniqueId: "tech-create-policy-version", context: "Create a new policy version with Action:* Resource:*" },
      { techniqueId: "tech-attach-user-policy", context: "Ensure the escalated policy is attached and set as default" },
      { techniqueId: "tech-assumerole-abuse", context: "Assume cross-account roles using newly granted permissions" },
    ],
  },
  {
    slug: "lambda-persistence-backdoor",
    title: "Lambda Persistence Backdoor",
    description:
      "An attacker creates a Lambda function with elevated permissions, configures automated triggers, and disables CloudTrail to cover their tracks.",
    severity: "High",
    tags: ["Lambda", "IAM", "CloudTrail", "Persistence", "Defense Evasion"],
    steps: [
      { techniqueId: "tech-passrole-abuse", context: "Pass a privileged role to the backdoor Lambda function" },
      { techniqueId: "tech-lambda-code-execution", context: "Deploy malicious code that executes on every trigger" },
      { techniqueId: "tech-lambda-event-trigger", context: "Configure CloudWatch Events or S3 triggers for automatic execution" },
      { techniqueId: "tech-cloudtrail-disable", context: "Disable CloudTrail logging to evade detection" },
    ],
  },
  {
    slug: "iam-backdoor-exfiltration",
    title: "IAM Backdoor & Data Exfiltration",
    description:
      "An attacker creates a backdoor IAM user, generates long-lived access keys, modifies S3 bucket policies to allow cross-account access, and exfiltrates data.",
    severity: "High",
    tags: ["IAM", "S3", "Persistence", "Data Exfiltration"],
    steps: [
      { techniqueId: "tech-iam-user-creation", context: "Create a hidden IAM user with administrative inline policy" },
      { techniqueId: "tech-access-key-creation", context: "Generate access keys for the backdoor user" },
      { techniqueId: "tech-s3-bucket-policy-mod", context: "Modify bucket policies to allow cross-account access" },
      { techniqueId: "tech-s3-data-download", context: "Download sensitive data using the backdoor credentials" },
    ],
  },
  {
    slug: "ec2-lateral-movement",
    title: "EC2 Lateral Movement & Escalation",
    description:
      "An attacker compromises an EC2 instance, steals IMDS credentials, escalates via PassRole to Lambda, and uses the Lambda role to exfiltrate data.",
    severity: "High",
    tags: ["EC2", "IAM", "Lambda", "S3", "Lateral Movement"],
    steps: [
      { techniqueId: "tech-imds-credential-theft", context: "Steal IAM credentials from the compromised EC2 instance" },
      { techniqueId: "tech-passrole-abuse", context: "Use stolen credentials to pass a higher-privilege role" },
      { techniqueId: "tech-lambda-code-execution", context: "Execute code via Lambda with the escalated role" },
      { techniqueId: "tech-s3-data-download", context: "Use Lambda's permissions to exfiltrate S3 data" },
    ],
  },
];

// ─── Lookup helpers ───

export function getAttackPathBySlug(slug: string): AttackPath | undefined {
  return attackPaths.find((ap) => ap.slug === slug);
}

/** Get all attack paths that include a given technique */
export function getAttackPathsForTechnique(techniqueId: string): AttackPath[] {
  return attackPaths.filter((ap) => ap.steps.some((s) => s.techniqueId === techniqueId));
}
