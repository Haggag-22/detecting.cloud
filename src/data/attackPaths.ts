// Attack Paths — chains of reusable technique nodes.
// Each attack path represents a realistic attacker progression through AWS services.

import type { TechniqueCategory } from "./techniques";

export interface AttackPathStep {
  techniqueId: string;
  /** Optional context describing how this technique is used in this specific chain */
  context?: string;
}

export type AttackObjective = "credential-access" | "privilege-escalation" | "persistence" | "lateral-movement" | "exfiltration";

export interface AttackPath {
  slug: string;
  title: string;
  description: string;
  severity: "Critical" | "High" | "Medium";
  /** Primary attacker objective — determines the color accent */
  objective: AttackObjective;
  tags: string[];
  /** Ordered chain of technique steps */
  steps: AttackPathStep[];
  /** Attribution to sources (Hacking the Cloud, CloudGoat, etc.) */
  references?: Array<{ source: string; url?: string }>;
}

export const attackObjectiveLabels: Record<AttackObjective, string> = {
  "credential-access": "Credential Access",
  "privilege-escalation": "Privilege Escalation",
  "persistence": "Persistence",
  "lateral-movement": "Lateral Movement",
  "exfiltration": "Data Exfiltration",
};

export const attackPaths: AttackPath[] = [
  {
    slug: "ec2-imds-to-s3-exfiltration",
    title: "EC2 IMDS to S3 Exfiltration",
    description:
      "An attacker gains code execution on an EC2 instance, steals IAM credentials via the Instance Metadata Service, assumes a cross-account role, and exfiltrates sensitive data from S3.",
    severity: "Critical",
    objective: "exfiltration",
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
    objective: "privilege-escalation",
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
    objective: "privilege-escalation",
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
    objective: "persistence",
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
    objective: "exfiltration",
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
    objective: "lateral-movement",
    tags: ["EC2", "IAM", "Lambda", "S3", "Lateral Movement"],
    steps: [
      { techniqueId: "tech-imds-credential-theft", context: "Steal IAM credentials from the compromised EC2 instance" },
      { techniqueId: "tech-passrole-abuse", context: "Use stolen credentials to pass a higher-privilege role" },
      { techniqueId: "tech-lambda-code-execution", context: "Execute code via Lambda with the escalated role" },
      { techniqueId: "tech-s3-data-download", context: "Use Lambda's permissions to exfiltrate S3 data" },
    ],
  },
  // ─── Phase 2: Atlas attack paths (25 additions) ───
  {
    slug: "external-imds-ssrf-to-s3",
    title: "External IMDS SSRF to S3",
    description: "Exploit SSRF in a publicly accessible web app to reach EC2 IMDS, steal instance role credentials with no prior AWS access, and exfiltrate S3 data.",
    severity: "Critical",
    objective: "credential-access",
    tags: ["EC2", "IMDS", "SSRF", "S3", "CloudGoat"],
    steps: [
      { techniqueId: "tech-external-imds-ssrf", context: "Use SSRF to query IMDS and obtain instance role credentials" },
      { techniqueId: "tech-s3-data-download", context: "Use stolen credentials to access and exfiltrate S3 buckets" },
    ],
    references: [
      { source: "CloudGoat", url: "https://github.com/RhinoSecurityLabs/cloudgoat/blob/master/cloudgoat/scenarios/aws/cloud_breach_s3.md" },
      { source: "Hacking the Cloud", url: "https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/" },
    ],
  },
  {
    slug: "trust-backdoor-persistence",
    title: "Trust Policy Backdoor Persistence",
    description: "Modify IAM role trust policies to add attacker principals (e.g., external account root) for persistent cross-account access.",
    severity: "Critical",
    objective: "persistence",
    tags: ["IAM", "Trust Policy", "Persistence", "Cross-Account"],
    steps: [
      { techniqueId: "tech-trust-policy-modification", context: "Add attacker account root to role trust policy" },
      { techniqueId: "tech-assumerole-abuse", context: "Assume the backdoored role from attacker account" },
    ],
  },
  {
    slug: "oidc-misconfig-initial-access",
    title: "OIDC Trust Misconfiguration Initial Access",
    description: "Exploit overly permissive OIDC trust policies (e.g., GitHub, GitLab) to assume roles from attacker-controlled repositories.",
    severity: "Critical",
    objective: "initial-access",
    tags: ["IAM", "OIDC", "GitHub", "Initial Access"],
    steps: [
      { techniqueId: "tech-oidc-trust-misconfig", context: "Fork repo or use attacker-controlled IdP to satisfy trust policy" },
      { techniqueId: "tech-assumerole-abuse", context: "Assume role via OIDC federation" },
    ],
  },
  {
    slug: "cloudfront-takeover-initial-access",
    title: "CloudFront Orphaned Origin Takeover",
    description: "Take over orphaned CloudFront origins (e.g., deleted S3 buckets) by creating a bucket with the same name to serve malicious content.",
    severity: "Critical",
    objective: "initial-access",
    tags: ["CloudFront", "S3", "Origin Takeover", "Initial Access"],
    steps: [
      { techniqueId: "tech-cloudfront-origin-takeover", context: "Create S3 bucket matching orphaned origin domain" },
    ],
  },
  {
    slug: "beanstalk-secrets-to-admin",
    title: "Beanstalk Secrets to Admin",
    description: "Extract credentials from Elastic Beanstalk environment configuration and use them to create access keys for admin persistence.",
    severity: "High",
    objective: "privilege-escalation",
    tags: ["Elastic Beanstalk", "IAM", "Credential Theft"],
    steps: [
      { techniqueId: "tech-beanstalk-env-theft", context: "Retrieve env vars containing IAM credentials" },
      { techniqueId: "tech-beanstalk-credential-pivot", context: "Use CreateAccessKey to generate persistent keys" },
    ],
  },
  {
    slug: "lambda-cred-theft-to-s3",
    title: "Lambda Credential Theft to S3",
    description: "Exploit SSRF in a Lambda function to steal execution role credentials via IMDS, then exfiltrate S3 data.",
    severity: "High",
    objective: "credential-access",
    tags: ["Lambda", "SSRF", "IMDS", "S3"],
    steps: [
      { techniqueId: "tech-lambda-credential-theft", context: "Use Lambda SSRF to reach IMDS and steal role credentials" },
      { techniqueId: "tech-s3-data-download", context: "Exfiltrate S3 data with stolen credentials" },
    ],
  },
  {
    slug: "eventbridge-persistence-chain",
    title: "EventBridge Persistence Chain",
    description: "Pass a privileged role to Lambda, deploy backdoor code, and configure EventBridge rules for scheduled persistence.",
    severity: "High",
    objective: "persistence",
    tags: ["Lambda", "EventBridge", "PassRole", "Persistence"],
    steps: [
      { techniqueId: "tech-passrole-abuse", context: "Pass admin role to Lambda function" },
      { techniqueId: "tech-lambda-code-execution", context: "Deploy backdoor Lambda code" },
      { techniqueId: "tech-eventbridge-rule-persistence", context: "Create EventBridge rule to trigger Lambda on schedule" },
    ],
  },
  {
    slug: "codebuild-env-to-privesc",
    title: "CodeBuild Environment to Privilege Escalation",
    description: "Extract credentials from CodeBuild environment variables during build, then pivot to create access keys or assume roles.",
    severity: "High",
    objective: "privilege-escalation",
    tags: ["CodeBuild", "Credential Theft", "Privilege Escalation"],
    steps: [
      { techniqueId: "tech-codebuild-env-theft", context: "Extract credentials from build environment" },
      { techniqueId: "tech-access-key-creation", context: "Create access keys with stolen permissions" },
    ],
  },
  {
    slug: "ecs-task-cred-theft-chain",
    title: "ECS Task Credential Theft Chain",
    description: "Extract IAM credentials from ECS task role, then assume roles or create access keys for escalation.",
    severity: "High",
    objective: "credential-access",
    tags: ["ECS", "IAM", "Credential Theft"],
    steps: [
      { techniqueId: "tech-ecs-task-credential-theft", context: "Extract task role credentials from container" },
      { techniqueId: "tech-assumerole-abuse", context: "Assume higher-privilege roles with stolen creds" },
    ],
  },
  {
    slug: "ec2-userdata-to-imds",
    title: "EC2 User Data to IMDS",
    description: "Retrieve EC2 user data to find secrets or bootstrap info, then use instance access to steal IMDS credentials.",
    severity: "High",
    objective: "credential-access",
    tags: ["EC2", "User Data", "IMDS"],
    steps: [
      { techniqueId: "tech-ec2-userdata-disclosure", context: "Retrieve user data via DescribeInstanceAttribute" },
      { techniqueId: "tech-imds-credential-theft", context: "Access IMDS from instance to steal role credentials" },
    ],
  },
  {
    slug: "ec2-userdata-injection-persistence",
    title: "EC2 User Data Injection Persistence",
    description: "Modify EC2 instance user data to inject malicious bootstrap scripts for persistence across instance restarts.",
    severity: "High",
    objective: "persistence",
    tags: ["EC2", "User Data", "Persistence"],
    steps: [
      { techniqueId: "tech-ec2-userdata-injection", context: "Inject backdoor script into instance user data" },
    ],
  },
  {
    slug: "ssm-via-tags-lateral-movement",
    title: "SSM Access via CreateTags Lateral Movement",
    description: "Bypass SSM resource-based access by adding attacker tags to instances, then use StartSession for lateral movement.",
    severity: "High",
    objective: "lateral-movement",
    tags: ["SSM", "EC2", "CreateTags", "Lateral Movement"],
    steps: [
      { techniqueId: "tech-ssm-via-tags", context: "Add tags to instance to satisfy SSM session policy" },
      { techniqueId: "tech-ssm-session", context: "Start SSM session for interactive access" },
    ],
  },
  {
    slug: "volume-snapshot-credential-loot",
    title: "Volume Snapshot Credential Loot",
    description: "Create snapshot of EC2 volume, copy to attacker account, mount, and extract credentials or sensitive data.",
    severity: "High",
    objective: "credential-access",
    tags: ["EC2", "Snapshot", "Credential Access"],
    steps: [
      { techniqueId: "tech-volume-snapshot-loot", context: "Snapshot volume, copy, mount, and extract credentials" },
    ],
  },
  {
    slug: "resource-policy-initial-access",
    title: "Resource Policy Initial Access",
    description: "Exploit resource policies with Principal * or overly permissive principals to access S3 or Lambda without prior credentials.",
    severity: "High",
    objective: "initial-access",
    tags: ["S3", "Lambda", "Resource Policy", "Misconfiguration"],
    steps: [
      { techniqueId: "tech-resource-policy-misconfig", context: "Access S3 or Lambda via misconfigured resource policy" },
    ],
  },
  {
    slug: "cognito-self-signup-access",
    title: "Cognito Self-Signup Access",
    description: "Exploit open Cognito User Pool self-signup to create attacker accounts and gain application access.",
    severity: "High",
    objective: "initial-access",
    tags: ["Cognito", "Self-Signup", "Initial Access"],
    steps: [
      { techniqueId: "tech-cognito-self-signup", context: "Create account via self-signup" },
    ],
  },
  {
    slug: "cognito-identity-pool-privesc",
    title: "Cognito Identity Pool Privilege Escalation",
    description: "Obtain temporary credentials from Cognito Identity Pool with unauthenticated access, then use overprivileged role.",
    severity: "High",
    objective: "privilege-escalation",
    tags: ["Cognito", "Identity Pool", "Privilege Escalation"],
    steps: [
      { techniqueId: "tech-cognito-identity-pool-creds", context: "Get credentials from identity pool" },
      { techniqueId: "tech-s3-data-download", context: "Use overprivileged role to access S3" },
    ],
  },
  {
    slug: "bedrock-agent-hijacking",
    title: "Bedrock Agent Hijacking",
    description: "Modify Bedrock agent configuration (Lambda function) to hijack agent and invoke with elevated permissions.",
    severity: "High",
    objective: "privilege-escalation",
    tags: ["Bedrock", "Lambda", "Agent Hijacking"],
    steps: [
      { techniqueId: "tech-bedrock-agent-hijacking", context: "Update agent Lambda to execute attacker code" },
    ],
  },
  {
    slug: "passrole-ec2-escalation",
    title: "PassRole EC2 Escalation",
    description: "Exploit PassRole with RunInstances to launch EC2 with privileged role, then steal credentials via IMDS.",
    severity: "High",
    objective: "privilege-escalation",
    tags: ["IAM", "EC2", "PassRole", "IMDS"],
    steps: [
      { techniqueId: "tech-passrole-ec2", context: "Launch EC2 with privileged role via PassRole" },
      { techniqueId: "tech-imds-credential-theft", context: "Steal role credentials from instance IMDS" },
    ],
  },
  {
    slug: "passrole-ecs-escalation",
    title: "PassRole ECS Escalation",
    description: "Exploit PassRole with RunTask to run ECS task with privileged role, then extract credentials from task.",
    severity: "High",
    objective: "privilege-escalation",
    tags: ["IAM", "ECS", "PassRole"],
    steps: [
      { techniqueId: "tech-passrole-ecs", context: "Run ECS task with privileged role" },
      { techniqueId: "tech-ecs-task-credential-theft", context: "Extract task role credentials" },
    ],
  },
  {
    slug: "passrole-glue-escalation",
    title: "PassRole Glue Escalation",
    description: "Exploit PassRole with CreateDevEndpoint to create Glue dev endpoint with privileged role, extract credentials via SSH.",
    severity: "High",
    objective: "privilege-escalation",
    tags: ["IAM", "Glue", "PassRole"],
    steps: [
      { techniqueId: "tech-passrole-glue", context: "Create Glue dev endpoint with privileged role" },
      { techniqueId: "tech-glue-dev-endpoint-update", context: "Update SSH key and extract credentials" },
    ],
  },
  {
    slug: "get-federation-token-persistence",
    title: "GetFederationToken Persistence",
    description: "Create federation tokens that survive access key deletion, providing persistent access after key rotation.",
    severity: "High",
    objective: "persistence",
    tags: ["STS", "Federation Token", "Persistence"],
    steps: [
      { techniqueId: "tech-get-federation-token", context: "Create federation token before key deletion" },
    ],
  },
  {
    slug: "codebuild-github-runner-persistence",
    title: "CodeBuild GitHub Runner Persistence",
    description: "Create CodeBuild project as GitHub Actions runner for persistent code execution and credential theft.",
    severity: "High",
    objective: "persistence",
    tags: ["CodeBuild", "GitHub", "Persistence"],
    steps: [
      { techniqueId: "tech-codebuild-github-runner", context: "Create CodeBuild project as GitHub runner" },
    ],
  },
  {
    slug: "rogue-oidc-persistence",
    title: "Rogue OIDC Persistence",
    description: "Create rogue OIDC identity provider and use it in trust policies to assume roles from attacker-controlled identity sources.",
    severity: "High",
    objective: "persistence",
    tags: ["IAM", "OIDC", "Persistence"],
    steps: [
      { techniqueId: "tech-rogue-oidc-provider", context: "Create OIDC provider pointing to attacker IdP" },
      { techniqueId: "tech-assumerole-abuse", context: "Assume roles via rogue IdP" },
    ],
  },
  {
    slug: "roles-anywhere-persistence",
    title: "Roles Anywhere Persistence",
    description: "Create IAM Roles Anywhere trust anchors and profiles to enable certificate-based access from attacker infrastructure.",
    severity: "High",
    objective: "persistence",
    tags: ["IAM", "Roles Anywhere", "Persistence"],
    steps: [
      { techniqueId: "tech-roles-anywhere-persistence", context: "Create trust anchor and profile" },
    ],
  },
  {
    slug: "guardduty-evasion-chain",
    title: "GuardDuty Evasion Chain",
    description: "Modify or disable GuardDuty detectors, add trusted IPs, and suppress findings to evade detection.",
    severity: "High",
    objective: "defense-evasion",
    tags: ["GuardDuty", "Defense Evasion"],
    steps: [
      { techniqueId: "tech-guardduty-detector-evasion", context: "Modify or disable detector" },
      { techniqueId: "tech-guardduty-ip-trust-evasion", context: "Add attacker IPs to trusted list" },
      { techniqueId: "tech-guardduty-suppression", context: "Create filters to suppress findings" },
    ],
  },
  {
    slug: "cloudtrail-evasion-chain",
    title: "CloudTrail Evasion Chain",
    description: "Update CloudTrail configuration, modify event selectors, or alter bucket lifecycle to reduce or eliminate audit logging.",
    severity: "High",
    objective: "defense-evasion",
    tags: ["CloudTrail", "Defense Evasion"],
    steps: [
      { techniqueId: "tech-cloudtrail-config-update", context: "Update trail configuration" },
      { techniqueId: "tech-cloudtrail-event-selectors", context: "Modify event selectors to exclude events" },
      { techniqueId: "tech-cloudtrail-bucket-lifecycle", context: "Modify bucket lifecycle to delete logs" },
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
