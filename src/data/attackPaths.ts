// Attack Paths — chains of reusable technique nodes.
// Each attack path represents a realistic attacker progression through AWS services.

import type { TechniqueCategory } from "./techniques";

export interface AttackPathStep {
  techniqueId: string;
  /** Optional context describing how this technique is used in this specific chain */
  context?: string;
}

export type AttackObjective = "credential-access" | "privilege-escalation" | "persistence" | "lateral-movement" | "exfiltration" | "initial-access" | "defense-evasion";

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
  "initial-access": "Initial Access",
  "defense-evasion": "Defense Evasion",
};

export const attackPaths: AttackPath[] = [
  {
    slug: "ec2-imds-to-s3-exfiltration",
    title: "EC2 IMDS to S3 Exfiltration",
    description:
      "This attack chain begins when an attacker achieves code execution on an EC2 instance, either through a compromised application, RCE vulnerability, or stolen SSH keys. Once on the instance, the attacker queries the Instance Metadata Service at 169.254.169.254 to retrieve the IAM role credentials attached to the instance. These temporary credentials are then used to assume a cross-account role that has S3 access, or to directly access S3 buckets if the instance role already has permissions. The attacker downloads sensitive objects from target buckets to complete the exfiltration. This path requires no prior AWS credentials; the attacker only needs a foothold on the instance.",
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
      "An attacker who has iam:PassRole and lambda:CreateFunction can escalate to full administrative access. The attacker creates a new Lambda function and passes a high-privilege IAM role (e.g., one with AdministratorAccess) as the execution role. The Lambda code is written to create a backdoor IAM user and attach administrative policies, then generate access keys for that user. When the attacker invokes the Lambda, it runs with the passed role's permissions and performs these actions. The attacker then uses the newly created access keys for persistent access. This chain exploits the fact that PassRole allows assigning any role the attacker has permission to pass, and Lambda execution inherits that role's full permissions.",
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
      "This path exploits iam:CreatePolicyVersion on a managed policy that the attacker is already attached to. The attacker creates a new policy version with a document that grants Action: * and Resource: *, then sets it as the default version. Because the attacker is attached to this policy, the new permissions take effect immediately without any additional API calls. The attacker then uses the escalated permissions to assume cross-account roles or perform other privileged actions across the organization. The key requirement is that the attacker must have CreatePolicyVersion on a policy they are attached to.",
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
      "The attacker establishes persistent access by deploying a backdoor Lambda function with a privileged execution role. The Lambda code is designed to execute on every invocation (e.g., creating backdoor users or exfiltrating data). The attacker then configures EventBridge rules or S3 event notifications to trigger the Lambda automatically on a schedule or when specific events occur. Finally, the attacker disables or modifies CloudTrail to reduce the likelihood of detection. This creates a self-sustaining backdoor that continues to run even after the initial compromise is remediated.",
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
      "After gaining IAM privileges, the attacker creates a hidden backdoor user with a low-profile name and attaches an administrative inline policy. Access keys are generated for this user to enable persistent programmatic access. The attacker then modifies S3 bucket policies on target buckets to add their external account as an allowed principal, or to grant the backdoor user explicit access. Using the backdoor credentials, the attacker downloads sensitive data from the buckets. This path ensures access survives key rotation of the original compromised credentials.",
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
      "The attacker gains access to an EC2 instance (e.g., via compromised application or SSH) and retrieves the instance role credentials from the Instance Metadata Service. If the instance role has iam:PassRole and lambda:CreateFunction, the attacker can escalate by creating a Lambda function with a higher-privilege role. The Lambda is invoked with code that uses the escalated role to access S3 or other resources. The attacker exfiltrates data using the Lambda's permissions. This path demonstrates lateral movement from a low-privilege instance to broader data access through service chaining.",
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
    description:
      "This critical path requires no prior AWS credentials. The attacker finds a web application that is vulnerable to Server-Side Request Forgery (SSRF) and runs on EC2. By injecting a URL pointing to the Instance Metadata Service (e.g., http://169.254.169.254/latest/meta-data/iam/security-credentials/), the attacker causes the server to fetch its own IAM role credentials and return them in the response. With these credentials, the attacker accesses S3 buckets that the instance role can read and exfiltrates sensitive data. This is a common scenario in CloudGoat and similar cloud security labs.",
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
    description:
      "An attacker with iam:UpdateAssumeRolePolicy modifies a role's trust policy to add their own principal (e.g., the root of an attacker-controlled AWS account) as a trusted entity. Once the trust policy is updated, the attacker can assume the role from their account at any time using sts:AssumeRole. This creates a persistent backdoor that survives key rotation or remediation of the original compromise. The attacker maintains long-term cross-account access through the backdoored role.",
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
    description:
      "IAM roles can trust external OIDC identity providers such as GitHub or GitLab. If the trust policy is misconfigured (e.g., uses a wildcard or overly broad subject claim), an attacker can satisfy the trust conditions from an attacker-controlled repository or identity. The attacker forks a target repository, configures GitHub Actions to request OIDC tokens, and uses those tokens to assume the role via the AWS STS assume-role-with-web-identity API. This provides initial access without any stolen credentials or prior AWS access.",
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
    description:
      "When a CloudFront distribution uses an S3 bucket as its origin and that bucket is later deleted, the distribution becomes orphaned. The origin domain (e.g., bucket-name.s3.amazonaws.com) may still resolve to the S3 namespace. An attacker can create a new S3 bucket with the same name as the deleted bucket. CloudFront will then serve content from the attacker's bucket, allowing the attacker to serve malicious content to users visiting the distribution URL. This provides initial access or enables phishing and malware distribution through a trusted domain.",
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
    description:
      "Elastic Beanstalk environment configurations often store IAM credentials or references to Parameter Store secrets. An attacker with elasticbeanstalk:DescribeConfigurationSettings can retrieve these environment variables. If the instance profile or referenced credentials have iam:CreateAccessKey, the attacker uses the stolen credentials to create long-lived access keys for themselves or a backdoor user. This pivots from read-only environment access to persistent administrative access.",
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
    description:
      "A Lambda function vulnerable to SSRF can be exploited to reach the Instance Metadata Service. Lambda runs on EC2-like infrastructure and has access to IMDS. By triggering the Lambda with a malicious input that causes an outbound request to 169.254.169.254, the attacker retrieves the Lambda's execution role credentials. With those credentials, the attacker accesses S3 buckets and other resources that the Lambda role can access, enabling data exfiltration.",
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
    description:
      "The attacker uses iam:PassRole and lambda:CreateFunction to deploy a Lambda with an administrative role. The Lambda code performs malicious actions (e.g., creating backdoor users). The attacker then uses events:PutRule and events:PutTargets to create an EventBridge rule that invokes the Lambda on a schedule (e.g., every 5 minutes). The Lambda runs automatically without further attacker interaction, establishing persistence. Each execution can reinforce backdoor access or exfiltrate data.",
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
    description:
      "CodeBuild projects can have environment variables that contain credentials or reference Parameter Store secrets. An attacker who can trigger a build (or modify the build spec) injects code that exfiltrates these credentials during the build. The build runs with the CodeBuild service role, which may have iam:CreateAccessKey or other privileged permissions. The attacker uses the stolen credentials to create access keys or assume higher-privilege roles, completing the escalation.",
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
    description:
      "ECS tasks receive IAM credentials via the task role, which are available inside the container through the metadata endpoint or environment variables. An attacker with code execution in a container (e.g., via a vulnerable application) can retrieve these credentials. If the task role has sts:AssumeRole or iam:CreateAccessKey, the attacker uses the stolen credentials to assume higher-privilege roles or create persistent access keys, escalating from the task's permissions to broader account access.",
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
    description:
      "An attacker with ec2:DescribeInstanceAttribute can retrieve the user data of an EC2 instance, which may contain embedded secrets, database connection strings, or bootstrap scripts. If the attacker also has access to the instance (e.g., the user data revealed SSH keys or the instance is in a shared environment), they can log in and query the Instance Metadata Service to steal the instance role credentials. This combines reconnaissance (user data disclosure) with credential theft (IMDS access).",
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
    description:
      "An attacker with ec2:ModifyInstanceAttribute can change the user data of a running instance. User data is executed when the instance boots. By injecting a malicious script (e.g., one that creates a backdoor user or installs a reverse shell), the attacker ensures the script runs on the next instance restart or when a new instance is launched from an AMI that includes the modified user data. This establishes persistence that survives instance replacement.",
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
    description:
      "SSM Session Manager access can be restricted via resource tags (e.g., only principals with a specific tag can start sessions on instances with a matching tag). An attacker with ec2:CreateTags or ssm:AddTagsToResource can add the required tags to target instances, satisfying the session policy. The attacker then uses ssm:StartSession to gain interactive shell access to the instances without SSH keys or open port 22. This bypasses tag-based access controls for lateral movement.",
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
    description:
      "An attacker with ec2:CreateSnapshot and ec2:ModifySnapshotAttribute creates a snapshot of an EC2 instance's root or data volume. The snapshot is shared with the attacker's account (or made temporarily public), then copied and attached as a volume to an attacker-controlled instance. The attacker mounts the volume and extracts credentials from the filesystem (e.g., ~/.aws/credentials, application config files) or other sensitive data. Unencrypted volumes are especially vulnerable.",
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
    description:
      "S3 buckets and Lambda functions can have resource-based policies that grant access to principals. Misconfigurations such as Principal: * or overly broad account/role allowlists enable unauthenticated or weakly authenticated access. An attacker discovers these misconfigured resources (e.g., through enumeration or public disclosure) and accesses them without prior AWS credentials. This provides initial access to read S3 objects, invoke Lambda functions, or trigger other actions depending on the policy.",
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
    description:
      "When a Cognito User Pool has self-signup enabled without proper restrictions, anyone can create an account. An attacker registers with a valid email (or uses a disposable email) and gains access to the application protected by the User Pool. Depending on the application's authorization logic, the attacker may access resources intended only for legitimate users. This is a common misconfiguration that provides initial access to applications using Cognito for authentication.",
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
    description:
      "Cognito Identity Pools can be configured to allow unauthenticated access, granting temporary AWS credentials to anyone who requests them. The credentials are scoped to an IAM role. If that role is overprivileged (e.g., has S3 read access to sensitive buckets), an attacker can obtain credentials without authentication and use them to access resources. The attacker calls GetCredentialsForIdentity (or the equivalent in the SDK) and receives temporary keys with the role's permissions.",
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
    description:
      "Bedrock agents use Lambda functions to execute custom logic. An attacker with bedrock:UpdateAgent and lambda:UpdateFunctionCode can modify the agent's Lambda to run attacker-controlled code. When the agent is invoked (e.g., via the Bedrock API or an application using the agent), the malicious Lambda executes with the agent's IAM role permissions. This hijacks the agent's behavior for privilege escalation or data exfiltration while appearing to be legitimate agent usage.",
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
    description:
      "An attacker with iam:PassRole and ec2:RunInstances launches a new EC2 instance with an IAM instance profile that has high privileges. The attacker specifies an AMI they control or a standard Amazon Linux AMI. Once the instance is running, the attacker accesses it (e.g., via SSM if they have StartSession, or by pre-configuring user data to exfiltrate credentials). The attacker queries the Instance Metadata Service to retrieve the instance role credentials, gaining the privileged role's permissions.",
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
    description:
      "An attacker with iam:PassRole and ecs:RunTask runs an ECS task with a privileged task role. The task uses a container image that the attacker controls (or one that allows credential extraction). When the task runs, it receives the task role's credentials via the container metadata endpoint. The attacker's code in the container exfiltrates these credentials (e.g., by sending them to an external server or writing to an S3 bucket the attacker controls). The attacker then uses the credentials for privilege escalation.",
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
    description:
      "An attacker with iam:PassRole and glue:CreateDevEndpoint creates a Glue development endpoint with a high-privilege role. The endpoint is an EC2 instance that runs the Glue environment. The attacker uses glue:UpdateDevEndpoint to add their SSH public key to the endpoint. They then SSH into the endpoint and query the Instance Metadata Service to retrieve the endpoint's IAM role credentials. This provides the attacker with the privileged role's permissions for escalation.",
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
    description:
      "An attacker with sts:GetFederationToken can create federation tokens that are tied to the attacker's identity but have a configurable policy. Unlike AssumeRole, federation tokens are not revoked when the original access key is deleted or rotated. The attacker creates a federation token with broad permissions before their access key is rotated. They store the token credentials and use them for persistent access even after the organization believes they have removed the attacker's access by deleting keys.",
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
    description:
      "An attacker creates a CodeBuild project configured to act as a GitHub Actions runner. When the organization's GitHub repository runs workflows, the CodeBuild project executes the workflow jobs. The attacker modifies the workflow (if they have repo access) or creates a malicious workflow that exfiltrates credentials or performs other malicious actions. The CodeBuild service role's credentials are available during the build. This establishes persistence through the CI/CD pipeline.",
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
    description:
      "An attacker with iam:CreateOpenIDConnectProvider creates an OIDC identity provider that points to an attacker-controlled URL (e.g., a server that issues OIDC tokens). The attacker then modifies role trust policies (if they have UpdateAssumeRolePolicy) to trust this provider. From their IdP, the attacker issues tokens that satisfy the trust policy and assumes the role via sts:AssumeRoleWithWebIdentity. This creates persistence through a trusted identity source that the organization may not immediately recognize as malicious.",
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
    description:
      "IAM Roles Anywhere allows workloads outside of AWS (e.g., on-premises servers) to obtain temporary credentials using X.509 certificates. An attacker with rolesanywhere:CreateTrustAnchor and rolesanywhere:CreateProfile creates a trust anchor that trusts a certificate authority the attacker controls. They create a profile that maps the certificate to a privileged IAM role. The attacker then uses a certificate from their CA to assume the role from any infrastructure, establishing persistence that does not rely on IAM users or access keys.",
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
    description:
      "An attacker with GuardDuty management permissions performs a series of actions to evade detection. They use guardduty:UpdateDetector to disable the detector or reduce its sensitivity. They add attacker IPs to trusted IP lists via guardduty:CreateIPSet and guardduty:UpdateIPSet so that activity from those IPs does not generate findings. They create or update filters via guardduty:CreateFilter and guardduty:UpdateFilter to suppress specific finding types. This chain blinds security monitoring to the attacker's subsequent activities.",
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
    description:
      "An attacker with CloudTrail and S3 permissions performs multiple actions to reduce audit visibility. They use cloudtrail:UpdateTrail to change the trail configuration (e.g., disable logging or point to a different bucket). They use cloudtrail:PutEventSelectors to exclude data events or management events from being logged. They use s3:PutBucketLifecycleConfiguration on the CloudTrail bucket to add a lifecycle rule that deletes or transitions objects quickly, reducing the retention of existing logs. This chain degrades or eliminates audit trail coverage.",
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
