#!/usr/bin/env node
/**
 * Add the five Sigma rules that cover live techniques with no matching API today.
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const AWS = path.join(ROOT, "rules", "aws");

function writeJson(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + "\n");
}

function writeText(file, text) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text.replace(/\n$/, "") + "\n");
}

function writeLifecycle(dir, { title, behavior, eventSource, eventName, command }) {
  writeJson(path.join(dir, "lifecycle.json"), {
    whyItMatters: behavior,
    threatContext: {
      attackerBehavior: behavior,
      whyItMatters: `${title} is a high-signal control-plane action with no prior Sigma coverage in this catalog.`,
      riskAndImpact: "If missed, the technique node stays dark and the attacker action is invisible.",
    },
    telemetryValidation: {
      requiredLogSources: ["AWS CloudTrail management events"],
      requiredFields: ["eventSource", "eventName", "userIdentity.arn", "eventTime", "sourceIPAddress"],
      loggingRequirements: [`CloudTrail must log ${eventSource} ${eventName}.`],
      limitations: ["Management events only; data-plane follow-on is out of scope for this rule."],
    },
    enrichment: [
      {
        dimension: "Approved actor",
        description: "Compare the caller to identity and platform-admin inventories.",
        examples: ["identity platform pipeline", "break-glass admin"],
        falsePositiveReduction: "Suppress known IdP or CI roles after review.",
      },
    ],
    logicExplanation: {
      humanReadable: `Fire on successful ${eventName} from ${eventSource}.`,
      conditions: [`eventSource = ${eventSource}`, `eventName = ${eventName}`],
      whenToFire: "On each matching successful CloudTrail event.",
    },
    simulationCommand: command,
    quality: {
      signalQuality: 7,
      falsePositiveRate: "low-to-medium depending on platform automation",
      expectedVolume: "low",
      productionReadiness: "experimental",
    },
  });
}

const rules = [
  {
    slug: "openid-connect-provider-created",
    id: "det-201",
    title: "IAM OpenID Connect Provider Created",
    description: "Detects iam:CreateOpenIDConnectProvider. A rogue OIDC IdP can be trusted by roles for AssumeRoleWithWebIdentity persistence.",
    awsService: "IAM",
    eventSource: "iam.amazonaws.com",
    eventName: "CreateOpenIDConnectProvider",
    command: "aws iam create-open-id-connect-provider --url https://example.invalid --client-id-list sts.amazonaws.com --thumbprint-list 0000000000000000000000000000000000000000",
    sigma: `title: IAM OpenID Connect Provider Created
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: CreateOpenIDConnectProvider
  condition: selection
level: high
`,
  },
  {
    slug: "lambda-permission-added-for-external-principal",
    id: "det-202",
    title: "Lambda Permission Added for External Principal",
    description: "Detects lambda:AddPermission, which grants invoke rights via resource policy. This is the control-plane action for a Lambda resource-policy backdoor.",
    awsService: "Lambda",
    eventSource: "lambda.amazonaws.com",
    eventName: "AddPermission20150331",
    command: "aws lambda add-permission --function-name TargetFunction --statement-id BackdoorAccess --action lambda:InvokeFunction --principal 999888777666",
    sigma: `title: Lambda Permission Added
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: lambda.amazonaws.com
    eventName:
      - AddPermission20150331
      - AddPermission
  condition: selection
level: high
`,
  },
  {
    slug: "ec2-get-password-data",
    id: "det-203",
    title: "EC2 GetPasswordData Retrieved",
    description: "Detects ec2:GetPasswordData, used to retrieve the encrypted Windows administrator password for an instance.",
    awsService: "EC2",
    eventSource: "ec2.amazonaws.com",
    eventName: "GetPasswordData",
    command: "aws ec2 get-password-data --instance-id i-0abc123",
    sigma: `title: EC2 GetPasswordData Retrieved
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: ec2.amazonaws.com
    eventName: GetPasswordData
  condition: selection
level: high
`,
  },
  {
    slug: "cognito-identity-pool-credentials-retrieved",
    id: "det-204",
    title: "Cognito Identity Pool Credentials Retrieved",
    description: "Detects Cognito identity-pool credential issuance (GetCredentialsForIdentity / GetOpenIdToken) used to obtain AWS credentials from an identity pool, including unauthenticated pools.",
    awsService: "Cognito",
    eventSource: "cognito-identity.amazonaws.com",
    eventName: "GetCredentialsForIdentity",
    command: "aws cognito-identity get-credentials-for-identity --identity-id us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    sigma: `title: Cognito Identity Pool Credentials Retrieved
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: cognito-identity.amazonaws.com
    eventName:
      - GetCredentialsForIdentity
      - GetOpenIdToken
      - GetId
  condition: selection
level: medium
`,
  },
  {
    slug: "lambda-function-code-updated",
    id: "det-205",
    title: "Lambda Function Code Updated",
    description: "Detects lambda:UpdateFunctionCode, which replaces function code that then runs with the function's IAM role.",
    awsService: "Lambda",
    eventSource: "lambda.amazonaws.com",
    eventName: "UpdateFunctionCode20150331v2",
    command: "aws lambda update-function-code --function-name TargetFunction --zip-file fileb://malicious.zip",
    sigma: `title: Lambda Function Code Updated
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: lambda.amazonaws.com
    eventName:
      - UpdateFunctionCode20150331v2
      - UpdateFunctionCode
  condition: selection
level: high
`,
  },
];

for (const r of rules) {
  const dir = path.join(AWS, r.slug);
  if (fs.existsSync(path.join(dir, "meta.json"))) {
    console.log(`skip existing ${r.id} ${r.slug}`);
    continue;
  }
  writeJson(path.join(dir, "meta.json"), {
    id: r.id,
    title: r.title,
    description: r.description,
    awsService: r.awsService,
    relatedServices: ["IAM"],
    cloudProvider: "aws",
    severity: r.id === "det-204" ? "Medium" : "High",
    tags: [r.awsService, "Control Plane"],
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Authorized platform automation"],
    relatedAttackSlugs: [],
  });
  writeText(path.join(dir, "sigma.yml"), r.sigma);
  writeJson(path.join(dir, "telemetry.json"), {
    primaryLogSource: "AWS CloudTrail",
    generatingService: r.eventSource,
    importantFields: ["eventSource", "eventName", "userIdentity.arn", "sourceIPAddress", "eventTime"],
    exampleEvent: JSON.stringify(
      {
        eventVersion: "1.08",
        eventSource: r.eventSource,
        eventName: r.eventName,
        userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/attacker" },
        eventTime: "2026-01-15T12:00:00Z",
        sourceIPAddress: "203.0.113.10",
      },
      null,
      2
    ),
  });
  writeJson(path.join(dir, "investigation.json"), [
    `Identify who called ${r.eventName}.`,
    "Confirm the action was authorized.",
    "Inspect the created or modified resource for backdoors.",
  ]);
  writeJson(path.join(dir, "testing.json"), [
    `Run: ${r.command}`,
    "Confirm CloudTrail captured the event.",
    "Run the Sigma rule against the event.",
  ]);
  writeLifecycle(dir, {
    title: r.title,
    behavior: r.description,
    eventSource: r.eventSource,
    eventName: r.eventName,
    command: r.command,
  });
  console.log(`created ${r.id} ${r.slug}`);
}
