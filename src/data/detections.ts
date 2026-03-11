export type RuleFormat = "sigma" | "splunk" | "cloudtrail" | "cloudwatch" | "eventbridge";

export interface RuleFormats {
  sigma?: string;
  splunk?: string;
  cloudtrail?: string;
  cloudwatch?: string;
  /** EventBridge rule pattern (detection logic, not deployment) */
  eventbridge?: string;
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
      sigma: `title: AWS Lambda PassRole Privilege Escalation
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventName: CreateFunction20150331
    requestParameters.role|contains: 'Admin'
  condition: selection
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=CreateFunction*
| where like(requestParameters.role, "%Admin%")
| table _time, userIdentity.arn, requestParameters.functionName, requestParameters.role`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters
FROM cloudtrail_logs
WHERE eventName = 'CreateFunction20150331'
  AND requestParameters LIKE '%Admin%'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName
| filter eventName = "CreateFunction20150331"
| filter requestParameters.role like /Admin/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.lambda"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["CreateFunction20150331"] } }, null, 2),
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
    eventName:
      - AttachUserPolicy
      - PutUserPolicy
  filter:
    userIdentity.principalId|contains:
      - 'terraform'
      - 'cloudformation'
  condition: selection and not filter
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail (eventName=AttachUserPolicy OR eventName=PutUserPolicy)
| where NOT like(userIdentity.principalId, "%terraform%")
| table _time, userIdentity.arn, eventName, requestParameters.policyArn`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, requestParameters
FROM cloudtrail_logs
WHERE eventName IN ('AttachUserPolicy', 'PutUserPolicy')
  AND userIdentity.principalId NOT LIKE '%terraform%'
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.policyArn
| filter eventName in ["AttachUserPolicy", "PutUserPolicy"]
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["AttachUserPolicy", "PutUserPolicy"] } }, null, 2),
    },
    relatedAttackSlugs: ["iam-privilege-escalation", "assumerole-abuse", "create-policy-version-abuse", "iam-backdoor-policies"],
    telemetry: {
      primaryLogSource: "AWS CloudTrail",
      generatingService: "iam.amazonaws.com",
      importantFields: ["eventName", "userIdentity.arn", "userIdentity.principalId", "requestParameters.policyArn", "sourceIPAddress", "eventTime"],
      exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "AttachUserPolicy", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user", principalId: "AIDAEXAMPLE" }, requestParameters: { policyArn: "arn:aws:iam::123456789012:policy/AdminPolicy", userName: "target-user" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2),
    },
    investigationSteps: ["Identify the IAM user that attached the policy.", "Verify whether the policy attachment was authorized (e.g., onboarding).", "Check if userIdentity.principalId excludes Terraform/CloudFormation.", "Review the attached policy's permissions.", "Correlate with other IAM changes from the same identity."],
    testingSteps: ["Create an IAM user with AttachUserPolicy permission.", "Attach a policy to another user.", "Verify CloudTrail captures AttachUserPolicy or PutUserPolicy.", "Run the detection query to confirm the alert triggers."],},
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
    eventName: CreateAccessKey
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=CreateAccessKey
| where userIdentity.arn != requestParameters.userName
| table _time, userIdentity.arn, requestParameters.userName`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, requestParameters.userName
FROM cloudtrail_logs
WHERE eventName = 'CreateAccessKey'
ORDER BY eventTime DESC`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["CreateAccessKey"] } }, null, 2),
    },
    relatedAttackSlugs: ["iam-backdoor-policies"],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.userName", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "CreateAccessKey", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/attacker" }, requestParameters: { userName: "victim-user" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who created the access key and for which user.", "Verify if the target user differs from the caller (backdoor indicator).", "Review recent activity of both identities.", "Check if the key creation was part of onboarding."],
    testingSteps: ["As user A, create an access key for user B.", "Verify CloudTrail captures CreateAccessKey.", "Run the detection to confirm it triggers on cross-user key creation."],},
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
    eventName: CreatePolicyVersion
  condition: selection
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=CreatePolicyVersion
| spath input=requestParameters.policyDocument
| where like(Statement{}.Action, "%*%") AND like(Statement{}.Resource, "%*%")
| table _time, userIdentity.arn, requestParameters.policyArn`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, requestParameters.policyArn
FROM cloudtrail_logs
WHERE eventName = 'CreatePolicyVersion'
ORDER BY eventTime DESC`,
      eventbridge: JSON.stringify({ source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["CreatePolicyVersion"] } }, null, 2),
    },
    relatedAttackSlugs: ["create-policy-version-abuse", "iam-privilege-escalation"],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "iam.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.policyArn", "requestParameters.policyDocument", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "iam.amazonaws.com", eventName: "CreatePolicyVersion", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { policyArn: "arn:aws:iam::123456789012:policy/ExistingPolicy", policyDocument: '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who created the policy version.", "Inspect the new policy document for Action:* and Resource:*.", "Verify whether the identity was attached to the policy.", "Review recent privilege escalation activity."],
    testingSteps: ["Attach a policy to your user, then create a new version with admin permissions.", "Set it as default.", "Run the detection query to confirm the alert triggers."],},

  // --- Lambda ---
  {
    id: "det-005",
    title: "Lambda Function with External Network Calls",
    description: "Identifies Lambda functions making connections to external IP addresses.",
    awsService: "Lambda",
    relatedServices: ["EC2"],
    severity: "High",
    tags: ["Lambda", "Persistence", "Network"],
    logSources: ["VPC Flow Logs", "Lambda Logs"],
    falsePositives: ["Lambda functions that legitimately call external APIs"],
    rules: {
      sigma: `title: Lambda External Network Connection
status: experimental
logsource:
  product: aws
  service: vpcflow
detection:
  selection:
    srcAddr|startswith: '10.'
    dstPort:
      - 443
      - 80
      - 4444
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudwatchlogs:vpcflow
| where srcAddr IN (lookup lambda_eni_ips)
  AND NOT cidrmatch("10.0.0.0/8", dstAddr)
| stats count by srcAddr, dstAddr, dstPort`,
      cloudtrail: `SELECT srcAddr, dstAddr, dstPort, protocol
FROM vpc_flow_logs
WHERE srcAddr IN (SELECT private_ip FROM lambda_eni_mapping)
  AND dstAddr NOT LIKE '10.%'
  AND dstAddr NOT LIKE '172.16.%'
ORDER BY start_time DESC`,
      cloudwatch: `fields @timestamp, srcAddr, dstAddr, dstPort
| filter srcAddr like /10\\./
| filter dstAddr not like /^10\\./
| filter dstAddr not like /^172\\.16/
| stats count by srcAddr, dstAddr, dstPort`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["VPC Flow Log"], detail: {} }, null, 2),
    },
    relatedAttackSlugs: ["lambda-persistence", "lambda-privilege-escalation"],
    telemetry: { primaryLogSource: "VPC Flow Logs", generatingService: "vpcflowlogs.amazonaws.com", importantFields: ["srcAddr", "dstAddr", "dstPort", "protocol", "bytes"], exampleEvent: JSON.stringify({ version: "2", accountId: "123456789012", interfaceId: "eni-xxx", srcAddr: "10.0.1.50", dstAddr: "93.184.216.34", dstPort: 443, protocol: 6, packets: 1, bytes: 150 }, null, 2) },
    investigationSteps: ["Correlate srcAddr with Lambda ENI IPs.", "Identify which Lambda function made the external connection.", "Verify if the destination is an approved external API.", "Review Lambda function code for data exfiltration."],
    testingSteps: ["Deploy a Lambda that calls an external API.", "Ensure VPC Flow Logs capture the traffic.", "Run the detection to confirm it triggers on non-RFC1918 destinations."],},
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
    eventName: CreateFunction20150331
    requestParameters.role|contains: 'Admin'
  condition: selection
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=CreateFunction*
| where like(requestParameters.role, "%AdministratorAccess%") OR like(requestParameters.role, "%Admin%")
| table _time, userIdentity.arn, requestParameters.functionName, requestParameters.role`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, requestParameters.functionName, requestParameters.role
FROM cloudtrail_logs
WHERE eventName = 'CreateFunction20150331'
  AND requestParameters.role LIKE '%Admin%'`,
      eventbridge: JSON.stringify({ source: ["aws.lambda"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["CreateFunction20150331"] } }, null, 2),
    },
    relatedAttackSlugs: ["aws-passrole-abuse", "lambda-privilege-escalation"],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "lambda.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.role", "requestParameters.functionName", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "lambda.amazonaws.com", eventName: "CreateFunction20150331", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { functionName: "my-function", role: "arn:aws:iam::123456789012:role/AdministratorAccess" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who created the Lambda and which role was passed.", "Inspect the role for AdministratorAccess or similar.", "Verify if the creation was from a deployment pipeline.", "Review Lambda execution history for suspicious invocations."],
    testingSteps: ["Create a Lambda with a role containing 'Admin' or 'AdministratorAccess'.", "Observe CloudTrail CreateFunction event.", "Run the detection query to confirm the alert triggers."],},
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
    eventName: CreateEventSourceMapping
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=CreateEventSourceMapping
| table _time, userIdentity.arn, requestParameters.functionName, requestParameters.eventSourceArn`,
      eventbridge: JSON.stringify({ source: ["aws.lambda"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["CreateEventSourceMapping"] } }, null, 2),
    },
    relatedAttackSlugs: ["lambda-persistence"],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "lambda.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.functionName", "requestParameters.eventSourceArn", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "lambda.amazonaws.com", eventName: "CreateEventSourceMapping", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { functionName: "my-function", eventSourceArn: "arn:aws:dynamodb:us-east-1:123456789012:table/MyTable/stream/xxx" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the Lambda and event source (DynamoDB, S3, etc.).", "Verify if the mapping was part of a legitimate deployment.", "Review the Lambda's execution role and triggers.", "Check for persistence via scheduled or event-driven execution."],
    testingSteps: ["Create an event source mapping (e.g., DynamoDB stream to Lambda).", "Verify CloudTrail captures CreateEventSourceMapping.", "Run the detection to confirm the alert triggers."],},

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
    eventName: RunInstances
    requestParameters.iamInstanceProfile.arn|contains: 'Admin'
  condition: selection
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=RunInstances
| where like(requestParameters.iamInstanceProfile.arn, "%Admin%")
| table _time, userIdentity.arn, requestParameters.instanceType`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, requestParameters.instanceType,
       requestParameters.iamInstanceProfile.arn
FROM cloudtrail_logs
WHERE eventName = 'RunInstances'
  AND requestParameters.iamInstanceProfile.arn LIKE '%Admin%'`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["RunInstances"] } }, null, 2),
    },
    relatedAttackSlugs: ["ec2-metadata-abuse"],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.iamInstanceProfile.arn", "requestParameters.instanceType", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "RunInstances", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { instanceType: "t3.micro", iamInstanceProfile: { arn: "arn:aws:iam::123456789012:instance-profile/AdminRole" } }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who launched the instance and which IAM profile was used.", "Inspect the instance profile for Admin or high-privilege policies.", "Verify if the instance is a management host with legitimate elevated access.", "Review IMDS configuration for credential theft risk."],
    testingSteps: ["Launch an EC2 instance with an IAM profile containing 'Admin'.", "Verify CloudTrail captures RunInstances.", "Run the detection to confirm the alert triggers."],},
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
  selection:
    eventName: RunInstances
    requestParameters.metadataOptions.httpTokens: optional
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=RunInstances
| spath requestParameters.instancesSet.items{}.metadataOptions.httpTokens
| where httpTokens="optional"
| table _time, userIdentity.arn, responseElements.instancesSet.items{}.instanceId`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["RunInstances"] } }, null, 2),
    },
    relatedAttackSlugs: ["ec2-metadata-abuse"],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.metadataOptions.httpTokens", "responseElements.instancesSet", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "RunInstances", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { metadataOptions: { httpTokens: "optional" } }, responseElements: { instancesSet: { items: [{ instanceId: "i-xxx" }] } }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify instances launched with httpTokens: optional (IMDSv1).", "Assess SSRF risk for applications on those instances.", "Plan migration to IMDSv2.", "Review instance usage for credential access attempts."],
    testingSteps: ["Launch an EC2 instance without enforcing IMDSv2.", "Verify CloudTrail shows metadataOptions.httpTokens.", "Run the detection to confirm it triggers on optional tokens."],},
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
    eventName: AuthorizeSecurityGroupIngress
    requestParameters.ipPermissions.items{}.ipRanges.items{}.cidrIp: '0.0.0.0/0'
  condition: selection
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=AuthorizeSecurityGroupIngress
| where like(requestParameters, "%0.0.0.0/0%")
| table _time, userIdentity.arn, requestParameters.groupId`,
      cloudwatch: `fields @timestamp, userIdentity.arn, requestParameters.groupId
| filter eventName = "AuthorizeSecurityGroupIngress"
| filter requestParameters like /0\\.0\\.0\\.0\\/0/
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["AuthorizeSecurityGroupIngress"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.groupId", "requestParameters.ipPermissions", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "AuthorizeSecurityGroupIngress", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { groupId: "sg-xxx", ipPermissions: { items: [{ ipRanges: { items: [{ cidrIp: "0.0.0.0/0" }] } }] } }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who modified the security group.", "Verify if 0.0.0.0/0 was intentionally added (e.g., web server).", "Review the affected instances and exposed ports.", "Check for lateral movement or data exfiltration risk."],
    testingSteps: ["Add an ingress rule with 0.0.0.0/0 to a security group.", "Verify CloudTrail captures AuthorizeSecurityGroupIngress.", "Run the detection to confirm the alert triggers."],},

  // --- S3 ---
  {
    id: "det-003",
    title: "Unusual S3 Data Download Volume",
    description: "Detects unusually large data downloads from S3 buckets that may indicate exfiltration.",
    awsService: "S3",
    relatedServices: ["IAM", "CloudTrail"],
    severity: "High",
    tags: ["S3", "Data Exfiltration", "Anomaly"],
    logSources: ["AWS CloudTrail S3 Data Events"],
    falsePositives: ["Legitimate data pipeline operations", "Backup processes"],
    rules: {
      sigma: `title: Unusual S3 Data Download
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventName: GetObject
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=GetObject
| stats sum(bytesTransferredOut) as total_bytes by userIdentity.arn, requestParameters.bucketName
| where total_bytes > 1073741824
| sort -total_bytes`,
      cloudtrail: `SELECT userIdentity.arn, requestParameters.bucketName,
       COUNT(*) as download_count
FROM cloudtrail_logs
WHERE eventName = 'GetObject'
GROUP BY userIdentity.arn, requestParameters.bucketName
HAVING download_count > 1000
ORDER BY download_count DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, requestParameters.bucketName
| filter eventName = "GetObject"
| stats count(*) as downloads by userIdentity.arn, requestParameters.bucketName
| filter downloads > 100
| sort downloads desc`,
      eventbridge: JSON.stringify({ source: ["aws.s3"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["GetObject"] } }, null, 2),
    },
    relatedAttackSlugs: ["s3-data-exfiltration"],
    telemetry: { primaryLogSource: "AWS CloudTrail S3 Data Events", generatingService: "s3.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.bucketName", "requestParameters.key", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "s3.amazonaws.com", eventName: "GetObject", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { bucketName: "my-bucket", key: "sensitive/data.csv" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify the identity and bucket with high download volume.", "Verify if the activity matches known pipelines or backups.", "Check for anomalous download patterns (time, volume).", "Review S3 access logs for exfiltration indicators."],
    testingSteps: ["Enable S3 data events for a test bucket.", "Perform many GetObject operations.", "Run the detection to confirm volume-based alert triggers."],},
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
    eventName:
      - PutBucketPolicy
      - DeleteBucketPolicy
  condition: selection
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail (eventName=PutBucketPolicy OR eventName=DeleteBucketPolicy)
| table _time, userIdentity.arn, requestParameters.bucketName`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.bucketName
| filter eventName in ["PutBucketPolicy", "DeleteBucketPolicy"]
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.s3"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["PutBucketPolicy", "DeleteBucketPolicy"] } }, null, 2),
    },
    relatedAttackSlugs: ["s3-data-exfiltration"],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "s3.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.bucketName", "requestParameters.policy", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "s3.amazonaws.com", eventName: "PutBucketPolicy", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { bucketName: "my-bucket", policy: '{"Statement":[{"Principal":{"AWS":"*"},"Action":"s3:GetObject"}]}' }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who modified the bucket policy.", "Inspect the new policy for public or cross-account access.", "Verify if the change was from IaC (Terraform/CloudFormation).", "Review recent S3 access from external principals."],
    testingSteps: ["Modify an S3 bucket policy (PutBucketPolicy or DeleteBucketPolicy).", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],},
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
  selection:
    eventName: DeletePublicAccessBlock
  condition: selection
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=DeletePublicAccessBlock
| table _time, userIdentity.arn, requestParameters.bucketName`,
      eventbridge: JSON.stringify({ source: ["aws.s3"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["DeletePublicAccessBlock"] } }, null, 2),
    },
    relatedAttackSlugs: ["s3-data-exfiltration"],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "s3.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.bucketName", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "s3.amazonaws.com", eventName: "DeletePublicAccessBlock", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { bucketName: "my-bucket" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who removed the public access block.", "Assess whether the bucket contains sensitive data.", "Verify if static website hosting was intended.", "Restore PublicAccessBlock if unauthorized."],
    testingSteps: ["Remove PublicAccessBlock from a test bucket.", "Verify CloudTrail captures DeletePublicAccessBlock.", "Run the detection to confirm the alert triggers."],},

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
  selection:
    eventName:
      - StopLogging
      - DeleteTrail
      - UpdateTrail
  condition: selection
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail (eventName=StopLogging OR eventName=DeleteTrail OR eventName=UpdateTrail)
| table _time, userIdentity.arn, eventName, sourceIPAddress`,
      cloudtrail: `SELECT eventTime, userIdentity.arn, eventName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventName IN ('StopLogging', 'DeleteTrail', 'UpdateTrail')
ORDER BY eventTime DESC`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, sourceIPAddress
| filter eventName in ["StopLogging", "DeleteTrail", "UpdateTrail"]
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.cloudtrail"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["StopLogging", "DeleteTrail", "UpdateTrail"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "cloudtrail.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "cloudtrail.amazonaws.com", eventName: "StopLogging", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { name: "my-trail" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who stopped, deleted, or updated the trail.", "Assess impact on audit visibility.", "Verify if this was planned maintenance.", "Restore CloudTrail immediately if unauthorized."],
    testingSteps: ["Stop logging on a test trail (or use UpdateTrail).", "Verify CloudTrail captures StopLogging/DeleteTrail/UpdateTrail.", "Run the detection to confirm the alert triggers."],},

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
    eventName: ScheduleKeyDeletion
  condition: selection
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=ScheduleKeyDeletion
| table _time, userIdentity.arn, requestParameters.keyId, requestParameters.pendingWindowInDays`,
      cloudwatch: `fields @timestamp, userIdentity.arn, requestParameters.keyId
| filter eventName = "ScheduleKeyDeletion"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.kms"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["ScheduleKeyDeletion"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "kms.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.keyId", "requestParameters.pendingWindowInDays", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "kms.amazonaws.com", eventName: "ScheduleKeyDeletion", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { keyId: "arn:aws:kms:us-east-1:123456789012:key/xxx", pendingWindowInDays: 7 }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who scheduled the key deletion.", "Verify if this was planned key rotation.", "Assess impact on encrypted resources (S3, EBS).", "Cancel deletion if unauthorized."],
    testingSteps: ["Schedule key deletion for a test KMS key.", "Verify CloudTrail captures ScheduleKeyDeletion.", "Run the detection to confirm the alert triggers."],},
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
    eventName: PutKeyPolicy
  condition: selection
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=PutKeyPolicy
| table _time, userIdentity.arn, requestParameters.keyId`,
      eventbridge: JSON.stringify({ source: ["aws.kms"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["PutKeyPolicy"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "kms.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.keyId", "requestParameters.policy", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "kms.amazonaws.com", eventName: "PutKeyPolicy", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { keyId: "arn:aws:kms:us-east-1:123456789012:key/xxx", policyName: "default" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who modified the key policy.", "Inspect the new policy for unauthorized principals.", "Verify if this was routine key management.", "Review key usage for anomalies."],
    testingSteps: ["Modify a KMS key policy (PutKeyPolicy).", "Verify CloudTrail captures the event.", "Run the detection to confirm the alert triggers."],},

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
    eventName: ModifySnapshotAttribute
    requestParameters.createVolumePermission.add.items{}.group: 'all'
  condition: selection
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=ModifySnapshotAttribute
| where like(requestParameters, "%all%")
| table _time, userIdentity.arn, requestParameters.snapshotId`,
      cloudwatch: `fields @timestamp, userIdentity.arn, requestParameters.snapshotId
| filter eventName = "ModifySnapshotAttribute"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["ModifySnapshotAttribute"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.snapshotId", "requestParameters.createVolumePermission", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "ModifySnapshotAttribute", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { snapshotId: "snap-xxx", createVolumePermission: { add: { items: [{ group: "all" }] } } }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who made the snapshot public.", "Assess whether the snapshot contains sensitive data.", "Verify if this was for AMI sharing.", "Revoke public access if unauthorized."],
    testingSteps: ["Modify snapshot attribute to add group 'all'.", "Verify CloudTrail captures ModifySnapshotAttribute.", "Run the detection to confirm the alert triggers."],},
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
    eventName: CreateVolume
    requestParameters.encrypted: false
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=CreateVolume
| where requestParameters.encrypted="false"
| table _time, userIdentity.arn, responseElements.volumeId`,
      eventbridge: JSON.stringify({ source: ["aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["CreateVolume"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ec2.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.encrypted", "responseElements.volumeId", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ec2.amazonaws.com", eventName: "CreateVolume", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { encrypted: false, size: 100 }, responseElements: { volumeId: "vol-xxx" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who created the unencrypted volume.", "Verify if the environment has encryption exceptions.", "Assess compliance impact.", "Consider enabling encryption by default."],
    testingSteps: ["Create an EBS volume with encrypted: false.", "Verify CloudTrail captures CreateVolume.", "Run the detection to confirm the alert triggers."],},

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
    eventName: ExportTableToPointInTime
  condition: selection
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=ExportTableToPointInTime
| table _time, userIdentity.arn, requestParameters.tableArn, requestParameters.s3Bucket`,
      cloudwatch: `fields @timestamp, userIdentity.arn, requestParameters.tableArn
| filter eventName = "ExportTableToPointInTime"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.dynamodb"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["ExportTableToPointInTime"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "dynamodb.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.tableArn", "requestParameters.s3Bucket", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "dynamodb.amazonaws.com", eventName: "ExportTableToPointInTime", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { tableArn: "arn:aws:dynamodb:us-east-1:123456789012:table/MyTable", s3Bucket: "export-bucket" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who initiated the export and the destination S3 bucket.", "Verify if this was a scheduled data lake or backup.", "Check the S3 bucket for unauthorized access.", "Review export frequency for exfiltration patterns."],
    testingSteps: ["Export a DynamoDB table to S3.", "Verify CloudTrail captures ExportTableToPointInTime.", "Run the detection to confirm the alert triggers."],},
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
    eventName: UpdateTable
  condition: selection
level: medium`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=UpdateTable
| where requestParameters.deletionProtectionEnabled="false"
| table _time, userIdentity.arn, requestParameters.tableName`,
      eventbridge: JSON.stringify({ source: ["aws.dynamodb"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["UpdateTable"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "dynamodb.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.tableName", "requestParameters.deletionProtectionEnabled", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "dynamodb.amazonaws.com", eventName: "UpdateTable", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { tableName: "MyTable", deletionProtectionEnabled: false }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who disabled deletion protection.", "Verify if this was part of table lifecycle management.", "Assess risk of accidental table deletion.", "Re-enable protection if unauthorized."],
    testingSteps: ["Disable deletion protection on a test DynamoDB table.", "Verify CloudTrail captures UpdateTable.", "Run the detection to confirm the alert triggers."],},

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
    eventName:
      - CreateCluster
      - UpdateClusterConfig
  condition: selection
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail (eventName=CreateCluster OR eventName=UpdateClusterConfig)
| where like(requestParameters, "%publicAccessCidrs%0.0.0.0/0%")
| table _time, userIdentity.arn, requestParameters.name`,
      cloudwatch: `fields @timestamp, userIdentity.arn, eventName, requestParameters.name
| filter eventName in ["CreateCluster", "UpdateClusterConfig"]
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.eks"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["CreateCluster", "UpdateClusterConfig"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "eks.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.name", "requestParameters.resourcesVpcConfig", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "eks.amazonaws.com", eventName: "UpdateClusterConfig", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { name: "my-cluster", resourcesVpcConfig: { publicAccessCidrs: ["0.0.0.0/0"] } }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who enabled public endpoint or expanded publicAccessCidrs.", "Verify if this was for development cluster access.", "Assess exposure of the API server.", "Restrict public access if unauthorized."],
    testingSteps: ["Create or update an EKS cluster with public endpoint (0.0.0.0/0).", "Verify CloudTrail captures CreateCluster or UpdateClusterConfig.", "Run the detection to confirm the alert triggers."],},
  {
    id: "det-026",
    title: "EKS Anonymous Authentication Enabled",
    description: "Detects EKS cluster configurations that may allow anonymous or unauthenticated access.",
    awsService: "EKS",
    relatedServices: ["IAM"],
    severity: "Critical",
    tags: ["EKS", "Kubernetes", "Authentication"],
    logSources: ["AWS CloudTrail", "EKS Audit Logs"],
    falsePositives: ["Rare legitimate use cases for anonymous access"],
    rules: {
      sigma: `title: EKS Anonymous Auth
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventName: UpdateClusterConfig
  condition: selection
level: critical`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=UpdateClusterConfig
| table _time, userIdentity.arn, requestParameters.name, requestParameters`,
      eventbridge: JSON.stringify({ source: ["aws.eks"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["UpdateClusterConfig"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "eks.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.name", "requestParameters.accessConfig", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "eks.amazonaws.com", eventName: "UpdateClusterConfig", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { name: "my-cluster", accessConfig: { authenticationMode: "API_AND_CONFIG_MAP", bootstrapClusterCreatorAdminPermissions: true } }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who updated the cluster config.", "Check for anonymous or permissive authentication.", "Verify RBAC and access controls.", "Restore secure auth if unauthorized."],
    testingSteps: ["Update EKS cluster config with anonymous auth or permissive settings.", "Verify CloudTrail captures UpdateClusterConfig.", "Run the detection to confirm the alert triggers."],},
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
    eventName: RegisterTaskDefinition
  filter:
    requestParameters.containerDefinitions{}.image|contains:
      - '.dkr.ecr.'
  condition: selection and not filter
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=RegisterTaskDefinition
| where NOT like(requestParameters, "%.dkr.ecr.%")
| table _time, userIdentity.arn, requestParameters.family`,
      cloudwatch: `fields @timestamp, userIdentity.arn, requestParameters.family
| filter eventName = "RegisterTaskDefinition"
| sort @timestamp desc`,
      eventbridge: JSON.stringify({ source: ["aws.ecs"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["RegisterTaskDefinition"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "ecs.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.family", "requestParameters.containerDefinitions", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "ecs.amazonaws.com", eventName: "RegisterTaskDefinition", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { family: "my-task", containerDefinitions: [{ image: "nginx:latest" }] }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who registered the task definition.", "Inspect container images for non-ECR sources (supply chain risk).", "Verify if external registries are approved.", "Review task definitions for malicious code."],
    testingSteps: ["Register an ECS task definition with an image from Docker Hub.", "Verify CloudTrail captures RegisterTaskDefinition.", "Run the detection to confirm it triggers on non-ECR images."],},

  // --- Secrets Manager ---
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
    eventName: GetSecretValue
  condition: selection
  timeframe: 5m
  count: "> 10"
level: high`,
      splunk: `index=aws sourcetype=aws:cloudtrail eventName=GetSecretValue
| stats count by userIdentity.arn, bin(_time, 5m)
| where count > 10
| sort -count`,
      cloudwatch: `fields @timestamp, userIdentity.arn, requestParameters.secretId
| filter eventName = "GetSecretValue"
| stats count(*) as retrievals by userIdentity.arn
| filter retrievals > 10`,
      eventbridge: JSON.stringify({ source: ["aws.secretsmanager"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["GetSecretValue"] } }, null, 2),
    },
    relatedAttackSlugs: [],
    telemetry: { primaryLogSource: "AWS CloudTrail", generatingService: "secretsmanager.amazonaws.com", importantFields: ["eventName", "userIdentity.arn", "requestParameters.secretId", "sourceIPAddress", "eventTime"], exampleEvent: JSON.stringify({ eventVersion: "1.08", eventSource: "secretsmanager.amazonaws.com", eventName: "GetSecretValue", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" }, requestParameters: { secretId: "my-secret" }, sourceIPAddress: "203.0.113.10", eventTime: "2025-02-10T12:45:00Z" }, null, 2) },
    investigationSteps: ["Identify who retrieved secrets and in what volume.", "Verify if bulk retrieval matches app startup or rotation.", "Check for credential harvesting patterns.", "Review secret access patterns for anomalies."],
    testingSteps: ["Retrieve multiple secrets in quick succession (e.g., >10 in 5 min).", "Verify CloudTrail captures GetSecretValue.", "Run the detection to confirm volume-based alert triggers."],},

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
];

/**
 * Get detections grouped by PRIMARY AWS service only (for sidebar navigation).
 * Each rule appears once under its primary service — no duplicates.
 */
export function getDetectionsByService(): Record<string, Detection[]> {
  const grouped: Record<string, Detection[]> = {};
  const serviceOrder = ["IAM", "STS", "Lambda", "EC2", "S3", "EBS", "DynamoDB", "CloudTrail", "KMS", "EKS", "ECS", "Secrets Manager", "SSM", "Organizations"];

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
  const order = ["IAM", "STS", "Lambda", "EC2", "S3", "EBS", "DynamoDB", "CloudTrail", "KMS", "EKS", "ECS", "Secrets Manager", "SSM", "Organizations"];
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
