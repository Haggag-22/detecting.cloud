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
