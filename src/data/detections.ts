export type RuleFormat = "sigma" | "splunk" | "cloudtrail" | "cloudwatch";

export interface RuleFormats {
  sigma?: string;
  splunk?: string;
  cloudtrail?: string;
  cloudwatch?: string;
}

export interface Detection {
  id: string;
  title: string;
  description: string;
  awsService: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  tags: string[];
  logSources: string[];
  falsePositives: string[];
  rules: RuleFormats;
  relatedAttackSlugs: string[];
}

export const awsServices = [
  "IAM",
  "Lambda",
  "EC2",
  "S3",
  "EBS",
  "DynamoDB",
  "CloudTrail",
  "KMS",
  "EKS",
] as const;

export const detections: Detection[] = [
  // --- IAM ---
  {
    id: "det-001",
    title: "IAM PassRole Privilege Escalation",
    description: "Detects when iam:PassRole is used to pass an administrative role to a Lambda function or other AWS service.",
    awsService: "IAM",
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
    },
    relatedAttackSlugs: ["aws-passrole-abuse", "iam-privilege-escalation", "lambda-privilege-escalation"],
  },
  {
    id: "det-004",
    title: "IAM User Policy Attachment",
    description: "Detects when an IAM policy is attached directly to a user, which may indicate privilege escalation.",
    awsService: "IAM",
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
    },
    relatedAttackSlugs: ["iam-privilege-escalation", "assumerole-abuse", "create-policy-version-abuse", "iam-backdoor-policies"],
  },
  {
    id: "det-010",
    title: "IAM Access Key Created for Another User",
    description: "Detects when an IAM user creates access keys for a different user, potentially establishing backdoor access.",
    awsService: "IAM",
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
    },
    relatedAttackSlugs: ["iam-backdoor-policies"],
  },
  {
    id: "det-011",
    title: "IAM Policy Version Created with Full Admin",
    description: "Detects creation of a new policy version granting full administrative access (Action: *, Resource: *).",
    awsService: "IAM",
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
    },
    relatedAttackSlugs: ["create-policy-version-abuse", "iam-privilege-escalation"],
  },

  // --- Lambda ---
  {
    id: "det-005",
    title: "Lambda Function with External Network Calls",
    description: "Identifies Lambda functions making connections to external IP addresses.",
    awsService: "Lambda",
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
    },
    relatedAttackSlugs: ["lambda-persistence", "lambda-privilege-escalation"],
  },
  {
    id: "det-012",
    title: "Lambda Function Created with Admin Role",
    description: "Detects creation of Lambda functions with overly permissive execution roles.",
    awsService: "Lambda",
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
    },
    relatedAttackSlugs: ["aws-passrole-abuse", "lambda-privilege-escalation"],
  },
  {
    id: "det-013",
    title: "Lambda Event Source Mapping Created",
    description: "Detects new Lambda event source mappings which could be used for persistence via trigger-based execution.",
    awsService: "Lambda",
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
    },
    relatedAttackSlugs: ["lambda-persistence"],
  },

  // --- EC2 ---
  {
    id: "det-014",
    title: "EC2 Instance with Highly Privileged IAM Role",
    description: "Detects EC2 instances launched with IAM roles that have administrative or highly permissive policies.",
    awsService: "EC2",
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
    },
    relatedAttackSlugs: ["ec2-metadata-abuse"],
  },
  {
    id: "det-015",
    title: "EC2 IMDSv1 Usage Detected",
    description: "Detects EC2 instances using IMDSv1 which is vulnerable to SSRF-based credential theft.",
    awsService: "EC2",
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
    },
    relatedAttackSlugs: ["ec2-metadata-abuse"],
  },
  {
    id: "det-016",
    title: "EC2 Security Group Opened to 0.0.0.0/0",
    description: "Detects when an EC2 security group is modified to allow inbound traffic from any IP address.",
    awsService: "EC2",
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
    },
    relatedAttackSlugs: [],
  },

  // --- S3 ---
  {
    id: "det-003",
    title: "Unusual S3 Data Download Volume",
    description: "Detects unusually large data downloads from S3 buckets that may indicate exfiltration.",
    awsService: "S3",
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
    },
    relatedAttackSlugs: ["s3-data-exfiltration"],
  },
  {
    id: "det-017",
    title: "S3 Bucket Policy Modified",
    description: "Detects modifications to S3 bucket policies which could expose data publicly or to unauthorized accounts.",
    awsService: "S3",
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
    },
    relatedAttackSlugs: ["s3-data-exfiltration"],
  },
  {
    id: "det-018",
    title: "S3 Bucket Made Public",
    description: "Detects when S3 Public Access Block settings are removed, potentially exposing bucket contents.",
    awsService: "S3",
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
    },
    relatedAttackSlugs: ["s3-data-exfiltration"],
  },

  // --- CloudTrail ---
  {
    id: "det-002",
    title: "CloudTrail Logging Disabled",
    description: "Detects when CloudTrail logging is stopped or the trail is deleted.",
    awsService: "CloudTrail",
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
    },
    relatedAttackSlugs: [],
  },

  // --- KMS ---
  {
    id: "det-019",
    title: "KMS Key Scheduled for Deletion",
    description: "Detects when a KMS key is scheduled for deletion, which could lead to data loss or indicate destructive activity.",
    awsService: "KMS",
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
    },
    relatedAttackSlugs: [],
  },
  {
    id: "det-020",
    title: "KMS Key Policy Modified",
    description: "Detects modifications to KMS key policies which could grant unauthorized access to encryption keys.",
    awsService: "KMS",
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
    },
    relatedAttackSlugs: [],
  },

  // --- EBS ---
  {
    id: "det-021",
    title: "EBS Snapshot Made Public",
    description: "Detects when an EBS snapshot is shared publicly, potentially exposing sensitive data.",
    awsService: "EBS",
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
    },
    relatedAttackSlugs: [],
  },
  {
    id: "det-022",
    title: "EBS Volume Not Encrypted",
    description: "Detects creation of unencrypted EBS volumes which violates security best practices.",
    awsService: "EBS",
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
    },
    relatedAttackSlugs: [],
  },

  // --- DynamoDB ---
  {
    id: "det-023",
    title: "DynamoDB Table Exported to S3",
    description: "Detects when a DynamoDB table is exported to S3, which could be used for data exfiltration.",
    awsService: "DynamoDB",
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
    },
    relatedAttackSlugs: [],
  },
  {
    id: "det-024",
    title: "DynamoDB Table Deletion Protection Disabled",
    description: "Detects when deletion protection is removed from a DynamoDB table.",
    awsService: "DynamoDB",
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
    },
    relatedAttackSlugs: [],
  },

  // --- EKS ---
  {
    id: "det-025",
    title: "EKS Cluster Public Endpoint Enabled",
    description: "Detects when an EKS cluster API server endpoint is made publicly accessible.",
    awsService: "EKS",
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
    },
    relatedAttackSlugs: [],
  },
  {
    id: "det-026",
    title: "EKS Anonymous Authentication Enabled",
    description: "Detects EKS cluster configurations that may allow anonymous or unauthenticated access.",
    awsService: "EKS",
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
    },
    relatedAttackSlugs: [],
  },
];

// Helper: group detections by AWS service
export function getDetectionsByService(): Record<string, Detection[]> {
  const grouped: Record<string, Detection[]> = {};
  for (const service of awsServices) {
    const serviceDetections = detections.filter((d) => d.awsService === service);
    if (serviceDetections.length > 0) {
      grouped[service] = serviceDetections;
    }
  }
  return grouped;
}
