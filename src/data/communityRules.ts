/**
 * Community-contributed detection rules.
 * 
 * To contribute a new rule, see CONTRIBUTING.md
 * Add your rule to the array below and submit a Pull Request.
 */

export interface CommunityRule {
  id: string;
  title: string;
  description: string;
  author: string;
  awsService: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  format: "sigma" | "splunk" | "cloudtrail" | "cloudwatch";
  rule: string;
  votes: number;
  createdAt: string;
  tags: string[];
}

export const communityRules: CommunityRule[] = [
  {
    id: "cr-001",
    title: "GuardDuty Finding Suppressed",
    description: "Detects when a GuardDuty finding is archived or suppressed, which could indicate an attacker covering their tracks.",
    author: "SecurityOps_Pro",
    awsService: "GuardDuty",
    severity: "High",
    format: "sigma",
    rule: `title: GuardDuty Finding Suppressed
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventName:
      - ArchiveFindings
      - UpdateFindingsFeedback
  condition: selection
level: high`,
    votes: 47,
    createdAt: "2025-12-15",
    tags: ["GuardDuty", "Defense Evasion"],
  },
  {
    id: "cr-002",
    title: "KMS Key Deletion Scheduled",
    description: "Detects when a KMS key is scheduled for deletion, potentially destroying encryption keys for critical data.",
    author: "CloudDefender42",
    awsService: "KMS",
    severity: "Critical",
    format: "splunk",
    rule: `index=aws sourcetype=aws:cloudtrail eventName=ScheduleKeyDeletion
| table _time, userIdentity.arn, requestParameters.keyId, requestParameters.pendingWindowInDays
| sort -_time`,
    votes: 62,
    createdAt: "2025-11-20",
    tags: ["KMS", "Impact", "Encryption"],
  },
  {
    id: "cr-003",
    title: "SSO Permission Set Modified",
    description: "Detects modifications to AWS SSO permission sets which could grant unauthorized access across accounts.",
    author: "IdentityWatch",
    awsService: "SSO",
    severity: "High",
    format: "cloudwatch",
    rule: `fields @timestamp, userIdentity.arn, eventName
| filter eventName in ["CreatePermissionSet", "UpdatePermissionSet", "AttachManagedPolicyToPermissionSet"]
| sort @timestamp desc`,
    votes: 35,
    createdAt: "2026-01-08",
    tags: ["SSO", "IAM", "Privilege Escalation"],
  },
  {
    id: "cr-004",
    title: "RDS Snapshot Made Public",
    description: "Detects when an RDS snapshot is shared publicly, potentially exposing database contents.",
    author: "DBSec_Team",
    awsService: "RDS",
    severity: "Critical",
    format: "sigma",
    rule: `title: RDS Snapshot Made Public
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventName: ModifyDBSnapshotAttribute
    requestParameters.attributeName: restore
    requestParameters.valuesToAdd: 'all'
  condition: selection
level: critical`,
    votes: 89,
    createdAt: "2025-10-05",
    tags: ["RDS", "Data Exposure", "Snapshot"],
  },
  {
    id: "cr-005",
    title: "Config Rule Deleted",
    description: "Detects deletion of AWS Config rules which could be used to disable compliance monitoring.",
    author: "ComplianceBot",
    awsService: "Config",
    severity: "Medium",
    format: "splunk",
    rule: `index=aws sourcetype=aws:cloudtrail (eventName=DeleteConfigRule OR eventName=DeleteDeliveryChannel)
| table _time, userIdentity.arn, eventName, requestParameters.configRuleName`,
    votes: 28,
    createdAt: "2026-02-01",
    tags: ["Config", "Defense Evasion", "Compliance"],
  },
  {
    id: "cr-006",
    title: "Secrets Manager Secret Accessed by Unusual Role",
    description: "Detects when secrets are accessed by IAM roles not in the expected list.",
    author: "VaultGuard",
    awsService: "Secrets Manager",
    severity: "High",
    format: "cloudtrail",
    rule: `SELECT eventTime, userIdentity.arn, requestParameters.secretId
FROM cloudtrail_logs
WHERE eventName = 'GetSecretValue'
  AND userIdentity.arn NOT LIKE '%expected-role%'
ORDER BY eventTime DESC`,
    votes: 41,
    createdAt: "2026-01-22",
    tags: ["Secrets Manager", "Credential Access"],
  },
];
