export interface Detection {
  id: string;
  title: string;
  description: string;
  type: "Sigma" | "CloudTrail" | "Splunk" | "SIEM";
  logSources: string[];
  falsePositives: string[];
  query: string;
}

export const detections: Detection[] = [
  {
    id: "det-001",
    title: "AWS PassRole Privilege Escalation",
    description: "Detects when iam:PassRole is used to pass an administrative role to a Lambda function.",
    type: "Sigma",
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Legitimate DevOps automation creating Lambda functions with appropriate roles"],
    query: `title: AWS Lambda PassRole Privilege Escalation
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventName: CreateFunction20150331
    requestParameters.role|contains: 'Admin'
  condition: selection
level: high`,
  },
  {
    id: "det-002",
    title: "CloudTrail Logging Disabled",
    description: "Detects when CloudTrail logging is stopped or the trail is deleted.",
    type: "CloudTrail",
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Planned maintenance or CloudTrail reconfiguration"],
    query: `SELECT eventTime, userIdentity.arn, eventName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventName IN ('StopLogging', 'DeleteTrail', 'UpdateTrail')
ORDER BY eventTime DESC`,
  },
  {
    id: "det-003",
    title: "Unusual S3 Data Download Volume",
    description: "Detects unusually large data downloads from S3 buckets that may indicate exfiltration.",
    type: "Splunk",
    logSources: ["AWS CloudTrail S3 Data Events"],
    falsePositives: ["Legitimate data pipeline operations", "Backup processes"],
    query: `index=aws sourcetype=aws:cloudtrail eventName=GetObject
| stats sum(bytesTransferredOut) as total_bytes by userIdentity.arn, requestParameters.bucketName
| where total_bytes > 1073741824
| sort -total_bytes`,
  },
  {
    id: "det-004",
    title: "IAM User Policy Attachment",
    description: "Detects when an IAM policy is attached directly to a user, which may indicate privilege escalation.",
    type: "SIEM",
    logSources: ["AWS CloudTrail"],
    falsePositives: ["Onboarding processes for new users"],
    query: `event.action:("AttachUserPolicy" OR "PutUserPolicy")
AND NOT user.name:("terraform" OR "cloudformation")`,
  },
  {
    id: "det-005",
    title: "Lambda Function with External Network Calls",
    description: "Identifies Lambda functions making connections to external IP addresses.",
    type: "CloudTrail",
    logSources: ["VPC Flow Logs", "Lambda Logs"],
    falsePositives: ["Lambda functions that legitimately call external APIs"],
    query: `SELECT srcAddr, dstAddr, dstPort, protocol
FROM vpc_flow_logs
WHERE srcAddr IN (SELECT private_ip FROM lambda_eni_mapping)
  AND dstAddr NOT LIKE '10.%'
  AND dstAddr NOT LIKE '172.16.%'
ORDER BY start_time DESC`,
  },
];
