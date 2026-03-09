// Central data model entities for the Detecting.Cloud platform
// These entities power the Attack Graph, Detection Engineering, and sidebar navigation.

// ─── AWS Service Entity ───
export interface AwsService {
  id: string;
  name: string;
  shortName: string;
  description: string;
  category: "Security" | "Compute" | "Storage" | "Database" | "Management" | "Containers" | "Networking";
}

export const awsServices: AwsService[] = [
  {
    id: "iam",
    name: "AWS Identity and Access Management",
    shortName: "IAM",
    description: "Manage access to AWS services and resources securely using users, groups, roles, and policies.",
    category: "Security",
  },
  {
    id: "sts",
    name: "AWS Security Token Service",
    shortName: "STS",
    description: "Request temporary, limited-privilege credentials for IAM users or federated users.",
    category: "Security",
  },
  {
    id: "lambda",
    name: "AWS Lambda",
    shortName: "Lambda",
    description: "Run code without provisioning or managing servers. Supports event-driven serverless compute.",
    category: "Compute",
  },
  {
    id: "ec2",
    name: "Amazon Elastic Compute Cloud",
    shortName: "EC2",
    description: "Scalable virtual servers in the cloud with configurable compute capacity.",
    category: "Compute",
  },
  {
    id: "s3",
    name: "Amazon Simple Storage Service",
    shortName: "S3",
    description: "Object storage built to retrieve any amount of data from anywhere.",
    category: "Storage",
  },
  {
    id: "ebs",
    name: "Amazon Elastic Block Store",
    shortName: "EBS",
    description: "Block-level storage volumes for use with EC2 instances.",
    category: "Storage",
  },
  {
    id: "dynamodb",
    name: "Amazon DynamoDB",
    shortName: "DynamoDB",
    description: "Fast, flexible NoSQL database service for single-digit millisecond performance at any scale.",
    category: "Database",
  },
  {
    id: "cloudtrail",
    name: "AWS CloudTrail",
    shortName: "CloudTrail",
    description: "Track user activity and API usage across your AWS infrastructure.",
    category: "Management",
  },
  {
    id: "kms",
    name: "AWS Key Management Service",
    shortName: "KMS",
    description: "Create and manage cryptographic keys and control their use across AWS services.",
    category: "Security",
  },
  {
    id: "eks",
    name: "Amazon Elastic Kubernetes Service",
    shortName: "EKS",
    description: "Managed Kubernetes service to run containers without managing control plane infrastructure.",
    category: "Containers",
  },
];

// Lookup helpers
export function getServiceByShortName(shortName: string): AwsService | undefined {
  return awsServices.find((s) => s.shortName === shortName);
}

export function getServiceById(id: string): AwsService | undefined {
  return awsServices.find((s) => s.id === id);
}

// ─── Log Source Entity ───
export interface LogSource {
  id: string;
  name: string;
  description: string;
  awsServiceId: string; // which AWS service produces this telemetry
}

export const logSources: LogSource[] = [
  {
    id: "cloudtrail-management",
    name: "AWS CloudTrail",
    description: "Records API calls and management events across your AWS account. Primary source for detecting IAM, Lambda, EC2, and most AWS service activity.",
    awsServiceId: "cloudtrail",
  },
  {
    id: "cloudtrail-s3-data",
    name: "AWS CloudTrail S3 Data Events",
    description: "Records object-level API activity in S3 buckets (GetObject, PutObject, DeleteObject). Must be explicitly enabled per bucket or account.",
    awsServiceId: "cloudtrail",
  },
  {
    id: "vpc-flow-logs",
    name: "VPC Flow Logs",
    description: "Captures information about IP traffic going to and from network interfaces in your VPC.",
    awsServiceId: "ec2",
  },
  {
    id: "lambda-logs",
    name: "Lambda Logs",
    description: "CloudWatch Logs groups created by Lambda functions containing execution output, errors, and custom logging.",
    awsServiceId: "lambda",
  },
  {
    id: "ec2-metadata",
    name: "EC2 Instance Metadata",
    description: "Instance Metadata Service (IMDS) access patterns detectable through host-level monitoring.",
    awsServiceId: "ec2",
  },
  {
    id: "eks-audit",
    name: "EKS Audit Logs",
    description: "Kubernetes API server audit logs from EKS clusters, shipped to CloudWatch Logs.",
    awsServiceId: "eks",
  },
  {
    id: "guardduty",
    name: "Amazon GuardDuty",
    description: "Threat detection service that monitors for malicious activity and unauthorized behavior.",
    awsServiceId: "cloudtrail",
  },
];

export function getLogSourceById(id: string): LogSource | undefined {
  return logSources.find((ls) => ls.id === id);
}

export function getLogSourceByName(name: string): LogSource | undefined {
  return logSources.find((ls) => ls.name === name);
}
