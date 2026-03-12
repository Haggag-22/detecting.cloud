/**
 * Rule type system for detection engineering.
 * Supports single_event, sequence, and behavioral rule types.
 */

export type RuleType = "single_event" | "sequence" | "behavioral";

/** AWS service name mapping: EventBridge source -> CloudTrail eventSource */
export const EVENTBRIDGE_TO_CLOUDTRAIL_SOURCE: Record<string, string> = {
  "aws.iam": "iam.amazonaws.com",
  "aws.lambda": "lambda.amazonaws.com",
  "aws.ec2": "ec2.amazonaws.com",
  "aws.s3": "s3.amazonaws.com",
  "aws.cloudtrail": "cloudtrail.amazonaws.com",
  "aws.kms": "kms.amazonaws.com",
  "aws.eks": "eks.amazonaws.com",
  "aws.codebuild": "codebuild.amazonaws.com",
  "aws.elasticbeanstalk": "elasticbeanstalk.amazonaws.com",
  "aws.secretsmanager": "secretsmanager.amazonaws.com",
  "aws.sts": "sts.amazonaws.com",
  "aws.rds": "rds.amazonaws.com",
  "aws.dynamodb": "dynamodb.amazonaws.com",
};

export interface RuleCondition {
  field: string;
  operator: "equals" | "in" | "contains" | "exists";
  values: string[];
}

export interface ParsedRule {
  ruleType: RuleType;
  requiredFields: string[];
  conditions: RuleCondition[];
  expectedEventSource?: string;
  expectedEventNames?: string[];
  /** For sequence rules: ordered event names */
  sequenceSteps?: string[];
  /** For sequence rules: time window in minutes */
  sequenceWindowMinutes?: number;
}
