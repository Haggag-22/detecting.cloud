/**
 * Detection rules - single event and correlation.
 */

import type { CorrelationRule, SingleEventRule } from "../types";

/** Single-event rules - trigger on one event */
export const singleEventRules: SingleEventRule[] = [
  {
    id: "single-create-access-key",
    name: "CreateAccessKey",
    description: "Detects IAM access key creation",
    severity: "High",
    eventSource: "iam.amazonaws.com",
    eventName: "CreateAccessKey",
  },
  {
    id: "single-stop-logging",
    name: "CloudTrail Logging Disabled",
    description: "Detects CloudTrail StopLogging",
    severity: "Critical",
    eventSource: "cloudtrail.amazonaws.com",
    eventName: "StopLogging",
  },
  {
    id: "single-put-bucket-policy",
    name: "S3 Bucket Policy Modified",
    description: "Detects PutBucketPolicy",
    severity: "High",
    eventSource: "s3.amazonaws.com",
    eventName: "PutBucketPolicy",
  },
  {
    id: "single-attach-user-policy",
    name: "IAM User Policy Attachment",
    description: "Detects AttachUserPolicy",
    severity: "High",
    eventSource: "iam.amazonaws.com",
    eventName: "AttachUserPolicy",
  },
  {
    id: "single-create-policy-version",
    name: "IAM Policy Version Created",
    description: "Detects CreatePolicyVersion",
    severity: "Critical",
    eventSource: "iam.amazonaws.com",
    eventName: "CreatePolicyVersion",
  },
];

/** Correlation rules - require multiple events */
export const correlationRules: CorrelationRule[] = [
  {
    id: "corr-orphaned-origin-access",
    name: "Orphaned Origin Followed by Access Anomaly",
    description:
      "Detects when an S3 bucket is created and an object is uploaded shortly after - potential orphaned CloudFront origin abuse",
    severity: "High",
    steps: [
      { stepId: "step1", eventSource: "s3.amazonaws.com", eventName: "CreateBucket", resourceField: "bucketName" },
      { stepId: "step2", eventSource: "s3.amazonaws.com", eventName: "PutObject", resourceField: "bucketName" },
    ],
    conditions: [
      { type: "resource_match", resourceField: "bucketName" },
      { type: "time_order", afterStepId: "step1" },
      { type: "time_window", windowSeconds: 3600 },
    ],
    reason: "Object upload occurred shortly after bucket creation - possible orphaned origin pattern",
  },
  {
    id: "corr-assume-attach-policy",
    name: "AssumeRole Followed by Policy Attachment",
    description: "Detects AssumeRole followed by AttachRolePolicy on the assumed role",
    severity: "Critical",
    steps: [
      { stepId: "step1", eventSource: "sts.amazonaws.com", eventName: "AssumeRole", resourceField: "roleArn" },
      { stepId: "step2", eventSource: "iam.amazonaws.com", eventName: "AttachRolePolicy", resourceField: "roleName" },
    ],
    conditions: [
      { type: "time_order", afterStepId: "step1" },
      { type: "time_window", windowSeconds: 3600 },
    ],
    reason: "Policy attached to role shortly after assumption",
  },
  {
    id: "corr-create-user-access-key",
    name: "CreateUser Followed by CreateAccessKey",
    description: "Detects new user creation followed by access key creation - potential backdoor",
    severity: "Critical",
    steps: [
      { stepId: "step1", eventSource: "iam.amazonaws.com", eventName: "CreateUser", resourceField: "userName" },
      { stepId: "step2", eventSource: "iam.amazonaws.com", eventName: "CreateAccessKey", resourceField: "userName" },
    ],
    conditions: [
      { type: "resource_match", resourceField: "userName" },
      { type: "time_order", afterStepId: "step1" },
      { type: "time_window", windowSeconds: 3600 },
    ],
    reason: "Access key created for newly created user - potential backdoor",
  },
];
