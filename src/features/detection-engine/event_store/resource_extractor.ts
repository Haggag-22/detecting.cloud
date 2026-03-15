/**
 * Extract resource identifier from CloudTrail events for correlation.
 */

import type { NormalizedCloudTrailEvent } from "@/features/cloudtrail-analyzer";
import type { StoredEvent } from "../types";

/** Map eventSource + eventName to primary resource field */
const RESOURCE_FIELD_MAP: Record<string, string> = {
  "s3.amazonaws.com:CreateBucket": "bucketName",
  "s3.amazonaws.com:PutObject": "bucketName",
  "s3.amazonaws.com:PutObjectRequest": "bucketName",
  "s3.amazonaws.com:GetObject": "bucketName",
  "s3.amazonaws.com:DeleteBucket": "bucketName",
  "s3.amazonaws.com:PutBucketPolicy": "bucketName",
  "iam.amazonaws.com:CreateUser": "userName",
  "iam.amazonaws.com:CreateAccessKey": "userName",
  "iam.amazonaws.com:AttachUserPolicy": "userName",
  "iam.amazonaws.com:CreateRole": "roleName",
  "iam.amazonaws.com:AttachRolePolicy": "roleName",
  "iam.amazonaws.com:PutUserPolicy": "userName",
  "iam.amazonaws.com:CreatePolicyVersion": "policyArn",
  "sts.amazonaws.com:AssumeRole": "roleArn",
  "cloudtrail.amazonaws.com:StopLogging": "name",
  "cloudtrail.amazonaws.com:StartLogging": "name",
  "ec2.amazonaws.com:RunInstances": "instanceId",
  "ec2.amazonaws.com:AuthorizeSecurityGroupIngress": "groupId",
};

function getResourceField(eventSource: string, eventName: string): string | undefined {
  return RESOURCE_FIELD_MAP[`${eventSource}:${eventName}`];
}

function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split(".");
  let current: unknown = obj;
  for (const p of parts) {
    if (current == null || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[p];
  }
  return current;
}

/** Extract resource value from request_parameters */
function extractResourceValue(
  params: Record<string, unknown>,
  eventSource: string,
  eventName: string
): { value: string; type: string } {
  const field = getResourceField(eventSource, eventName);
  if (field) {
    let val = getNestedValue(params, field);
    if (val == null && (field === "bucketName" || field === "bucket")) {
      val = getNestedValue(params, "bucketName") ?? getNestedValue(params, "bucket");
    }
    if (val != null && typeof val === "string") {
      let type = "unknown";
      if (field.includes("bucket")) type = "bucket";
      else if (field.includes("user")) type = "user";
      else if (field.includes("role")) type = "role";
      else if (field.includes("policy")) type = "policy";
      return { value: val, type };
    }
  }
  return { value: "", type: "unknown" };
}

/** Convert NormalizedCloudTrailEvent to StoredEvent */
export function toStoredEvent(normalized: NormalizedCloudTrailEvent): StoredEvent {
  const { value: resource, type: resource_type } = extractResourceValue(
    normalized.request_parameters ?? {},
    normalized.event_source,
    normalized.event_name
  );

  return {
    event_id: normalized.event_id,
    event_time: normalized.event_time,
    event_source: normalized.event_source,
    event_name: normalized.event_name,
    actor: normalized.principal_arn || normalized.principal_type || "",
    resource,
    resource_type,
    source_ip: normalized.source_ip,
    aws_region: normalized.aws_region,
    request_parameters: normalized.request_parameters ?? {},
    _normalized: normalized,
  };
}
