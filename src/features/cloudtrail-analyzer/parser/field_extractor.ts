/**
 * Extract and flatten important security fields from CloudTrail events.
 */

import type { RawCloudTrailEvent } from "../types";

/** Extract principal fields from userIdentity */
export function extractPrincipal(event: RawCloudTrailEvent): {
  type: string;
  arn: string;
  account_id: string;
  session_context?: Record<string, unknown>;
} {
  const ui = event.userIdentity;
  return {
    type: ui?.type ?? "",
    arn: ui?.arn ?? "",
    account_id: ui?.accountId ?? "",
    session_context: ui?.sessionContext as Record<string, unknown> | undefined,
  };
}

/** Extract top-level security fields */
export function extractSecurityFields(event: RawCloudTrailEvent): {
  source_ip: string;
  user_agent: string;
  aws_region: string;
  request_parameters: Record<string, unknown>;
  response_elements: Record<string, unknown>;
  resources: Array<{ type?: string; arn?: string; account_id?: string }>;
} {
  const resources = (event.resources ?? []).map((r) => ({
    type: r.type,
    arn: r.ARN,
    account_id: r.accountId,
  }));

  return {
    source_ip: event.sourceIPAddress ?? "",
    user_agent: event.userAgent ?? "",
    aws_region: event.awsRegion ?? "",
    request_parameters: (event.requestParameters as Record<string, unknown>) ?? {},
    response_elements: (event.responseElements as Record<string, unknown>) ?? {},
    resources,
  };
}
