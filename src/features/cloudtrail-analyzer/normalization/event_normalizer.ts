/**
 * Normalize raw CloudTrail events into consistent internal schema.
 */

import type { RawCloudTrailEvent, NormalizedCloudTrailEvent } from "../types";
import { hasRequiredFields } from "../parser/json_validator";
import { extractPrincipal, extractSecurityFields } from "../parser/field_extractor";

/** Generate a unique event ID for internal use */
function generateEventId(event: RawCloudTrailEvent, index: number): string {
  const id = event.eventID ?? event.requestID ?? `evt-${index}-${Date.now()}`;
  return String(id);
}

/** Normalize a single raw CloudTrail event */
export function normalizeEvent(
  raw: RawCloudTrailEvent,
  index: number = 0
): NormalizedCloudTrailEvent {
  const principal = extractPrincipal(raw);
  const security = extractSecurityFields(raw);
  const isFullyStructured = hasRequiredFields(raw);

  return {
    event_id: generateEventId(raw, index),
    event_time: raw.eventTime ?? "",
    event_source: raw.eventSource ?? "",
    event_name: raw.eventName ?? "",
    aws_region: security.aws_region,
    source_ip: security.source_ip,
    user_agent: security.user_agent,
    principal_type: principal.type,
    principal_arn: principal.arn,
    principal_account_id: principal.account_id,
    request_parameters: security.request_parameters,
    response_elements: security.response_elements,
    resources: security.resources,
    session_context: principal.session_context,
    error_code: raw.errorCode,
    error_message: raw.errorMessage,
    read_only: raw.readOnly,
    event_type: raw.eventType,
    is_fully_structured: isFullyStructured,
    _raw: raw,
  };
}
