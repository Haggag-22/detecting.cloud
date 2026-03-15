/**
 * JSON validation for CloudTrail input.
 * Validates structure and required fields.
 */

import type { RawCloudTrailEvent } from "../types";

const REQUIRED_FIELDS = ["eventTime", "eventSource", "eventName"] as const;

/** Check if value is a plain object (not array, not null) */
export function isCloudTrailEvent(obj: unknown): obj is RawCloudTrailEvent {
  return (
    obj !== null &&
    typeof obj === "object" &&
    !Array.isArray(obj) &&
    Object.prototype.toString.call(obj) === "[object Object]"
  );
}

/** Check if object has CloudTrail Records structure */
export function isCloudTrailRecordsBundle(obj: unknown): obj is { Records: RawCloudTrailEvent[] } {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return false;
  const o = obj as Record<string, unknown>;
  return Array.isArray(o.Records) && o.Records.every(isCloudTrailEvent);
}

/** Check if value is an array of CloudTrail events */
export function isCloudTrailEventArray(obj: unknown): obj is RawCloudTrailEvent[] {
  return Array.isArray(obj) && obj.every(isCloudTrailEvent);
}

/** Validate required CloudTrail fields. Returns true if all present. */
export function hasRequiredFields(event: RawCloudTrailEvent): boolean {
  return REQUIRED_FIELDS.every((f) => event[f] != null && String(event[f]).trim() !== "");
}

/** Get missing required fields */
export function getMissingFields(event: RawCloudTrailEvent): string[] {
  return REQUIRED_FIELDS.filter((f) => event[f] == null || String(event[f]).trim() === "");
}
