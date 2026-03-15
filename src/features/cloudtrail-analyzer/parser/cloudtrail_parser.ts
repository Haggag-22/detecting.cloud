/**
 * Main CloudTrail parser - detects format, extracts events, validates, normalizes.
 * Processes events sequentially for memory efficiency.
 */

import type {
  RawCloudTrailEvent,
  NormalizedCloudTrailEvent,
  ParseResult,
  IngestionResult,
  IngestionError,
} from "../types";
import {
  isCloudTrailEvent,
  isCloudTrailRecordsBundle,
  isCloudTrailEventArray,
} from "./json_validator";
import { normalizeEvent } from "../normalization/event_normalizer";
import { safeParseJson } from "../utils/error_handler";
import { createIngestionError } from "../utils/error_handler";
import { logger } from "../utils/logging";

/** Extract raw events from various input formats */
function extractRawEvents(parsed: unknown): RawCloudTrailEvent[] {
  if (isCloudTrailRecordsBundle(parsed)) {
    return parsed.Records;
  }
  if (isCloudTrailEventArray(parsed)) {
    return parsed;
  }
  if (isCloudTrailEvent(parsed)) {
    return [parsed];
  }
  return [];
}

/** Parse a single raw event into normalized format */
function parseOne(raw: RawCloudTrailEvent, index: number): ParseResult {
  try {
    const normalized = normalizeEvent(raw, index);
    return { success: true, event: normalized, raw };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    logger.warn("Failed to normalize event", { index, error: msg });
    return { success: false, error: msg, raw };
  }
}

/** Try to parse as NDJSON (one JSON object per line) */
function tryNdjson(input: string): RawCloudTrailEvent[] {
  const lines = input.split("\n").map((l) => l.trim()).filter(Boolean);
  if (lines.length < 2) return [];
  const events: RawCloudTrailEvent[] = [];
  for (let i = 0; i < lines.length; i++) {
    const parsed = safeParseJson<unknown>(lines[i]);
    if (parsed === null) return [];
    const extracted = extractRawEvents(parsed);
    if (extracted.length === 0) return [];
    events.push(...extracted);
  }
  return events;
}

/** Parse CloudTrail input (JSON string) into normalized events */
export function parseCloudTrailInput(input: string): IngestionResult {
  const errors: IngestionError[] = [];
  const parsedEvents: NormalizedCloudTrailEvent[] = [];

  let rawEvents: RawCloudTrailEvent[] = [];

  const parsed = safeParseJson<unknown>(input);
  if (parsed === null) {
    const ndjsonEvents = tryNdjson(input);
    if (ndjsonEvents.length > 0) {
      rawEvents = ndjsonEvents;
    } else {
      errors.push(createIngestionError("Invalid JSON", undefined, input));
      return {
        parsed_events: [],
        valid_count: 0,
        malformed_count: 0,
        total_count: 0,
        errors,
      };
    }
  } else {
    rawEvents = extractRawEvents(parsed);
  }

  if (rawEvents.length === 0) {
    errors.push(
      createIngestionError(
        "No CloudTrail events found. Expected: single event, array of events, or { Records: [...] }",
        undefined,
        input.slice(0, 300)
      )
    );
    return {
      parsed_events: [],
      valid_count: 0,
      malformed_count: 0,
      total_count: 0,
      errors,
    };
  }

  let validCount = 0;
  let malformedCount = 0;

  for (let i = 0; i < rawEvents.length; i++) {
    const result = parseOne(rawEvents[i], i);
    if (result.success && result.event) {
      parsedEvents.push(result.event);
      validCount++;
    } else {
      malformedCount++;
      errors.push(
        createIngestionError(
          result.error ?? "Unknown parse error",
          i,
          result.raw ? JSON.stringify(result.raw).slice(0, 200) : undefined
        )
      );
    }
  }

  return {
    parsed_events: parsedEvents,
    valid_count: validCount,
    malformed_count: malformedCount,
    total_count: rawEvents.length,
    errors,
  };
}
