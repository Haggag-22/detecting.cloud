/**
 * File upload handler for CloudTrail logs.
 * Supports: single event, multiple events, JSON array, CloudTrail Records bundle,
 * line-delimited JSON datasets, and CSV (analyzer export format).
 */

import { parseCloudTrailInput } from "../parser/cloudtrail_parser";
import { parseCsvToCloudTrailEvents } from "./csv_parser";
import { normalizeEvent } from "../normalization/event_normalizer";
import type { IngestionResult, NormalizedCloudTrailEvent } from "../types";

/** Max upload size for analyzer file ingestion (50MB). */
const MAX_UPLOAD_SIZE_BYTES = 50 * 1024 * 1024;

function processCsv(text: string): IngestionResult {
  const rawEvents = parseCsvToCloudTrailEvents(text);
  const parsedEvents: NormalizedCloudTrailEvent[] = [];
  const errors: { message: string; index?: number }[] = [];
  let validCount = 0;
  let malformedCount = 0;

  for (let i = 0; i < rawEvents.length; i++) {
    try {
      const normalized = normalizeEvent(rawEvents[i], i);
      parsedEvents.push(normalized);
      validCount++;
    } catch (e) {
      malformedCount++;
      errors.push({
        message: e instanceof Error ? e.message : String(e),
        index: i,
      });
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

/** Process an uploaded file - reads as text and parses */
export async function handleFileUpload(file: File): Promise<IngestionResult> {
  if (file.size > MAX_UPLOAD_SIZE_BYTES) {
    return {
      parsed_events: [],
      valid_count: 0,
      malformed_count: 0,
      total_count: 0,
      errors: [
        {
          message: `File too large (${(file.size / 1024 / 1024).toFixed(1)}MB). Max ${MAX_UPLOAD_SIZE_BYTES / 1024 / 1024}MB.`,
        },
      ],
    };
  }

  const isCsv = file.name.toLowerCase().endsWith(".csv");

  return new Promise((resolve) => {
    const reader = new FileReader();
    reader.onload = () => {
      const text = reader.result as string;
      const result = isCsv ? processCsv(text) : parseCloudTrailInput(text);
      resolve(result);
    };
    reader.onerror = () => {
      resolve({
        parsed_events: [],
        valid_count: 0,
        malformed_count: 0,
        total_count: 0,
        errors: [{ message: `Failed to read file: ${reader.error?.message ?? "Unknown error"}` }],
      });
    };
    reader.readAsText(file, "utf-8");
  });
}
