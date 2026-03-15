/**
 * Single event paste handler.
 * Validates JSON and CloudTrail structure for pasted input.
 */

import { parseCloudTrailInput } from "../parser/cloudtrail_parser";
import type { IngestionResult } from "../types";

/** Process pasted text as CloudTrail input */
export function handlePasteInput(input: string): IngestionResult {
  const trimmed = input.trim();
  if (!trimmed) {
    return {
      parsed_events: [],
      valid_count: 0,
      malformed_count: 0,
      total_count: 0,
      errors: [{ message: "Empty input" }],
    };
  }
  return parseCloudTrailInput(trimmed);
}
