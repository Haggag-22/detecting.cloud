/**
 * File upload handler for CloudTrail logs.
 * Supports: single event, multiple events, JSON array, CloudTrail Records bundle.
 */

import { parseCloudTrailInput } from "../parser/cloudtrail_parser";
import type { IngestionResult } from "../types";

/** Process an uploaded file - reads as text and parses */
export async function handleFileUpload(file: File): Promise<IngestionResult> {
  return new Promise((resolve) => {
    const reader = new FileReader();
    reader.onload = () => {
      const text = reader.result as string;
      const result = parseCloudTrailInput(text);
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
