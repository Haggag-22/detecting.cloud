/**
 * File upload handler for CloudTrail logs.
 * Supports: single event, multiple events, JSON array, CloudTrail Records bundle,
 * and line-delimited JSON datasets.
 */

import { parseCloudTrailInput } from "../parser/cloudtrail_parser";
import type { IngestionResult } from "../types";

/** Max upload size for analyzer file ingestion (50MB). */
const MAX_UPLOAD_SIZE_BYTES = 50 * 1024 * 1024;

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
