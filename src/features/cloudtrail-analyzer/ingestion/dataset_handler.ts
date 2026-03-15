/**
 * Dataset upload handler for large CloudTrail log files.
 * Processes event-by-event to avoid memory issues with thousands of events.
 * Uses the same parser which iterates sequentially.
 */

import { handleFileUpload } from "./file_upload_handler";
import type { IngestionResult } from "../types";

/** Max file size for dataset upload (50MB) - configurable */
const MAX_DATASET_SIZE_BYTES = 50 * 1024 * 1024;

/** Process a large dataset file. Same as file upload but with size validation. */
export async function handleDatasetUpload(file: File): Promise<IngestionResult> {
  if (file.size > MAX_DATASET_SIZE_BYTES) {
    return {
      parsed_events: [],
      valid_count: 0,
      malformed_count: 0,
      total_count: 0,
      errors: [
        {
          message: `File too large (${(file.size / 1024 / 1024).toFixed(1)}MB). Max ${MAX_DATASET_SIZE_BYTES / 1024 / 1024}MB.`,
        },
      ],
    };
  }

  return handleFileUpload(file);
}
