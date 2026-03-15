/**
 * Error handling for CloudTrail ingestion.
 * Gracefully handles invalid JSON, malformed events, missing fields, large files.
 * Errors are captured and logged; the system does not crash.
 */

import type { IngestionError } from "../types";
import { logger } from "./logging";

/** Safely parse JSON, returning null on failure */
export function safeParseJson<T = unknown>(input: string): T | null {
  try {
    return JSON.parse(input) as T;
  } catch (e) {
    logger.warn("Invalid JSON", { error: String(e), preview: input.slice(0, 100) });
    return null;
  }
}

/** Create an ingestion error record */
export function createIngestionError(
  message: string,
  index?: number,
  raw?: string
): IngestionError {
  return { index, message, raw: raw ? raw.slice(0, 200) : undefined };
}

/** Wrap async operations to catch and log errors without throwing */
export async function safeAsync<T>(
  fn: () => Promise<T>,
  fallback: T,
  errorContext?: string
): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    logger.error(errorContext ?? "Async operation failed", { error: String(e) });
    return fallback;
  }
}
