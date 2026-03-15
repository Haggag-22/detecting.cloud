/**
 * Logging utilities for CloudTrail ingestion pipeline.
 * Errors are logged but do not crash the system.
 */

export type LogLevel = "debug" | "info" | "warn" | "error";

const LOG_PREFIX = "[CloudTrailIngestion]";

export function log(level: LogLevel, message: string, data?: unknown): void {
  const timestamp = new Date().toISOString();
  const payload = data !== undefined ? ` ${JSON.stringify(data)}` : "";
  const line = `${timestamp} ${LOG_PREFIX} [${level.toUpperCase()}] ${message}${payload}`;

  switch (level) {
    case "debug":
      if (import.meta.env.DEV) console.debug(line);
      break;
    case "info":
      console.info(line);
      break;
    case "warn":
      console.warn(line);
      break;
    case "error":
      console.error(line);
      break;
  }
}

export const logger = {
  debug: (msg: string, data?: unknown) => log("debug", msg, data),
  info: (msg: string, data?: unknown) => log("info", msg, data),
  warn: (msg: string, data?: unknown) => log("warn", msg, data),
  error: (msg: string, data?: unknown) => log("error", msg, data),
};
