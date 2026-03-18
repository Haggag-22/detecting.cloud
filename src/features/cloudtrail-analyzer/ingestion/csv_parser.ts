/**
 * CSV parser for CloudTrail events.
 * Supports the analyzer's export format: event_id, event_time, event_source, event_name,
 * aws_region, source_ip, principal_type, principal_arn.
 */

import type { RawCloudTrailEvent } from "../types";

/** Parse a single CSV line, respecting quoted fields */
function parseCsvLine(line: string): string[] {
  const result: string[] = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if ((c === "," && !inQuotes) || c === "\n" || c === "\r") {
      result.push(current.trim());
      current = "";
      if (c === "\n" || c === "\r") break;
    } else {
      current += c;
    }
  }
  result.push(current.trim());
  return result;
}

/** Map CSV row (object keyed by header) to RawCloudTrailEvent */
function rowToRawEvent(row: Record<string, string>, index: number): RawCloudTrailEvent {
  const eventId = row.event_id || row.eventID || `csv-${index}-${Date.now()}`;
  const principalType = row.principal_type || row["userIdentity.type"] || "";
  const principalArn = row.principal_arn || row["userIdentity.arn"] || row.userIdentity_arn || "";

  return {
    eventVersion: "1.08",
    eventID: eventId,
    eventTime: row.event_time || row.eventTime || "",
    eventSource: row.event_source || row.eventSource || "",
    eventName: row.event_name || row.eventName || "",
    awsRegion: row.aws_region || row.awsRegion || "",
    sourceIPAddress: row.source_ip || row.sourceIPAddress || "",
    userIdentity: {
      type: principalType || undefined,
      arn: principalArn || undefined,
    },
  };
}

/** Parse CSV text into RawCloudTrailEvent array */
export function parseCsvToCloudTrailEvents(text: string): RawCloudTrailEvent[] {
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (lines.length < 2) return [];

  const headerLine = lines[0];
  const headers = parseCsvLine(headerLine);
  const events: RawCloudTrailEvent[] = [];

  for (let i = 1; i < lines.length; i++) {
    const values = parseCsvLine(lines[i]);
    if (values.length === 0 || values.every((v) => !v)) continue;

    const row: Record<string, string> = {};
    headers.forEach((h, j) => {
      const key = h.trim();
      if (key) row[key] = values[j] ?? "";
    });
    events.push(rowToRawEvent(row, i - 1));
  }

  return events;
}
