/**
 * Heuristic detection matcher for CloudTrail events.
 * Extracts eventName, eventSource, and simple conditions from Sigma YAML
 * and matches against normalized events.
 */

import type { NormalizedCloudTrailEvent } from "../types";
import type { Detection } from "@/data/detections";
import { detections } from "@/data/detections";

export interface MatchResult {
  detectionId: string;
  title: string;
  severity: string;
}

/** Extract eventName values from Sigma YAML or EventBridge JSON */
function extractEventNamesFromDetection(detection: Detection): string[] {
  const names: string[] = [];
  const sigma = detection.rules?.sigma ?? "";
  const eventbridge = detection.rules?.eventbridge ?? "";

  const sigmaSingle = sigma.match(/eventName:\s*(\w+)(?:\s|$)/);
  if (sigmaSingle) names.push(sigmaSingle[1]);
  const sigmaList = sigma.matchAll(/-\s+(\w+)\s*$/gm);
  for (const m of sigmaList) names.push(m[1]);

  try {
    const eb = JSON.parse(eventbridge) as { detail?: { eventName?: string | string[] } };
    const en = eb?.detail?.eventName;
    if (Array.isArray(en)) names.push(...en);
    else if (typeof en === "string") names.push(en);
  } catch {
    // ignore parse errors
  }
  return [...new Set(names.filter(Boolean))];
}

/** Extract contains conditions: field|contains: 'value' */
function extractContainsConditions(sigma: string): Array<{ path: string; value: string }> {
  const conditions: Array<{ path: string; value: string }> = [];
  const regex = /(\w+(?:\.\w+)*(?:\|\w+)?)\s*:\s*['"]([^'"]+)['"]/g;
  let m;
  while ((m = regex.exec(sigma)) !== null) {
    const path = m[1];
    const value = m[2];
    if (path.includes("contains") || path.includes("|")) {
      const basePath = path.replace(/\|.*$/, "");
      conditions.push({ path: basePath, value });
    } else if (path.includes(".") && !path.includes("eventName") && !path.includes("eventSource")) {
      conditions.push({ path, value });
    }
  }
  const containsRegex = /(\S+)\|contains:\s*['"]([^'"]+)['"]/g;
  while ((m = containsRegex.exec(sigma)) !== null) {
    conditions.push({ path: m[1].trim(), value: m[2] });
  }
  return conditions;
}

/** Get nested value from object by path (e.g. requestParameters.role) */
function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split(".");
  let current: unknown = obj;
  for (const p of parts) {
    if (current == null || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[p];
  }
  return current;
}

/** Check if event matches a detection's Sigma rule heuristically */
function eventMatchesDetection(event: NormalizedCloudTrailEvent, detection: Detection): boolean {
  const sigma = detection.rules?.sigma ?? "";
  const eventNames = extractEventNamesFromDetection(detection);
  if (eventNames.length > 0) {
    const nameMatch = eventNames.some(
      (n) => event.event_name === n || event.event_name.startsWith(n) || n.startsWith(event.event_name)
    );
    if (!nameMatch) return false;
  } else {
    return false;
  }

  const generatingService = detection.telemetry?.generatingService;
  if (generatingService && event.event_source && event.event_source !== generatingService) {
    const serviceMap: Record<string, string> = {
      IAM: "iam.amazonaws.com",
      Lambda: "lambda.amazonaws.com",
      EC2: "ec2.amazonaws.com",
      S3: "s3.amazonaws.com",
      STS: "sts.amazonaws.com",
    };
    const alt = serviceMap[detection.awsService];
    const allowed = [generatingService];
    if (alt) allowed.push(alt);
    if (!allowed.includes(event.event_source)) return false;
  }

  const containsConditions = extractContainsConditions(sigma);
  const raw = event._raw ?? {};
  const requestParams = (event.request_parameters ?? raw.requestParameters ?? {}) as Record<string, unknown>;

  for (const { path, value } of containsConditions) {
    const normalizedPath = path.replace(/\.\|contains$/, "");
    const fieldVal = getNestedValue(requestParams, normalizedPath) ?? getNestedValue(raw as Record<string, unknown>, path);
    const strVal = String(fieldVal ?? "");
    if (!strVal.toLowerCase().includes(value.toLowerCase())) {
      return false;
    }
  }

  if (sigma.includes("condition: selection and not filter")) {
    const filterMatch = sigma.match(/filter:\s*\n\s*userIdentity\.principalId\|contains:\s*\n\s+-\s+'([^']+)'/);
    if (filterMatch) {
      const exclude = filterMatch[1];
      const principalId = (raw.userIdentity as Record<string, unknown>)?.principalId ?? "";
      if (String(principalId).toLowerCase().includes(exclude.toLowerCase())) {
        return false;
      }
    }
  }

  return true;
}

/** Match a single event against all platform detections */
export function matchEventAgainstDetections(event: NormalizedCloudTrailEvent): MatchResult[] {
  const matches: MatchResult[] = [];
  for (const det of detections) {
    if (eventMatchesDetection(event, det)) {
      matches.push({
        detectionId: det.id,
        title: det.title,
        severity: det.severity,
      });
    }
  }
  return matches;
}

/** Match all events and return a map of event_id -> MatchResult[] */
export function matchEventsAgainstDetections(
  events: NormalizedCloudTrailEvent[]
): Map<string, MatchResult[]> {
  const map = new Map<string, MatchResult[]>();
  for (const ev of events) {
    map.set(ev.event_id, matchEventAgainstDetections(ev));
  }
  return map;
}
