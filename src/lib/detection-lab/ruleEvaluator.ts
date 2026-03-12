/**
 * Rule evaluator for Detection Lab.
 * Evaluates detection rules against normalized CloudTrail events.
 * Uses EventBridge pattern matching when available; falls back to eventSource/eventName pattern extraction.
 */

import type { NormalizedEvent } from "./normalize";
import type { Detection } from "@/data/detections";

export interface RuleMatchResult {
  detectionId: string;
  detectionTitle: string;
  severity: string;
  matched: boolean;
  matchedEvents: NormalizedEvent[];
  confidence: "high" | "medium" | "low";
}

/**
 * EventBridge pattern structure (from CloudTrail integration).
 */
interface EventBridgePattern {
  source?: string[];
  "detail-type"?: string[];
  detail?: Record<string, unknown>;
}

/**
 * Check if a normalized event matches an EventBridge rule pattern.
 */
function eventMatchesEventBridgePattern(event: NormalizedEvent, pattern: EventBridgePattern): boolean {
  if (!pattern.detail) return false;

  for (const [key, patternValue] of Object.entries(pattern.detail)) {
    const eventValue = getNestedValue(event, key);

    if (patternValue === undefined) continue;

    if (Array.isArray(patternValue)) {
      if (eventValue == null) return false;
      const strVal = String(eventValue);
      if (!patternValue.some((p) => String(p) === strVal)) return false;
    } else if (typeof patternValue === "object") {
      if (eventValue == null) return false;
      if (!eventMatchesEventBridgePattern(eventValue as NormalizedEvent, { detail: patternValue as Record<string, unknown> })) return false;
    } else {
      if (String(eventValue) !== String(patternValue)) return false;
    }
  }
  return true;
}

function getNestedValue(obj: unknown, path: string): unknown {
  if (obj == null) return undefined;
  const parts = path.split(".");
  let current: unknown = obj;
  for (const part of parts) {
    if (current == null || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

/**
 * Extract eventSource and eventName from Sigma rule (simple heuristic).
 */
function extractSigmaPatterns(sigmaRule: string): { eventSource?: string[]; eventName?: string[] } {
  const result: { eventSource?: string[]; eventName?: string[] } = {};
  const eventSourceMatch = sigmaRule.match(/eventSource:\s*(['"]?)([\w.-]+)\1/);
  if (eventSourceMatch) {
    result.eventSource = [eventSourceMatch[2]];
  }
  const eventNameMatch = sigmaRule.match(/eventName:\s*(?:\[([^\]]+)\]|(['"]?)([\w.-]+)\2)/);
  if (eventNameMatch) {
    if (eventNameMatch[1]) {
      result.eventName = eventNameMatch[1].split(",").map((s) => s.trim().replace(/^['"]|['"]$/g, ""));
    } else if (eventNameMatch[3]) {
      result.eventName = [eventNameMatch[3]];
    }
  }
  return result;
}

/**
 * Check if event matches Sigma-derived patterns.
 */
function eventMatchesSigmaPatterns(event: NormalizedEvent, patterns: { eventSource?: string[]; eventName?: string[] }): boolean {
  if (patterns.eventSource) {
    const es = event.eventSource ?? "";
    if (!patterns.eventSource.some((p) => es.includes(p) || p.includes(es))) return false;
  }
  if (patterns.eventName) {
    const en = event.eventName ?? "";
    if (!patterns.eventName.some((p) => en.includes(p) || p.includes(en))) return false;
  }
  return true;
}

/**
 * Evaluate a single detection rule against events.
 */
export function evaluateRule(detection: Detection, events: NormalizedEvent[]): RuleMatchResult {
  const matchedEvents: NormalizedEvent[] = [];

  // Prefer EventBridge pattern (most structured)
  if (detection.rules.eventbridge) {
    try {
      const pattern = JSON.parse(detection.rules.eventbridge) as EventBridgePattern;
      for (const evt of events) {
        if (eventMatchesEventBridgePattern(evt, pattern)) {
          matchedEvents.push(evt);
        }
      }
    } catch {
      // Fall through to Sigma
    }
  }

  // Fallback: Sigma pattern extraction
  if (matchedEvents.length === 0 && detection.rules.sigma) {
    const patterns = extractSigmaPatterns(detection.rules.sigma);
    if (patterns.eventSource || patterns.eventName) {
      for (const evt of events) {
        if (eventMatchesSigmaPatterns(evt, patterns)) {
          matchedEvents.push(evt);
        }
      }
    }
  }

  if (matchedEvents.length === 0 && (detection.rules.eventbridge || detection.rules.sigma)) {
    // Last resort: try matching eventSource/eventName from CloudTrail rule
    const cloudtrail = detection.rules.cloudtrail;
    if (cloudtrail) {
      const eventSourceMatch = cloudtrail.match(/eventSource\s*=\s*['"]([^'"]+)['"]/);
      const eventNameMatch = cloudtrail.match(/eventName\s*(?:=\s*['"]([^'"]+)['"]|IN\s*\(([^)]+)\))/);
      const source = eventSourceMatch?.[1];
      const names = eventNameMatch?.[1]
        ? [eventNameMatch[1]]
        : eventNameMatch?.[2]
          ? eventNameMatch[2].split(",").map((s) => s.trim().replace(/^['"]|['"]$/g, ""))
          : [];

      for (const evt of events) {
        if (source && evt.eventSource !== source) continue;
        if (names.length > 0 && !names.includes(evt.eventName ?? "")) continue;
        matchedEvents.push(evt);
      }
    }
  }

  const confidence: RuleMatchResult["confidence"] =
    matchedEvents.length > 0
      ? detection.rules.eventbridge
        ? "high"
        : "medium"
      : "low";

  return {
    detectionId: detection.id,
    detectionTitle: detection.title,
    severity: detection.severity,
    matched: matchedEvents.length > 0,
    matchedEvents,
    confidence,
  };
}

/**
 * Evaluate multiple detection rules against events.
 */
export function evaluateRules(detections: Detection[], events: NormalizedEvent[]): RuleMatchResult[] {
  return detections.map((d) => evaluateRule(d, events));
}
