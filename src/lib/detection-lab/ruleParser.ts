/**
 * Rule parser for detection rules.
 * Extracts conditions, required fields, and rule type from EventBridge, Sigma, and CloudTrail formats.
 */

import {
  type ParsedRule,
  type RuleCondition,
  EVENTBRIDGE_TO_CLOUDTRAIL_SOURCE,
} from "./ruleTypes";
import type { Detection } from "@/data/detections";

/**
 * Parse EventBridge pattern to extract strict conditions.
 * All conditions must match (AND logic).
 */
function parseEventBridgePattern(eb: Record<string, unknown>): ParsedRule {
  const conditions: RuleCondition[] = [];
  const requiredFields: string[] = ["eventSource", "eventName"];
  let expectedEventSource: string | undefined;
  let expectedEventNames: string[] | undefined;

  const detail = eb.detail as Record<string, unknown> | undefined;

  if (detail?.eventSource) {
    const esVal = detail.eventSource;
    const values = Array.isArray(esVal) ? esVal.map(String) : [String(esVal)];
    expectedEventSource = values[0];
    conditions.push({ field: "eventSource", operator: values.length === 1 ? "equals" : "in", values });
    requiredFields.push("eventSource");
  }
  if (!expectedEventSource) {
    const source = eb.source;
    if (Array.isArray(source) && source.length > 0) {
      const awsSource = String(source[0]);
      expectedEventSource = EVENTBRIDGE_TO_CLOUDTRAIL_SOURCE[awsSource] ?? awsSource.replace("aws.", "") + ".amazonaws.com";
      conditions.push({ field: "eventSource", operator: "equals", values: [expectedEventSource] });
      requiredFields.push("eventSource");
    }
  }

  if (detail) {
    for (const [key, patternValue] of Object.entries(detail)) {
      if (patternValue === undefined) continue;
      if (key === "eventSource") continue;
      if (key === "eventName") {
        const values = Array.isArray(patternValue)
          ? patternValue.map((v) => String(v))
          : [String(patternValue)];
        expectedEventNames = values;
        conditions.push({ field: "eventName", operator: "in", values });
        if (!requiredFields.includes("eventName")) requiredFields.push("eventName");
      } else {
        const values = Array.isArray(patternValue)
          ? patternValue.map((v) => String(v))
          : [String(patternValue)];
        conditions.push({ field: key, operator: Array.isArray(patternValue) ? "in" : "equals", values });
        requiredFields.push(key);
      }
    }
  }

  return {
    ruleType: "single_event",
    requiredFields: [...new Set(requiredFields)],
    conditions,
    expectedEventSource,
    expectedEventNames,
  };
}

/**
 * Extract eventSource and eventName from Sigma rule (strict extraction).
 */
function parseSigmaRule(sigma: string): ParsedRule {
  const conditions: RuleCondition[] = [];
  const requiredFields: string[] = [];

  const eventSourceMatch = sigma.match(/eventSource:\s*(['"]?)([\w.-]+)\1/);
  if (eventSourceMatch) {
    conditions.push({ field: "eventSource", operator: "equals", values: [eventSourceMatch[2]] });
    requiredFields.push("eventSource");
  }

  const eventNameMatch = sigma.match(/eventName:\s*(?:\[([^\]]+)\]|(['"]?)([\w.-]+)\2)/);
  if (eventNameMatch) {
    if (eventNameMatch[1]) {
      const names = eventNameMatch[1].split(",").map((s) => s.trim().replace(/^['"]|['"]$/g, ""));
      conditions.push({ field: "eventName", operator: "in", values: names });
    } else if (eventNameMatch[3]) {
      conditions.push({ field: "eventName", operator: "equals", values: [eventNameMatch[3]] });
    }
    requiredFields.push("eventName");
  }

  return {
    ruleType: "single_event",
    requiredFields: [...new Set(requiredFields)],
    conditions,
    expectedEventSource: conditions.find((c) => c.field === "eventSource")?.values[0],
    expectedEventNames: conditions.find((c) => c.field === "eventName")?.values,
  };
}

/**
 * Extract conditions from CloudTrail SQL-style rule.
 */
function parseCloudTrailRule(cloudtrail: string): ParsedRule {
  const conditions: RuleCondition[] = [];
  const requiredFields: string[] = [];

  const eventNameMatch = cloudtrail.match(/eventName\s*(?:=\s*['"]([^'"]+)['"]|IN\s*\(([^)]+)\))/i);
  if (eventNameMatch) {
    const names = eventNameMatch[1]
      ? [eventNameMatch[1]]
      : eventNameMatch[2].split(",").map((s) => s.trim().replace(/^['"]|['"]$/g, ""));
    conditions.push({ field: "eventName", operator: names.length === 1 ? "equals" : "in", values: names });
    requiredFields.push("eventName");
  }

  const eventSourceMatch = cloudtrail.match(/eventSource\s*=\s*['"]([^'"]+)['"]/i);
  if (eventSourceMatch) {
    conditions.push({ field: "eventSource", operator: "equals", values: [eventSourceMatch[1]] });
    requiredFields.push("eventSource");
  }

  return {
    ruleType: "single_event",
    requiredFields: [...new Set(requiredFields)],
    conditions,
    expectedEventSource: conditions.find((c) => c.field === "eventSource")?.values[0],
    expectedEventNames: conditions.find((c) => c.field === "eventName")?.values,
  };
}

/**
 * Parse a detection rule to extract conditions and metadata.
 */
export function parseRule(detection: Detection): ParsedRule | null {
  if (detection.rules.eventbridge) {
    try {
      const eb = JSON.parse(detection.rules.eventbridge) as Record<string, unknown>;
      return parseEventBridgePattern(eb);
    } catch {
      // fall through
    }
  }

  if (detection.rules.sigma) {
    return parseSigmaRule(detection.rules.sigma);
  }

  if (detection.rules.cloudtrail) {
    return parseCloudTrailRule(detection.rules.cloudtrail);
  }

  // Use telemetry metadata if available
  const telemetry = detection.telemetry;
  if (telemetry?.importantFields?.length) {
    return {
      ruleType: "single_event",
      requiredFields: telemetry.importantFields.slice(0, 5),
      conditions: [],
      expectedEventSource: undefined,
      expectedEventNames: undefined,
    };
  }

  return null;
}
