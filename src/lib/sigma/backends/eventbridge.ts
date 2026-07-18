import type { ParsedSigmaRule } from "../types";
import { extractSimpleEquals, normalizeFieldPath } from "../field";
import { collectAllMatches } from "./shared";

function serviceFromEventSource(eventSource: string): string {
  // lambda.amazonaws.com → aws.lambda
  const svc = eventSource.replace(/\.amazonaws\.com$/, "").split(".").pop() ?? "aws";
  return `aws.${svc}`;
}

/**
 * EventBridge can only express a subset of Sigma (mostly eventSource + eventName).
 * Nested requestParameters filters are noted as warnings.
 */
export function convertToEventBridge(rule: ParsedSigmaRule): { query: string; warnings: string[] } {
  const warnings = [...rule.parseWarnings];
  const matches = collectAllMatches(rule);

  const eventNames = extractSimpleEquals(matches, "eventName").map(String);
  const eventSources = extractSimpleEquals(matches, "eventSource").map(String);

  const otherFields = matches.filter((m) => {
    const f = normalizeFieldPath(m.field);
    return f !== "eventName" && f !== "eventSource";
  });

  if (otherFields.length > 0) {
    warnings.push(
      `EventBridge pattern only includes eventSource/eventName — ${otherFields.length} additional Sigma field condition(s) omitted (filter in the target or Lambda)`
    );
  }

  if (eventNames.length === 0 && eventSources.length === 0) {
    return {
      query: "",
      warnings: [
        ...warnings,
        "Cannot build EventBridge pattern: no eventName/eventSource equals matches found in Sigma",
      ],
    };
  }

  const source =
    eventSources.length > 0
      ? [...new Set(eventSources.map(serviceFromEventSource))]
      : ["aws.cloudtrail"];

  const detail: Record<string, unknown> = {};
  if (eventSources.length > 0) detail.eventSource = [...new Set(eventSources)];
  if (eventNames.length > 0) detail.eventName = [...new Set(eventNames)];

  const pattern = {
    source,
    "detail-type": ["AWS API Call via CloudTrail"],
    detail,
  };

  return { query: JSON.stringify(pattern, null, 2), warnings };
}
