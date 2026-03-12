/**
 * Detection Explanation Engine.
 * Explains why a rule matched by showing which fields and values triggered the detection.
 */

import type { NormalizedEvent } from "./normalize";
import type { ParsedRule, RuleCondition } from "./ruleTypes";
import { getMatchedConditions } from "./strictEvaluator";

export interface FieldMatch {
  field: string;
  operator: string;
  expectedValues: string[];
  actualValue: unknown;
  matched: boolean;
}

export interface DetectionExplanation {
  detectionId: string;
  detectionTitle: string;
  fieldMatches: FieldMatch[];
  summary: string;
}

/**
 * Generate human-readable explanation for why a rule matched.
 */
export function explainDetection(
  detectionId: string,
  detectionTitle: string,
  event: NormalizedEvent,
  rule: ParsedRule
): DetectionExplanation {
  const matched = getMatchedConditions(event, rule);
  const fieldMatches: FieldMatch[] = matched.map(({ condition, matched: isMatched, eventValue }) => ({
    field: condition.field,
    operator: condition.operator,
    expectedValues: condition.values,
    actualValue: eventValue,
    matched: isMatched,
  }));

  const matchedFields = fieldMatches.filter((m) => m.matched);
  const summary =
    matchedFields.length > 0
      ? `Rule matched because ${matchedFields.map((m) => `${m.field}=${JSON.stringify(m.actualValue)}`).join(", ")} satisfied the rule conditions.`
      : "No conditions matched.";

  return {
    detectionId,
    detectionTitle,
    fieldMatches,
    summary,
  };
}
