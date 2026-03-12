/**
 * Detection confidence scoring.
 * Base score increases when key fields match correctly.
 */

import type { NormalizedEvent } from "./normalize";
import type { ParsedRule } from "./ruleTypes";
import { getMatchedConditions } from "./strictEvaluator";

const BASE_SCORE = 20;
const EVENT_SOURCE_MATCH = 25;
const EVENT_NAME_MATCH = 25;
const ADDITIONAL_FIELD_MATCH = 10;
const MAX_SCORE = 100;

export interface ConfidenceResult {
  score: number;
  label: "strong" | "medium" | "low" | "possible_false_positive";
  breakdown: Array<{ field: string; matched: boolean; points: number }>;
}

/**
 * Calculate confidence score for a detection match.
 */
export function calculateConfidence(event: NormalizedEvent, rule: ParsedRule): ConfidenceResult {
  const matched = getMatchedConditions(event, rule);
  let score = BASE_SCORE;
  const breakdown: ConfidenceResult["breakdown"] = [];

  const eventSourceCond = rule.conditions.find((c) => c.field === "eventSource");
  const eventNameCond = rule.conditions.find((c) => c.field === "eventName");

  for (const { condition, matched: isMatched } of matched) {
    let points = 0;
    if (isMatched) {
      if (condition.field === "eventSource") {
        points = EVENT_SOURCE_MATCH;
      } else if (condition.field === "eventName") {
        points = EVENT_NAME_MATCH;
      } else {
        points = ADDITIONAL_FIELD_MATCH;
      }
      score += points;
    }
    breakdown.push({ field: condition.field, matched: isMatched, points });
  }

  score = Math.min(score, MAX_SCORE);

  let label: ConfidenceResult["label"];
  if (score >= 80) label = "strong";
  else if (score >= 60) label = "medium";
  else if (score >= 40) label = "low";
  else label = "possible_false_positive";

  return { score, label, breakdown };
}
