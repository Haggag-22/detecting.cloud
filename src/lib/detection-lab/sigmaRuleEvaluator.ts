/**
 * Sigma rule evaluator - main entry for evaluating Sigma rules in the detection pipeline.
 * Integrates sigma parser, evaluator, and explanation.
 */

import type { NormalizedEvent } from "./normalize";
import type { Detection } from "@/data/detections";
import { parseSigmaRule } from "./sigmaParser";
import { evaluateSigmaRule, getSigmaMatchExplanation } from "./sigmaEvaluator";
import type { DetectionExplanation } from "./explanationEngine";

export interface SigmaEvalResult {
  matched: boolean;
  matchedEvents: NormalizedEvent[];
  explanation: DetectionExplanation;
  confidence: "high" | "medium" | "low";
}

/**
 * Evaluate a detection with Sigma rule against events.
 * Returns null if the detection has no Sigma rule or parsing fails.
 */
export function evaluateDetectionWithSigma(
  detection: Detection,
  events: NormalizedEvent[]
): SigmaEvalResult | null {
  if (!detection.rules.sigma) return null;

  const rule = parseSigmaRule(detection.rules.sigma);
  if (!rule) return null;
  if (!rule.condition) return null;

  const matchedEvents: NormalizedEvent[] = [];
  for (const event of events) {
    if (evaluateSigmaRule(event, rule)) {
      matchedEvents.push(event);
    }
  }

  if (matchedEvents.length === 0) return null;

  const firstEvent = matchedEvents[0];
  const explanationParts = getSigmaMatchExplanation(firstEvent, rule);
  const matchedParts = explanationParts.filter((p) => p.matched);
  const fieldMatches = explanationParts.map((p) => ({
    field: p.field + (p.modifier ? `|${p.modifier}` : ""),
    operator: p.modifier ?? "equals",
    expectedValues: p.expectedValues,
    actualValue: p.actualValue,
    matched: p.matched,
  }));

  const summary =
    matchedParts.length > 0
      ? `Rule triggered because ${matchedParts.map((p) => `${p.field}=${JSON.stringify(p.actualValue)}`).join(", ")} satisfied the rule condition.`
      : "Rule condition evaluated to true.";

  const confidence: SigmaEvalResult["confidence"] =
    rule.filters.length > 0 ? "high" : rule.selections.some((s) => s.conditions.length > 1) ? "medium" : "low";

  return {
    matched: true,
    matchedEvents,
    explanation: {
      detectionId: detection.id,
      detectionTitle: detection.title,
      fieldMatches,
      summary,
    },
    confidence,
  };
}
