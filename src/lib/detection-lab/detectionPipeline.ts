/**
 * Detection pipeline - orchestrates rule evaluation, validation, scoring, and analysis.
 * Professional detection engineering workbench pipeline.
 */

import type { NormalizedEvent } from "./normalize";
import type { Detection } from "@/data/detections";
import { parseRule } from "./ruleParser";
import { evaluateStrict, validateRequiredFields } from "./strictEvaluator";
import { calculateConfidence } from "./confidenceScorer";
import { analyzeFalsePositive, type FalsePositiveFinding } from "./falsePositiveAnalyzer";
import { deduplicateDetections } from "./deduplication";
import { explainDetection, type DetectionExplanation } from "./explanationEngine";
import type { RuleType } from "./ruleTypes";
import { evaluateDetectionWithSigma } from "./sigmaRuleEvaluator";

export interface RuleEvaluationStatus {
  skipped: boolean;
  reason?: "no_parsable_rule" | "missing_required_fields" | "sequence_requires_multiple_events";
}

export interface DetectionMatch {
  detection: Detection;
  matchedEvents: NormalizedEvent[];
  confidenceScore: number;
  confidenceLabel: string;
  fpFinding: FalsePositiveFinding | null;
  explanation: DetectionExplanation;
  evaluationStatus: RuleEvaluationStatus;
}

export interface PipelineResult {
  validDetections: number;
  possibleFalsePositives: number;
  misconfiguredRules: number;
  matches: DetectionMatch[];
  deduplicated: ReturnType<typeof deduplicateDetections>;
  totalEvents: number;
  rulesEvaluated: number;
  rulesSkipped: number;
}

/**
 * Get rule type for a detection (default: single_event).
 */
function getRuleType(detection: Detection): RuleType {
  return "single_event";
}

/**
 * Run the full detection pipeline.
 */
export function runDetectionPipeline(
  detections: Detection[],
  events: NormalizedEvent[]
): PipelineResult {
  const matches: DetectionMatch[] = [];
  let rulesSkipped = 0;

  for (const detection of detections) {
    const ruleType = getRuleType(detection);

    // Prefer Sigma rule evaluation when available (full selection/filter/condition logic)
    const sigmaResult = evaluateDetectionWithSigma(detection, events);
    if (sigmaResult) {
      matches.push({
        detection,
        matchedEvents: sigmaResult.matchedEvents,
        confidenceScore: sigmaResult.confidence === "high" ? 85 : sigmaResult.confidence === "medium" ? 70 : 55,
        confidenceLabel: sigmaResult.confidence,
        fpFinding: null,
        explanation: sigmaResult.explanation,
        evaluationStatus: { skipped: false },
      });
      continue;
    }

    // Fallback: EventBridge/CloudTrail rule evaluation
    const parsed = parseRule(detection);
    if (!parsed) {
      rulesSkipped++;
      continue;
    }

    if (ruleType === "sequence" && events.length < 2) {
      rulesSkipped++;
      continue;
    }

    const matchedEvents: NormalizedEvent[] = [];

    for (const event of events) {
      const validation = validateRequiredFields(event, parsed);
      if (!validation.valid) continue;
      if (evaluateStrict(event, parsed)) matchedEvents.push(event);
    }

    if (matchedEvents.length === 0) continue;

    const firstEvent = matchedEvents[0];
    const confidence = calculateConfidence(firstEvent, parsed);
    const fpFinding = analyzeFalsePositive(
      detection.id,
      detection.title,
      firstEvent,
      parsed,
      events.length,
      ruleType
    );
    const explanation = explainDetection(detection.id, detection.title, firstEvent, parsed);

    matches.push({
      detection,
      matchedEvents,
      confidenceScore: confidence.score,
      confidenceLabel: confidence.label,
      fpFinding,
      explanation,
      evaluationStatus: { skipped: false },
    });
  }

  const validDetectionsCount = matches.filter((m) => !m.fpFinding && m.matchedEvents.length > 0).length;
  const possibleFPCount = matches.filter((m) => m.fpFinding?.result === "possible_false_positive").length;
  const misconfiguredCount = matches.filter((m) => m.fpFinding?.result === "rule_misconfigured").length;

  const confidenceScores: Record<string, number> = {};
  for (const m of matches) {
    if (!m.fpFinding || m.fpFinding.result !== "rule_misconfigured") {
      confidenceScores[m.detection.id] = m.confidenceScore;
    }
  }

  const deduplicated = deduplicateDetections(
    detections,
    matches.filter((m) => !m.evaluationStatus.skipped && m.matchedEvents.length > 0).map((m) => m.detection.id),
    confidenceScores
  );

  return {
    validDetections: validDetectionsCount,
    possibleFalsePositives: possibleFPCount,
    misconfiguredRules: misconfiguredCount,
    matches,
    deduplicated,
    totalEvents: events.length,
    rulesEvaluated: detections.length,
    rulesSkipped,
  };
}
