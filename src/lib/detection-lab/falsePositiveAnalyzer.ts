/**
 * False Positive Analyzer.
 * Inspects triggered detections for likely false positives and rule misconfigurations.
 */

import type { NormalizedEvent } from "./normalize";
import type { ParsedRule } from "./ruleTypes";
import { validateRequiredFields } from "./fieldValidator";

export type FPAnalysisResult = "valid" | "possible_false_positive" | "rule_misconfigured";

export interface FalsePositiveFinding {
  detectionId: string;
  detectionTitle: string;
  result: FPAnalysisResult;
  reason: string;
  expectedValue?: string;
  actualValue?: string;
  eventIndex?: number;
}

/**
 * Analyze a detection match for false positive indicators.
 */
export function analyzeFalsePositive(
  detectionId: string,
  detectionTitle: string,
  event: NormalizedEvent,
  rule: ParsedRule,
  totalEvents: number,
  ruleType: string
): FalsePositiveFinding | null {
  // Sequence rule firing on single event = misconfigured
  if (ruleType === "sequence" && totalEvents < 2) {
    return {
      detectionId,
      detectionTitle,
      result: "rule_misconfigured",
      reason: "Sequence rule requires multiple events but only one event was present",
    };
  }

  // eventSource mismatch: rule expects X but log has Y
  if (rule.expectedEventSource && event.eventSource) {
    if (event.eventSource !== rule.expectedEventSource) {
      return {
        detectionId,
        detectionTitle,
        result: "possible_false_positive",
        reason: "eventSource mismatch",
        expectedValue: rule.expectedEventSource,
        actualValue: event.eventSource,
      };
    }
  }

  // eventName mismatch
  if (rule.expectedEventNames?.length && event.eventName) {
    if (!rule.expectedEventNames.includes(event.eventName)) {
      return {
        detectionId,
        detectionTitle,
        result: "possible_false_positive",
        reason: "eventName mismatch",
        expectedValue: rule.expectedEventNames.join(" or "),
        actualValue: event.eventName,
      };
    }
  }

  // Missing required fields but rule still fired (shouldn't happen with strict eval, but check)
  const validation = validateRequiredFields(event, rule);
  if (!validation.valid && validation.missingFields.length > 0) {
    return {
      detectionId,
      detectionTitle,
      result: "rule_misconfigured",
      reason: `Required fields missing: ${validation.missingFields.join(", ")}`,
    };
  }

  return null;
}

export interface FalsePositiveReport {
  validDetections: number;
  possibleFalsePositives: number;
  misconfiguredRules: number;
  findings: FalsePositiveFinding[];
}

/**
 * Build a summary report from analysis results.
 */
export function buildFalsePositiveReport(findings: FalsePositiveFinding[]): FalsePositiveReport {
  const valid = findings.filter((f) => f.result === "valid").length;
  const possibleFP = findings.filter((f) => f.result === "possible_false_positive").length;
  const misconfigured = findings.filter((f) => f.result === "rule_misconfigured").length;

  return {
    validDetections: findings.length - possibleFP - misconfigured,
    possibleFalsePositives: possibleFP,
    misconfiguredRules: misconfigured,
    findings,
  };
}
