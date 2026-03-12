/**
 * Sigma rule evaluator.
 * Evaluates selections and filters against events, then evaluates the condition expression.
 */

import type { NormalizedEvent } from "./normalize";
import type { ParsedSigmaRule, SigmaSelection, SigmaFieldCondition } from "./sigmaParser";
import { evaluateCondition } from "./conditionInterpreter";

function getNestedValue(obj: unknown, path: string): unknown {
  if (obj == null) return undefined;
  const parts = path.split(".");
  let current: unknown = obj;
  for (const part of parts) {
    if (current == null || typeof current !== "object") return undefined;
    if (part.includes("{}")) {
      const [before, after] = part.split("{}");
      current = (current as Record<string, unknown>)[before];
      if (Array.isArray(current)) {
        const results = current.map((item) => getNestedValue(item, after || "")).filter((v) => v !== undefined);
        return results.length > 0 ? results : undefined;
      }
      current = getNestedValue(current, after || "");
    } else {
      current = (current as Record<string, unknown>)[part];
    }
  }
  return current;
}

/**
 * Evaluate a single field condition against an event.
 * Returns false if field is missing (required for accuracy).
 */
function evaluateFieldCondition(event: NormalizedEvent, cond: SigmaFieldCondition): boolean {
  const eventValue = getNestedValue(event, cond.field);

  if (cond.modifier === "contains") {
    if (eventValue == null) return false;
    const str = typeof eventValue === "string" ? eventValue : JSON.stringify(eventValue);
    return cond.values.some((v) => v && str.includes(v));
  }
  if (cond.modifier === "startswith") {
    if (eventValue == null) return false;
    const str = String(eventValue);
    return cond.values.some((v) => v && str.startsWith(v));
  }
  if (cond.modifier === "endswith") {
    if (eventValue == null) return false;
    const str = String(eventValue);
    return cond.values.some((v) => v && str.endsWith(v));
  }

  if (eventValue === undefined || eventValue === null) return false;

  if (cond.operator === "equals") {
    return cond.values.some((v) => String(eventValue) === v);
  }
  if (cond.operator === "in") {
    return cond.values.includes(String(eventValue));
  }
  return false;
}

/**
 * Evaluate a selection/filter block. All conditions in the block are ANDed.
 */
function evaluateSelection(event: NormalizedEvent, sel: SigmaSelection): boolean {
  if (sel.conditions.length === 0) return false;
  for (const cond of sel.conditions) {
    if (!evaluateFieldCondition(event, cond)) return false;
  }
  return true;
}

/**
 * Evaluate a Sigma rule against an event.
 * Returns true only if the full condition expression evaluates to true.
 */
export function evaluateSigmaRule(event: NormalizedEvent, rule: ParsedSigmaRule): boolean {
  const values: Record<string, boolean> = {};

  for (const sel of rule.selections) {
    values[sel.name] = evaluateSelection(event, sel);
  }
  for (const fil of rule.filters) {
    values[fil.name] = evaluateSelection(event, fil);
  }

  return evaluateCondition(rule.condition, values);
}

/**
 * Get which fields matched (for explanation).
 * Returns field-level details for the explanation UI.
 */
export function getSigmaMatchExplanation(
  event: NormalizedEvent,
  rule: ParsedSigmaRule
): Array<{ field: string; modifier?: string; expectedValues: string[]; actualValue: unknown; matched: boolean }> {
  const result: Array<{ field: string; modifier?: string; expectedValues: string[]; actualValue: unknown; matched: boolean }> = [];

  for (const sel of rule.selections) {
    for (const cond of sel.conditions) {
      const val = getNestedValue(event, cond.field);
      const matched = evaluateFieldCondition(event, cond);
      result.push({
        field: cond.field,
        modifier: cond.modifier,
        expectedValues: cond.values,
        actualValue: val,
        matched,
      });
    }
  }
  for (const fil of rule.filters) {
    for (const cond of fil.conditions) {
      const val = getNestedValue(event, cond.field);
      const matched = evaluateFieldCondition(event, cond);
      result.push({
        field: cond.field,
        modifier: cond.modifier,
        expectedValues: cond.values,
        actualValue: val,
        matched,
      });
    }
  }

  return result;
}
