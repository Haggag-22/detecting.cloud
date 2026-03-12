/**
 * Strict rule matching engine.
 * All conditions must match (AND logic). No partial matching.
 */

import type { NormalizedEvent } from "./normalize";
import type { ParsedRule, RuleCondition } from "./ruleTypes";
import { validateRequiredFields } from "./fieldValidator";

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

function evaluateCondition(event: NormalizedEvent, cond: RuleCondition): boolean {
  const eventValue = getNestedValue(event, cond.field);

  switch (cond.operator) {
    case "equals":
      return cond.values.some((v) => String(eventValue) === v);
    case "in":
      return eventValue != null && cond.values.includes(String(eventValue));
    case "contains":
      if (typeof eventValue !== "string") return false;
      return cond.values.some((v) => eventValue.includes(v));
    case "exists":
      return eventValue !== undefined && eventValue !== null;
    default:
      return false;
  }
}

/**
 * Strict AND evaluation: ALL conditions must match.
 */
export function evaluateStrict(event: NormalizedEvent, rule: ParsedRule): boolean {
  if (rule.conditions.length === 0) return false;

  for (const cond of rule.conditions) {
    if (!evaluateCondition(event, cond)) {
      return false;
    }
  }
  return true;
}

/**
 * Get which conditions matched (for explanation).
 */
export function getMatchedConditions(event: NormalizedEvent, rule: ParsedRule): Array<{ condition: RuleCondition; matched: boolean; eventValue: unknown }> {
  return rule.conditions.map((cond) => ({
    condition: cond,
    matched: evaluateCondition(event, cond),
    eventValue: getNestedValue(event, cond.field),
  }));
}

export { validateRequiredFields };
