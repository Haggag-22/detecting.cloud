/**
 * Rule field validation.
 * Validates that log events contain required fields before rule evaluation.
 */

import type { NormalizedEvent } from "./normalize";
import type { ParsedRule } from "./ruleTypes";

export interface FieldValidationResult {
  valid: boolean;
  missingFields: string[];
  presentFields: string[];
}

/**
 * Get nested value from object by dot path.
 */
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
 * Check if a field exists and has a non-empty value.
 */
function fieldExists(event: NormalizedEvent, field: string): boolean {
  const value = getNestedValue(event, field);
  if (value === undefined || value === null) return false;
  if (typeof value === "string" && value.trim() === "") return false;
  if (Array.isArray(value) && value.length === 0) return false;
  return true;
}

/**
 * Validate that an event has all required fields for a rule.
 */
export function validateRequiredFields(event: NormalizedEvent, rule: ParsedRule): FieldValidationResult {
  const missingFields: string[] = [];
  const presentFields: string[] = [];

  for (const field of rule.requiredFields) {
    if (fieldExists(event, field)) {
      presentFields.push(field);
    } else {
      missingFields.push(field);
    }
  }

  return {
    valid: missingFields.length === 0,
    missingFields,
    presentFields,
  };
}
