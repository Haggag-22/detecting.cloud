import type { ParsedSigmaRule } from "../types";
import { matchToSentinelOnePredicate } from "../field";
import { renderCondition } from "./shared";

export function convertToSentinelOne(rule: ParsedSigmaRule): { query: string; warnings: string[] } {
  const warnings = [...rule.parseWarnings];
  const { expression, warnings: condWarn } = renderCondition(rule, matchToSentinelOnePredicate, {
    wrapNot: (inner) => `NOT (${inner})`,
  });
  warnings.push(...condWarn);

  warnings.push(
    "SentinelOne Deep Visibility query is best-effort — CloudTrail field names may need remapping to S1 cloud/endpoint schema"
  );
  return {
    query: expression === "true" ? "true" : expression,
    warnings,
  };
}
