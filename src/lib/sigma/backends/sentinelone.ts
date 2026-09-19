import type { ParsedSigmaRule } from "../types";
import { matchToSentinelOnePredicate } from "../field";
import { renderCondition } from "./shared";

export function convertToSentinelOne(rule: ParsedSigmaRule): { query: string; warnings: string[] } {
  const warnings = [...rule.parseWarnings];
  const { expression, warnings: condWarn } = renderCondition(rule, matchToSentinelOnePredicate, {
    wrapNot: (inner) => `NOT (${inner})`,
  });
  warnings.push(...condWarn);

  const product = rule.logsource?.product ?? "aws";
  const service = rule.logsource?.service ?? (product === "aws" ? "cloudtrail" : "");
  warnings.push(
    `SentinelOne query from Sigma logsource (${product}${service ? `/${service}` : ""}) — remap fields to the S1 cloud/endpoint schema`
  );
  return {
    query: expression === "true" ? "true" : expression,
    warnings,
  };
}
