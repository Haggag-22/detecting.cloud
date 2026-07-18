import type { ParsedSigmaRule } from "../types";
import { matchToSplunkExpr, normalizeFieldPath } from "../field";
import { collectAllMatches, defaultOutputFields, renderCondition } from "./shared";

export function convertToSplunk(rule: ParsedSigmaRule): { query: string; warnings: string[] } {
  const warnings = [...rule.parseWarnings];
  const allMatches = collectAllMatches(rule);

  // Pull eventName / eventSource into the base search for performance
  const eventNames = allMatches
    .filter((m) => normalizeFieldPath(m.field) === "eventName" && m.modifier === "equals")
    .flatMap((m) => m.values.map(String));
  const eventSources = allMatches
    .filter((m) => normalizeFieldPath(m.field) === "eventSource" && m.modifier === "equals")
    .flatMap((m) => m.values.map(String));

  const baseParts = ["index=aws", "sourcetype=aws:cloudtrail"];
  if (eventSources.length === 1) baseParts.push(`eventSource=${eventSources[0]}`);
  else if (eventSources.length > 1) {
    baseParts.push(`(${eventSources.map((s) => `eventSource=${s}`).join(" OR ")})`);
  }
  if (eventNames.length === 1) baseParts.push(`eventName=${eventNames[0]}`);
  else if (eventNames.length > 1) {
    baseParts.push(`(${eventNames.map((n) => `eventName=${n}`).join(" OR ")})`);
  }

  const { expression, warnings: condWarn } = renderCondition(rule, matchToSplunkExpr, {
    wrapNot: (inner) => `NOT (${inner})`,
  });
  warnings.push(...condWarn);

  // Drop trivial true; use where for complex remainder
  const fields = defaultOutputFields(rule);
  const tableFields = ["_time", ...fields.filter((f) => f !== "eventTime")];

  let query = baseParts.join(" ");
  if (expression && expression !== "true") {
    // If expression is already covered by base search alone, still add where for modifiers
    query += `\n| where ${expression}`;
  }
  query += `\n| table ${tableFields.join(", ")}`;

  warnings.push("Best-effort SPL from Sigma — validate field extractions for your sourcetype");
  return { query, warnings };
}
