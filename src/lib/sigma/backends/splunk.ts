import type { ParsedSigmaRule } from "../types";
import { matchToSplunkExpr, normalizeFieldPath } from "../field";
import { classifyLogsource, logsourceLabel } from "../logsource";
import { collectAllMatches, defaultOutputFields, renderCondition } from "./shared";

function splunkToken(value: string): string {
  return /^[A-Za-z0-9._-]+$/.test(value) ? value : `"${value.replace(/"/g, '\\"')}"`;
}

export function convertToSplunk(rule: ParsedSigmaRule): { query: string; warnings: string[] } {
  const warnings = [...rule.parseWarnings];
  const mapping = classifyLogsource(rule);
  const allMatches = collectAllMatches(rule);

  const baseParts = [`index=${mapping.splunkIndex}`, `sourcetype=${mapping.splunkSourcetype}`];
  for (const field of mapping.splunkBaseFields) {
    const values = allMatches
      .filter((m) => normalizeFieldPath(m.field) === field && m.modifier === "equals")
      .flatMap((m) => m.values.map(String));
    if (values.length === 1) {
      baseParts.push(`${field}=${splunkToken(values[0])}`);
    } else if (values.length > 1) {
      baseParts.push(`(${values.map((v) => `${field}=${splunkToken(v)}`).join(" OR ")})`);
    }
  }

  const { expression, warnings: condWarn } = renderCondition(rule, matchToSplunkExpr, {
    wrapNot: (inner) => `NOT (${inner})`,
  });
  warnings.push(...condWarn);

  const fields = defaultOutputFields(rule);
  const tableFields = ["_time", ...fields];

  let query = baseParts.join(" ");
  if (expression && expression !== "true") {
    query += `\n| where ${expression}`;
  }
  query += `\n| table ${tableFields.join(", ")}`;

  warnings.push(
    `Splunk SPL from Sigma logsource (${logsourceLabel(mapping)}) — validate field extractions for sourcetype=${mapping.splunkSourcetype}`
  );
  return { query, warnings };
}
