import type { ParsedSigmaRule } from "../types";
import { matchToQRadarPredicate } from "../field";
import { classifyLogsource, logsourceLabel } from "../logsource";
import { defaultOutputFields, renderCondition } from "./shared";

export function convertToQRadar(rule: ParsedSigmaRule): { query: string; warnings: string[] } {
  const warnings = [...rule.parseWarnings];
  const mapping = classifyLogsource(rule);
  const { expression, warnings: condWarn } = renderCondition(rule, matchToQRadarPredicate, {
    wrapNot: (inner) => `NOT (${inner})`,
  });
  warnings.push(...condWarn);

  const fields = defaultOutputFields(rule);
  const selectFields = [
    "UTF8(payload) AS event_payload",
    ...fields.map((f) => `"${f.replace(/"/g, '""')}"`),
  ];
  const whereParts = [mapping.qradarLogSourceFilter];
  if (expression && expression !== "true") whereParts.push(expression);

  const query = [
    `SELECT ${selectFields.join(", ")}`,
    "FROM events",
    `WHERE ${whereParts.join(" AND ")}`,
    "LAST 24 HOURS",
  ].join("\n");

  warnings.push(
    `QRadar AQL from Sigma logsource (${logsourceLabel(mapping)}) — custom properties / DSM mappings may differ from Sigma field names`
  );
  return { query, warnings };
}
