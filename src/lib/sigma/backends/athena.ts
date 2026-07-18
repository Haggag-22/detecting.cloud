import type { ParsedSigmaRule } from "../types";
import { matchToSqlPredicate } from "../field";
import { defaultOutputFields, renderCondition } from "./shared";

export function convertToAthena(rule: ParsedSigmaRule): { query: string; warnings: string[] } {
  const warnings = [...rule.parseWarnings];
  const { expression, warnings: condWarn } = renderCondition(rule, matchToSqlPredicate, {
    wrapNot: (inner) => `NOT (${inner})`,
  });
  warnings.push(...condWarn);

  const fields = defaultOutputFields(rule);
  const selectCols = ["eventTime", ...fields.filter((f) => f !== "eventTime")];

  const query = [
    `SELECT ${selectCols.join(", ")}`,
    "FROM cloudtrail_logs",
    `WHERE ${expression === "true" ? "1=1" : expression}`,
    "ORDER BY eventTime DESC",
  ].join("\n");

  warnings.push("Athena SQL assumes a cloudtrail_logs table with JSON-projected columns");
  return { query, warnings };
}
