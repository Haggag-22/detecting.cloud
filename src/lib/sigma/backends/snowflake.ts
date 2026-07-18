import type { ParsedSigmaRule } from "../types";
import { matchToSqlPredicate } from "../field";
import { defaultOutputFields, renderCondition } from "./shared";

/**
 * Best-effort Snowflake SQL from Sigma.
 * Assumes a CloudTrail-like VARIANT/flat table named cloudtrail_logs.
 */
export function convertToSnowflake(rule: ParsedSigmaRule): { query: string; warnings: string[] } {
  const warnings = [...rule.parseWarnings];
  const { expression, warnings: condWarn } = renderCondition(rule, matchToSqlPredicate, {
    wrapNot: (inner) => `NOT (${inner})`,
  });
  warnings.push(...condWarn);

  const fields = defaultOutputFields(rule);
  const selectCols = ["event_time", ...fields.filter((f) => f !== "eventTime")];

  const query = [
    `SELECT ${selectCols.join(", ")}`,
    "FROM cloudtrail_logs",
    `WHERE ${expression === "true" ? "1=1" : expression}`,
    "ORDER BY event_time DESC",
  ].join("\n");

  warnings.push(
    "Snowflake SQL assumes a cloudtrail_logs table with projected columns — adjust VARIANT paths (e.g. RECORD_CONTENT:eventName) for your landing zone"
  );
  return { query, warnings };
}
