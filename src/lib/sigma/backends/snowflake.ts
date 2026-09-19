import type { ParsedSigmaRule } from "../types";
import { matchToSqlPredicate } from "../field";
import { classifyLogsource, logsourceLabel } from "../logsource";
import { defaultOutputFields, renderCondition } from "./shared";

/**
 * Best-effort Snowflake SQL from Sigma.
 * Table name follows the Sigma logsource (CloudTrail, Azure, GCP, etc.).
 */
export function convertToSnowflake(rule: ParsedSigmaRule): { query: string; warnings: string[] } {
  const warnings = [...rule.parseWarnings];
  const mapping = classifyLogsource(rule);
  const { expression, warnings: condWarn } = renderCondition(rule, matchToSqlPredicate, {
    wrapNot: (inner) => `NOT (${inner})`,
  });
  warnings.push(...condWarn);

  const fields = defaultOutputFields(rule);
  const selectCols = [mapping.snowflakeTimeColumn, ...fields];

  const query = [
    `SELECT ${selectCols.join(", ")}`,
    `FROM ${mapping.snowflakeTable}`,
    `WHERE ${expression === "true" ? "1=1" : expression}`,
    `ORDER BY ${mapping.snowflakeTimeColumn} DESC`,
  ].join("\n");

  warnings.push(
    `Snowflake SQL from Sigma logsource (${logsourceLabel(mapping)}) assumes table ${mapping.snowflakeTable} — adjust VARIANT paths for your landing zone`
  );
  return { query, warnings };
}
