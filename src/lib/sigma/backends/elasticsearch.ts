import type { ParsedSigmaRule } from "../types";
import { matchToEsqlPredicate } from "../field";
import { classifyLogsource, logsourceLabel } from "../logsource";
import { defaultOutputFields, renderCondition } from "./shared";

/** Convert Sigma → Elasticsearch ES|QL (default Elastic query dialect). */
export function convertToElasticsearch(rule: ParsedSigmaRule): { query: string; warnings: string[] } {
  const warnings = [...rule.parseWarnings];
  const mapping = classifyLogsource(rule);
  const { expression, warnings: condWarn } = renderCondition(rule, matchToEsqlPredicate, {
    wrapNot: (inner) => `NOT (${inner})`,
  });
  warnings.push(...condWarn);

  const fields = defaultOutputFields(rule);
  const keep = ["@timestamp", ...fields].slice(0, 10);

  const lines = [
    `FROM ${mapping.elasticsearchFrom}`,
    `| WHERE ${expression === "true" ? "true" : expression}`,
    `| KEEP ${keep.join(", ")}`,
    "| SORT @timestamp DESC",
  ];

  warnings.push(
    `Elasticsearch ES|QL data stream from Sigma logsource (${logsourceLabel(mapping)}); adjust field names to your integration mapping if needed`
  );
  return { query: lines.join("\n"), warnings };
}
