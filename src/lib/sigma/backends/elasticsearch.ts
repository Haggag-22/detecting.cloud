import type { ParsedSigmaRule } from "../types";
import { matchToEsqlPredicate } from "../field";
import { defaultOutputFields, renderCondition } from "./shared";

/** Convert Sigma → Elasticsearch ES|QL (default Elastic query dialect). */
export function convertToElasticsearch(rule: ParsedSigmaRule): { query: string; warnings: string[] } {
  const warnings = [...rule.parseWarnings];
  const { expression, warnings: condWarn } = renderCondition(rule, matchToEsqlPredicate, {
    wrapNot: (inner) => `NOT (${inner})`,
  });
  warnings.push(...condWarn);

  const fields = defaultOutputFields(rule);
  const keep = ["@timestamp", ...fields].slice(0, 10);

  const lines = [
    "FROM logs-aws.cloudtrail-*",
    `| WHERE ${expression === "true" ? "true" : expression}`,
    `| KEEP ${keep.join(", ")}`,
    "| SORT @timestamp DESC",
  ];

  warnings.push(
    "Elasticsearch ES|QL assumes Elastic AWS CloudTrail integration field names; adjust the data stream if needed"
  );
  return { query: lines.join("\n"), warnings };
}
