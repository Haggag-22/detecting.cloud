import type { ParsedSigmaRule } from "../types";
import { matchToCloudWatchFilter, normalizeFieldPath } from "../field";
import { collectAllMatches, defaultOutputFields, renderCondition } from "./shared";

export function convertToCloudWatch(rule: ParsedSigmaRule): { query: string; warnings: string[] } {
  const warnings = [...rule.parseWarnings];
  const { expression, warnings: condWarn } = renderCondition(rule, matchToCloudWatchFilter, {
    wrapNot: (inner) => `not (${inner})`,
  });
  warnings.push(...condWarn);

  const fields = ["@timestamp", ...defaultOutputFields(rule)].slice(0, 10);

  // Prefer discrete filter lines for simple equals when possible
  const all = collectAllMatches(rule);
  const simpleEquals = all.filter((m) => m.modifier === "equals" && m.values.length >= 1);
  const useStructured =
    expression.includes(" OR ") === false &&
    simpleEquals.length > 0 &&
    rule.selections.length <= 2;

  let query: string;
  if (useStructured && rule.condition.trim().toLowerCase() === "selection") {
    const filters = (rule.selections[0]?.matches ?? []).map((m) => {
      if (m.modifier === "equals" && m.values.length === 1) {
        const v = m.values[0];
        const f = normalizeFieldPath(m.field);
        if (typeof v === "boolean" || typeof v === "number") return `| filter ${f} = ${v}`;
        return `| filter ${f} = "${String(v).replace(/"/g, '\\"')}"`;
      }
      return `| filter ${matchToCloudWatchFilter(m)}`;
    });
    query = [`fields ${fields.join(", ")}`, ...filters, "| sort @timestamp desc"].join("\n");
  } else {
    query = [
      `fields ${fields.join(", ")}`,
      `| filter ${expression === "true" ? "true" : expression}`,
      "| sort @timestamp desc",
    ].join("\n");
  }

  warnings.push("CloudWatch Logs Insights syntax is approximate for nested CloudTrail JSON fields");
  return { query, warnings };
}
