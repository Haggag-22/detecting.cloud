import type { ParsedSigmaRule } from "../types";
import { matchToDatadogClause } from "../field";
import { classifyLogsource, logsourceLabel } from "../logsource";
import { buildAst } from "./shared";
import { getSelectionMap } from "../condition";
import type { ConditionNode } from "../condition";
import type { SigmaSelection } from "../types";

function selectionToDd(sel: SigmaSelection | undefined, facetMap: Record<string, string>): string {
  if (!sel || sel.matches.length === 0) return "";
  return sel.matches.map((m) => matchToDatadogClause(m, facetMap)).join(" AND ");
}

function walkDd(
  node: ConditionNode,
  map: Map<string, SigmaSelection>,
  warnings: string[],
  facetMap: Record<string, string>
): string {
  switch (node.type) {
    case "ref": {
      const sel = map.get(node.name);
      if (!sel) {
        warnings.push(`Unknown selection '${node.name}' in condition`);
        return "";
      }
      return selectionToDd(sel, facetMap);
    }
    case "and": {
      const kids = node.children.map((c) => walkDd(c, map, warnings, facetMap)).filter(Boolean);
      return kids.length <= 1 ? kids[0] ?? "" : kids.map((k) => `(${k})`).join(" AND ");
    }
    case "or": {
      const kids = node.children.map((c) => walkDd(c, map, warnings, facetMap)).filter(Boolean);
      return kids.length <= 1 ? kids[0] ?? "" : `(${kids.join(" OR ")})`;
    }
    case "not": {
      const inner = walkDd(node.child, map, warnings, facetMap);
      return inner ? `-(${inner})` : "";
    }
    default:
      return "";
  }
}

/** Datadog `source:` from Sigma logsource — never assume CloudTrail. */
export function datadogSourceFromLogsource(rule: ParsedSigmaRule): string {
  return classifyLogsource(rule).datadogSource;
}

export function convertToDatadog(rule: ParsedSigmaRule): { query: string; warnings: string[] } {
  const warnings = [...rule.parseWarnings];
  const mapping = classifyLogsource(rule);
  const map = getSelectionMap(rule);
  const expr = walkDd(buildAst(rule), map, warnings, mapping.datadogFacetMap);
  const query = [mapping.datadogSource, expr].filter(Boolean).join(" ");

  warnings.push(
    `Datadog source derived from Sigma logsource (${logsourceLabel(mapping)}) — facet names vary by pipeline`
  );
  return { query, warnings };
}
