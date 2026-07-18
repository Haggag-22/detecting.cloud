import type { ParsedSigmaRule } from "../types";
import { matchToDatadogClause } from "../field";
import { buildAst } from "./shared";
import { getSelectionMap } from "../condition";
import type { ConditionNode } from "../condition";
import type { SigmaSelection } from "../types";

function selectionToDd(sel: SigmaSelection | undefined): string {
  if (!sel || sel.matches.length === 0) return "";
  return sel.matches.map(matchToDatadogClause).join(" AND ");
}

function walkDd(node: ConditionNode, map: Map<string, SigmaSelection>, warnings: string[]): string {
  switch (node.type) {
    case "ref": {
      const sel = map.get(node.name);
      if (!sel) {
        warnings.push(`Unknown selection '${node.name}' in condition`);
        return "";
      }
      return selectionToDd(sel);
    }
    case "and": {
      const kids = node.children.map((c) => walkDd(c, map, warnings)).filter(Boolean);
      return kids.length <= 1 ? kids[0] ?? "" : kids.map((k) => `(${k})`).join(" AND ");
    }
    case "or": {
      const kids = node.children.map((c) => walkDd(c, map, warnings)).filter(Boolean);
      return kids.length <= 1 ? kids[0] ?? "" : `(${kids.join(" OR ")})`;
    }
    case "not": {
      const inner = walkDd(node.child, map, warnings);
      return inner ? `-(${inner})` : "";
    }
    default:
      return "";
  }
}

export function convertToDatadog(rule: ParsedSigmaRule): { query: string; warnings: string[] } {
  const warnings = [...rule.parseWarnings];
  const map = getSelectionMap(rule);
  const expr = walkDd(buildAst(rule), map, warnings);
  const query = ["source:cloudtrail", expr].filter(Boolean).join(" ");

  warnings.push(
    "Datadog facet names vary by pipeline — map @evt.name / nested requestParameters as needed"
  );
  return { query, warnings };
}
