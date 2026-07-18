import type { ConditionNode } from "../condition";
import { getSelectionMap } from "../condition";
import type { ParsedSigmaRule, SigmaSelection } from "../types";
import { matchToCrowdStrikeClause } from "../field";
import { buildAst } from "./shared";

function selectionToCs(sel: SigmaSelection | undefined): string {
  if (!sel || sel.matches.length === 0) return "";
  return sel.matches.map(matchToCrowdStrikeClause).join(" ");
}

function walkCs(node: ConditionNode, map: Map<string, SigmaSelection>, warnings: string[]): string {
  switch (node.type) {
    case "ref": {
      const sel = map.get(node.name);
      if (!sel) {
        warnings.push(`Unknown selection '${node.name}' in condition`);
        return "";
      }
      return selectionToCs(sel);
    }
    case "and": {
      const kids = node.children.map((c) => walkCs(c, map, warnings)).filter(Boolean);
      return kids.join(" ");
    }
    case "or": {
      const kids = node.children.map((c) => walkCs(c, map, warnings)).filter(Boolean);
      return kids.length <= 1 ? kids[0] ?? "" : `(${kids.join(" OR ")})`;
    }
    case "not": {
      const inner = walkCs(node.child, map, warnings);
      return inner ? `NOT ${inner}` : "";
    }
    default:
      return "";
  }
}

export function convertToCrowdStrike(rule: ParsedSigmaRule): { query: string; warnings: string[] } {
  const warnings = [...rule.parseWarnings];
  const map = getSelectionMap(rule);
  const query = walkCs(buildAst(rule), map, warnings);

  warnings.push(
    "CrowdStrike LogScale/CQL is best-effort for CloudTrail-style fields — Falcon endpoint pipelines use different field names"
  );
  return { query: query || "*", warnings };
}
