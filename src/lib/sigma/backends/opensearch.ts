import type { ConditionNode } from "../condition";
import { getSelectionMap } from "../condition";
import type { ParsedSigmaRule, SigmaSelection } from "../types";
import { matchToLuceneClause } from "../field";
import { buildAst } from "./shared";

function selectionToLucene(sel: SigmaSelection | undefined): string {
  if (!sel || sel.matches.length === 0) return "";
  return sel.matches.map(matchToLuceneClause).join(" AND ");
}

function walkLucene(
  node: ConditionNode,
  map: Map<string, SigmaSelection>,
  warnings: string[]
): string {
  switch (node.type) {
    case "ref": {
      const sel = map.get(node.name);
      if (!sel) {
        warnings.push(`Unknown selection '${node.name}' in condition`);
        return "";
      }
      return selectionToLucene(sel);
    }
    case "and": {
      const kids = node.children.map((c) => walkLucene(c, map, warnings)).filter(Boolean);
      return kids.length <= 1 ? kids[0] ?? "" : kids.map((k) => `(${k})`).join(" AND ");
    }
    case "or": {
      const kids = node.children.map((c) => walkLucene(c, map, warnings)).filter(Boolean);
      return kids.length <= 1 ? kids[0] ?? "" : `(${kids.join(" OR ")})`;
    }
    case "not": {
      const inner = walkLucene(node.child, map, warnings);
      return inner ? `NOT (${inner})` : "";
    }
    default:
      return "";
  }
}

export function convertToOpenSearch(rule: ParsedSigmaRule): { query: string; warnings: string[] } {
  const warnings = [...rule.parseWarnings];
  const map = getSelectionMap(rule);
  const query = walkLucene(buildAst(rule), map, warnings);

  warnings.push(
    "OpenSearch Lucene query from Sigma — map field names to your index mapping as needed"
  );
  return { query: query || "*:*", warnings };
}
