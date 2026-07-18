import type { ConditionNode } from "../condition";
import { expandWildcards, getSelectionMap, parseCondition } from "../condition";
import type { ParsedSigmaRule, SigmaFieldMatch, SigmaSelection } from "../types";
import { joinAlts } from "../field";

export type MatchRenderer = (m: SigmaFieldMatch) => string;

export function buildAst(rule: ParsedSigmaRule): ConditionNode {
  const raw = parseCondition(rule.condition || "selection");
  return expandWildcards(rule, raw);
}

function selectionToExpr(sel: SigmaSelection | undefined, render: MatchRenderer): string {
  if (!sel || sel.matches.length === 0) return "true";
  const parts = sel.matches.map(render);
  return parts.length === 1 ? parts[0] : `(${parts.join(" AND ")})`;
}

/**
 * Render a condition AST into a boolean expression string using the given field renderer.
 */
export function renderCondition(
  rule: ParsedSigmaRule,
  render: MatchRenderer,
  options?: { wrapNot?: (inner: string) => string }
): { expression: string; warnings: string[] } {
  const warnings: string[] = [];
  const map = getSelectionMap(rule);
  const wrapNot = options?.wrapNot ?? ((inner: string) => `NOT (${inner})`);

  function walk(node: ConditionNode): string {
    switch (node.type) {
      case "ref": {
        const sel = map.get(node.name);
        if (!sel) {
          warnings.push(`Unknown selection '${node.name}' in condition`);
          return "true";
        }
        return selectionToExpr(sel, render);
      }
      case "and": {
        const kids = node.children.map(walk).filter((x) => x && x !== "true");
        if (kids.length === 0) return "true";
        return kids.length === 1 ? kids[0] : `(${kids.join(" AND ")})`;
      }
      case "or": {
        const kids = node.children.map(walk);
        return joinAlts(kids);
      }
      case "not":
        return wrapNot(walk(node.child));
      case "oneof":
      case "allof":
        warnings.push(`Unresolved wildcard '${node.prefix}*' in condition`);
        return "true";
    }
  }

  const expression = walk(buildAst(rule));
  return { expression, warnings };
}

/** Collect all field matches from referenced selections (for EventBridge simplification) */
export function collectAllMatches(rule: ParsedSigmaRule): SigmaFieldMatch[] {
  return rule.selections.flatMap((s) => s.matches);
}

export function defaultOutputFields(rule: ParsedSigmaRule): string[] {
  const base = [
    "eventTime",
    "userIdentity.type",
    "userIdentity.arn",
    "eventName",
    "eventSource",
    "sourceIPAddress",
  ];
  const extras = new Set<string>();
  for (const sel of rule.selections) {
    for (const m of sel.matches) {
      const f = m.field.replace(/\|.*/, "").replace(/\{\}/g, "");
      if (
        f.startsWith("requestParameters") ||
        f.startsWith("responseElements") ||
        f === "errorCode"
      ) {
        extras.add(f.split(".")[0] === "requestParameters" || f.split(".")[0] === "responseElements"
          ? f
          : f);
      }
    }
  }
  // Keep list short
  const extraList = [...extras].slice(0, 4);
  return [...base.filter((b) => b !== "eventTime"), ...extraList];
}
