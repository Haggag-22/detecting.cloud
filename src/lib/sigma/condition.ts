import type { ParsedSigmaRule, SigmaSelection } from "./types";

export type ConditionNode =
  | { type: "ref"; name: string }
  | { type: "and"; children: ConditionNode[] }
  | { type: "or"; children: ConditionNode[] }
  | { type: "not"; child: ConditionNode }
  | { type: "oneof"; prefix: string }
  | { type: "allof"; prefix: string };

/**
 * Expand `1 of foo_*` / `all of foo_*` against known selection names.
 */
export function expandWildcards(rule: ParsedSigmaRule, node: ConditionNode): ConditionNode {
  if (node.type === "oneof" || node.type === "allof") {
    const names = rule.selectionNames.filter((n) => n.startsWith(node.prefix));
    if (names.length === 0) return { type: "ref", name: `${node.prefix}*` };
    const refs: ConditionNode[] = names.map((name) => ({ type: "ref", name }));
    return node.type === "oneof" ? { type: "or", children: refs } : { type: "and", children: refs };
  }
  if (node.type === "and" || node.type === "or") {
    return { ...node, children: node.children.map((c) => expandWildcards(rule, c)) };
  }
  if (node.type === "not") {
    return { type: "not", child: expandWildcards(rule, node.child) };
  }
  return node;
}

/**
 * Parse a Sigma condition expression into an AST.
 * Supports: and, or, not, parentheses, `1 of x_*`, `all of x_*`.
 */
export function parseCondition(expr: string): ConditionNode {
  const tokens = tokenize(expr);
  let i = 0;

  function peek(): string | undefined {
    return tokens[i];
  }
  function consume(): string {
    return tokens[i++];
  }

  function parseOr(): ConditionNode {
    let left = parseAnd();
    while (peek()?.toLowerCase() === "or") {
      consume();
      const right = parseAnd();
      if (left.type === "or") left = { type: "or", children: [...left.children, right] };
      else left = { type: "or", children: [left, right] };
    }
    return left;
  }

  function parseAnd(): ConditionNode {
    let left = parseUnary();
    while (peek()?.toLowerCase() === "and") {
      consume();
      const right = parseUnary();
      if (left.type === "and") left = { type: "and", children: [...left.children, right] };
      else left = { type: "and", children: [left, right] };
    }
    return left;
  }

  function parseUnary(): ConditionNode {
    if (peek()?.toLowerCase() === "not") {
      consume();
      return { type: "not", child: parseUnary() };
    }
    return parsePrimary();
  }

  function parsePrimary(): ConditionNode {
    const t = peek();
    if (!t) return { type: "ref", name: "selection" };

    if (t === "(") {
      consume();
      const inner = parseOr();
      if (peek() === ")") consume();
      return inner;
    }

    // `1 of prefix_*` or `all of prefix_*`
    if (t === "1" || t.toLowerCase() === "all") {
      const kind = t.toLowerCase() === "all" ? "allof" : "oneof";
      consume();
      if (peek()?.toLowerCase() === "of") consume();
      const nameTok = consume() || "selection_*";
      const prefix = nameTok.replace(/\*$/, "");
      return { type: kind, prefix };
    }

    consume();
    return { type: "ref", name: t };
  }

  return parseOr();
}

function tokenize(expr: string): string[] {
  const tokens: string[] = [];
  const re = /\(|\)|\b1\b|\ball\b|\bof\b|\band\b|\bor\b|\bnot\b|[A-Za-z_][\w*]*/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(expr)) !== null) {
    tokens.push(m[0]);
  }
  return tokens;
}

export function getSelectionMap(rule: ParsedSigmaRule): Map<string, SigmaSelection> {
  return new Map(rule.selections.map((s) => [s.name, s]));
}

/** Flatten expanded condition for backends that prefer AND of OR-groups */
export function collectReferencedSelections(node: ConditionNode): string[] {
  switch (node.type) {
    case "ref":
      return [node.name];
    case "and":
    case "or":
      return node.children.flatMap(collectReferencedSelections);
    case "not":
      return collectReferencedSelections(node.child);
    case "oneof":
    case "allof":
      return [`${node.prefix}*`];
  }
}
