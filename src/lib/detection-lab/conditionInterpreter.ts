/**
 * Condition interpreter for Sigma rules.
 * Evaluates logical expressions: selection1 AND selection2, (selection1 OR selection2) AND not filter, etc.
 */

/**
 * Evaluate a Sigma condition expression given a map of identifier -> boolean.
 * Supports: AND, OR, NOT, parentheses.
 * Tokens: identifiers (selection, filter, selection_iam, etc.), and, or, not, (, )
 */
export function evaluateCondition(condition: string, values: Record<string, boolean>): boolean {
  const expr = condition.toLowerCase().trim();
  if (!expr) return false;

  const tokens = tokenize(expr);
  if (tokens.length === 0) return false;

  let pos = 0;

  function parseOr(): boolean {
    let left = parseAnd();
    while (pos < tokens.length && tokens[pos] === "or") {
      pos++;
      const right = parseAnd();
      left = left || right;
    }
    return left;
  }

  function parseAnd(): boolean {
    let left = parseNot();
    while (pos < tokens.length && tokens[pos] === "and") {
      pos++;
      const right = parseNot();
      left = left && right;
    }
    return left;
  }

  function parseNot(): boolean {
    if (pos < tokens.length && tokens[pos] === "not") {
      pos++;
      return !parseNot();
    }
    return parsePrimary();
  }

  function parsePrimary(): boolean {
    if (pos >= tokens.length) return false;
    const tok = tokens[pos];
    if (tok === "(") {
      pos++;
      const result = parseOr();
      if (pos < tokens.length && tokens[pos] === ")") pos++;
      return result;
    }
    if (tok === "and" || tok === "or" || tok === "not" || tok === ")" || tok === "(") {
      return false;
    }
    pos++;
    return values[tok] === true;
  }

  return parseOr();
}

function tokenize(expr: string): string[] {
  const tokens: string[] = [];
  let i = 0;

  while (i < expr.length) {
    const c = expr[i];
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    if (c === "(" || c === ")") {
      tokens.push(c);
      i++;
      continue;
    }
    if (c === "&" && expr.slice(i, i + 3) === "and") {
      tokens.push("and");
      i += 3;
      continue;
    }
    if (expr.slice(i, i + 3).toLowerCase() === "and" && !/\w/.test(expr[i + 3] ?? "")) {
      tokens.push("and");
      i += 3;
      continue;
    }
    if (expr.slice(i, i + 2).toLowerCase() === "or" && !/\w/.test(expr[i + 2] ?? "")) {
      tokens.push("or");
      i += 2;
      continue;
    }
    if (expr.slice(i, i + 3).toLowerCase() === "not" && !/\w/.test(expr[i + 3] ?? "")) {
      tokens.push("not");
      i += 3;
      continue;
    }
    if (/\w/.test(c)) {
      let end = i;
      while (end < expr.length && /[\w_]/.test(expr[end])) end++;
      tokens.push(expr.slice(i, end).toLowerCase());
      i = end;
      continue;
    }
    i++;
  }

  return tokens;
}
