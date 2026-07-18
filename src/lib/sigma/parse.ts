import type { ParsedSigmaRule, SigmaFieldMatch, SigmaFieldModifier, SigmaSelection } from "./types";

interface YamlNode {
  [key: string]: unknown;
}

/** Unquote a YAML scalar */
function unquote(raw: string): string | number | boolean {
  const s = raw.trim();
  if ((s.startsWith("'") && s.endsWith("'")) || (s.startsWith('"') && s.endsWith('"'))) {
    return s.slice(1, -1);
  }
  if (s === "true") return true;
  if (s === "false") return false;
  if (s === "null" || s === "~") return "";
  if (/^-?\d+(\.\d+)?$/.test(s)) return Number(s);
  return s;
}

function indentOf(line: string): number {
  const m = line.match(/^(\s*)/);
  return m ? m[1].length : 0;
}

/**
 * Lightweight indentation-based YAML parser for Sigma rule documents.
 * Supports maps, lists, scalars — enough for the CloudTrail Sigma rules in this repo.
 */
export function parseYamlSubset(text: string): YamlNode {
  const lines = text
    .split(/\r?\n/)
    .map((l) => l.replace(/\t/g, "  "))
    .filter((l) => l.trim() !== "" && !l.trim().startsWith("#"));

  type Frame = { indent: number; container: unknown };
  const root: YamlNode = {};
  const stack: Frame[] = [{ indent: -1, container: root }];

  const currentContainer = () => stack[stack.length - 1].container;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const indent = indentOf(line);
    const trimmed = line.trim();

    while (stack.length > 1 && indent <= stack[stack.length - 1].indent) {
      stack.pop();
    }

    const container = currentContainer();

    // List item
    if (trimmed.startsWith("- ")) {
      const itemRaw = trimmed.slice(2).trim();
      if (!Array.isArray(container)) {
        // orphan list — ignore
        continue;
      }
      if (itemRaw.includes(": ") && !itemRaw.startsWith("'") && !itemRaw.startsWith('"')) {
        // inline map in list — rare in our rules; treat as scalar string
        container.push(unquote(itemRaw));
      } else if (itemRaw === "" || itemRaw.endsWith(":")) {
        const child: YamlNode = {};
        container.push(child);
        stack.push({ indent, container: child });
      } else {
        container.push(unquote(itemRaw));
      }
      continue;
    }

    // Key: value or Key:
    const colonIdx = trimmed.indexOf(":");
    if (colonIdx === -1 || Array.isArray(container)) continue;

    const key = trimmed.slice(0, colonIdx).trim();
    const rest = trimmed.slice(colonIdx + 1).trim();
    const map = container as YamlNode;

    if (rest === "") {
      // Peek next line to decide map vs list
      const next = lines[i + 1];
      const nextIndent = next ? indentOf(next) : -1;
      const nextTrim = next?.trim() ?? "";
      if (next && nextIndent > indent && nextTrim.startsWith("- ")) {
        const arr: unknown[] = [];
        map[key] = arr;
        stack.push({ indent, container: arr });
      } else {
        const child: YamlNode = {};
        map[key] = child;
        stack.push({ indent, container: child });
      }
    } else {
      map[key] = unquote(rest);
    }
  }

  return root;
}

function parseFieldKey(rawKey: string): { field: string; modifier: SigmaFieldModifier; allValues: boolean } {
  const parts = rawKey.split("|");
  const field = parts[0];
  let modifier: SigmaFieldModifier = "equals";
  let allValues = false;

  for (let i = 1; i < parts.length; i++) {
    const mod = parts[i].toLowerCase();
    if (mod === "all") {
      allValues = true;
      continue;
    }
    if (
      mod === "contains" ||
      mod === "startswith" ||
      mod === "endswith" ||
      mod === "re" ||
      mod === "cidr" ||
      mod === "windash"
    ) {
      modifier = mod;
    }
  }

  return { field, modifier, allValues };
}

function toValueArray(value: unknown): Array<string | number | boolean> {
  if (Array.isArray(value)) {
    return value.map((v) => {
      if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") return v;
      return String(v);
    });
  }
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return [value];
  }
  if (value && typeof value === "object") {
    // Nested maps (e.g. requestParameters.foo.bar as nested YAML) — flatten poorly; warn via empty
    return [];
  }
  return [];
}

function parseSelectionMap(name: string, node: unknown): SigmaSelection {
  const matches: SigmaFieldMatch[] = [];
  if (!node || typeof node !== "object" || Array.isArray(node)) {
    return { name, matches };
  }

  for (const [rawKey, rawVal] of Object.entries(node as YamlNode)) {
    // Skip nested object values that aren't field matches (shouldn't happen often)
    if (rawVal && typeof rawVal === "object" && !Array.isArray(rawVal)) {
      // Nested structure — flatten one level with dotted keys
      for (const [subKey, subVal] of Object.entries(rawVal as YamlNode)) {
        const { field, modifier, allValues } = parseFieldKey(`${rawKey}.${subKey}`);
        const values = toValueArray(subVal);
        if (values.length) matches.push({ field, modifier, values, allValues });
      }
      continue;
    }

    const { field, modifier, allValues } = parseFieldKey(rawKey);
    const values = toValueArray(rawVal);
    if (values.length) {
      matches.push({ field, modifier, values, allValues });
    }
  }

  return { name, matches };
}

/**
 * Parse a Sigma YAML string into a structured rule model.
 */
export function parseSigmaRule(yaml: string): ParsedSigmaRule {
  const warnings: string[] = [];
  if (!yaml?.trim()) {
    return {
      selections: [],
      condition: "",
      selectionNames: [],
      parseWarnings: ["Empty Sigma rule"],
    };
  }

  let doc: YamlNode;
  try {
    doc = parseYamlSubset(yaml);
  } catch (e) {
    return {
      selections: [],
      condition: "",
      selectionNames: [],
      parseWarnings: [`Failed to parse Sigma YAML: ${e instanceof Error ? e.message : String(e)}`],
    };
  }

  const logsource =
    doc.logsource && typeof doc.logsource === "object"
      ? (doc.logsource as { product?: string; service?: string; category?: string })
      : undefined;

  const detection = doc.detection;
  if (!detection || typeof detection !== "object" || Array.isArray(detection)) {
    warnings.push("No detection block found in Sigma rule");
    return {
      title: typeof doc.title === "string" ? doc.title : undefined,
      status: typeof doc.status === "string" ? doc.status : undefined,
      level: typeof doc.level === "string" ? doc.level : undefined,
      description: typeof doc.description === "string" ? doc.description : undefined,
      logsource,
      selections: [],
      condition: "",
      selectionNames: [],
      parseWarnings: warnings,
    };
  }

  const detMap = detection as YamlNode;
  const condition = typeof detMap.condition === "string" ? detMap.condition : "";
  if (!condition) warnings.push("Missing detection.condition");

  const selections: SigmaSelection[] = [];
  const selectionNames: string[] = [];

  for (const [name, value] of Object.entries(detMap)) {
    if (name === "condition" || name === "timeframe") continue;
    selectionNames.push(name);
    selections.push(parseSelectionMap(name, value));
  }

  if (selections.length === 0) {
    warnings.push("No selection blocks found under detection");
  }

  // Flag modifiers we only partially support
  for (const sel of selections) {
    for (const m of sel.matches) {
      if (m.modifier === "cidr" || m.modifier === "windash" || m.modifier === "re") {
        warnings.push(`Modifier '|${m.modifier}' on '${m.field}' has limited conversion support`);
      }
      if (m.field.includes("{}")) {
        warnings.push(`List-wildcard field '${m.field}' is approximated in converted queries`);
      }
    }
  }

  return {
    title: typeof doc.title === "string" ? doc.title : undefined,
    status: typeof doc.status === "string" ? doc.status : undefined,
    level: typeof doc.level === "string" ? doc.level : undefined,
    description: typeof doc.description === "string" ? doc.description : undefined,
    logsource,
    selections,
    condition,
    selectionNames,
    parseWarnings: warnings,
  };
}
