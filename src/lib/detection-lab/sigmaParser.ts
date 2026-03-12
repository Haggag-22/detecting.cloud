/**
 * Sigma rule parser.
 * Parses Sigma YAML detection rules to extract selections, filters, and condition expression.
 */

export interface SigmaFieldCondition {
  field: string;
  modifier?: "contains" | "startswith" | "endswith";
  operator: "equals" | "in";
  values: string[];
}

export interface SigmaSelection {
  name: string;
  conditions: SigmaFieldCondition[];
}

export interface ParsedSigmaRule {
  selections: SigmaSelection[];
  filters: SigmaSelection[];
  condition: string;
}

/**
 * Parse a Sigma rule YAML string into selections, filters, and condition.
 */
export function parseSigmaRule(sigma: string): ParsedSigmaRule | null {
  const detectionMatch = sigma.match(/detection:\s*\n([\s\S]*?)(?=\n(?:level|falsepositives|tags|id|references|description)\s*:|$)/i);
  if (!detectionMatch) return null;

  const block = detectionMatch[1];
  const selections: SigmaSelection[] = [];
  const filters: SigmaSelection[] = [];
  let condition = "";

  const lines = block.split("\n");
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();
    const indent = line.search(/\S/);
    if (indent < 0) {
      i++;
      continue;
    }

    if (trimmed.toLowerCase().startsWith("condition:")) {
      condition = trimmed.replace(/^condition:\s*/i, "").trim();
      break;
    }

    const topMatch = trimmed.match(/^(selection(?:_\w+)?|filter(?:_\w+)?)\s*:\s*(.*)$/i);
    if (topMatch && indent <= 2) {
      const [, key, rest] = topMatch;
      const target = key.toLowerCase().startsWith("selection") ? selections : filters;
      const { conditions, consumed } = parseMappingBlock(lines, i, rest.trim());
      target.push({ name: key, conditions });
      i += consumed;
      continue;
    }
    i++;
  }

  if (!condition) {
    if (selections.length > 0) condition = selections[0].name;
    else if (filters.length > 0) condition = filters[0].name;
  }

  return { selections, filters, condition };
}

function parseMappingBlock(lines: string[], startIdx: number, firstVal: string): {
  conditions: SigmaFieldCondition[];
  consumed: number;
} {
  const conditions: SigmaFieldCondition[] = [];
  const baseIndent = lines[startIdx].search(/\S/);
  let i = startIdx + 1;

  while (i < lines.length) {
    const line = lines[i];
    const lineIndent = line.search(/\S/);
    const trimmed = line.trim();

    if (trimmed && lineIndent <= baseIndent) break;
    if (!trimmed || trimmed.startsWith("#")) {
      i++;
      continue;
    }

    const kvMatch = trimmed.match(/^([\w.{}|]+)\s*:\s*(.*)$/);
    if (kvMatch) {
      const [, fieldKey, valuePart] = kvMatch;
      let values: string[] = [];

      const vTrimmed = valuePart.trim();
      if (vTrimmed && !vTrimmed.startsWith("-")) {
        values = [vTrimmed.replace(/^['"]|['"]$/g, "")];
        i++;
      } else {
        i++;
        while (i < lines.length) {
          const nextLine = lines[i];
          const nextIndent = nextLine.search(/\S/);
          const nextTrimmed = nextLine.trim();
          if (nextTrimmed && nextIndent <= baseIndent + 2) break;
          const listItem = nextTrimmed.match(/^-\s*['"]?([^'"]*)['"]?\s*$/);
          if (listItem) {
            values.push(listItem[1].trim());
            i++;
          } else {
            break;
          }
        }
        if (values.length === 0 && vTrimmed) {
          values = [vTrimmed.replace(/^-\s*['"]?|['"]$/g, "").trim()];
        }
      }

      const cond = parseFieldCondition(fieldKey.trim(), values);
      if (cond) conditions.push(cond);
    } else {
      i++;
    }
  }

  return { conditions, consumed: i - startIdx };
}

function parseFieldCondition(fieldKey: string, values: string[]): SigmaFieldCondition | null {
  let field = fieldKey;
  let modifier: SigmaFieldCondition["modifier"] | undefined;
  const pipeIdx = fieldKey.indexOf("|");
  if (pipeIdx >= 0) {
    field = fieldKey.slice(0, pipeIdx).trim();
    const mod = fieldKey.slice(pipeIdx + 1).trim().toLowerCase();
    if (mod === "contains") modifier = "contains";
    else if (mod === "startswith") modifier = "startswith";
    else if (mod === "endswith") modifier = "endswith";
  }

  const cleanValues = values.map((v) => v.replace(/^['"]|['"]$/g, "").trim()).filter(Boolean);
  if (cleanValues.length === 0 && !modifier) return null;

  return {
    field,
    modifier,
    operator: cleanValues.length <= 1 && !modifier ? "equals" : "in",
    values: cleanValues.length > 0 ? cleanValues : [""],
  };
}
