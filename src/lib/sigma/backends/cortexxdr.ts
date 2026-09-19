import type { ParsedSigmaRule } from "../types";
import { matchToCortexXqlPredicate } from "../field";
import { classifyLogsource, logsourceLabel } from "../logsource";
import { renderCondition } from "./shared";

export function convertToCortexXdr(rule: ParsedSigmaRule): { query: string; warnings: string[] } {
  const warnings = [...rule.parseWarnings];
  const mapping = classifyLogsource(rule);
  const { expression, warnings: condWarn } = renderCondition(rule, matchToCortexXqlPredicate, {
    wrapNot: (inner) => `not (${inner})`,
  });
  warnings.push(...condWarn);

  const query = [
    `dataset = ${mapping.cortexDataset}`,
    `| filter ${expression === "true" ? "true" : expression}`,
  ].join("\n");

  warnings.push(
    `Cortex XDR XQL from Sigma logsource (${logsourceLabel(mapping)}) — remap fields to dataset ${mapping.cortexDataset}`
  );
  return { query, warnings };
}
