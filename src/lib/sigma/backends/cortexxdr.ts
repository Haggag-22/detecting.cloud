import type { ParsedSigmaRule } from "../types";
import { matchToCortexXqlPredicate } from "../field";
import { renderCondition } from "./shared";

export function convertToCortexXdr(rule: ParsedSigmaRule): { query: string; warnings: string[] } {
  const warnings = [...rule.parseWarnings];
  const { expression, warnings: condWarn } = renderCondition(rule, matchToCortexXqlPredicate, {
    wrapNot: (inner) => `not (${inner})`,
  });
  warnings.push(...condWarn);

  const dataset =
    rule.logsource?.service === "cloudtrail" || rule.logsource?.product === "aws"
      ? "cloud_audit_logs"
      : "xdr_data";

  const query = [
    `dataset = ${dataset}`,
    `| filter ${expression === "true" ? "true" : expression}`,
  ].join("\n");

  warnings.push(
    "Cortex XDR XQL is best-effort — remap fields to your Cortex dataset schema (cloud_audit_logs vs xdr_data)"
  );
  return { query, warnings };
}
