import { convertToAthena } from "./backends/athena";
import { convertToCloudWatch } from "./backends/cloudwatch";
import { convertToDatadog } from "./backends/datadog";
import { convertToEsql } from "./backends/esql";
import { convertToEventBridge } from "./backends/eventbridge";
import { convertToSplunk } from "./backends/splunk";
import { parseSigmaRule } from "./parse";
import {
  getTargetInfo,
  type ConversionResult,
  type ConvertOptions,
  type SigmaTargetLanguage,
  TARGET_LANGUAGES,
} from "./types";

type BackendFn = (rule: ReturnType<typeof parseSigmaRule>) => { query: string; warnings: string[] };

const BACKENDS: Partial<Record<SigmaTargetLanguage, BackendFn>> = {
  esql: convertToEsql,
  splunk: convertToSplunk,
  datadog: convertToDatadog,
  cloudtrail: convertToAthena,
  cloudwatch: convertToCloudWatch,
  eventbridge: convertToEventBridge,
};

function dedupeWarnings(warnings: string[]): string[] {
  return [...new Set(warnings.filter(Boolean))];
}

/**
 * Convert a Sigma YAML rule to a target query language.
 *
 * Strategy (Sigma-canonical):
 * 1. Parse Sigma and attempt best-effort conversion.
 * 2. If preferStored or conversion fails/empty, use curated storedRules when present.
 * 3. Hybrid: converted query preferred; stored used as fallback; warn when both differ in intent.
 */
export function convertSigma(
  sigmaYaml: string,
  language: SigmaTargetLanguage,
  options: ConvertOptions = {}
): ConversionResult {
  const info = getTargetInfo(language);
  const stored = options.storedRules?.[language]?.trim();
  const preferStored = options.preferStored ?? false;

  if (!sigmaYaml?.trim() && !stored) {
    return {
      language,
      label: info.label,
      query: "",
      supported: false,
      warnings: ["No Sigma rule available to convert"],
      source: "converted",
      extension: info.extension,
    };
  }

  // Lambda: stored-only (not a faithful Sigma compile target)
  if (language === "lambda") {
    if (stored) {
      return {
        language,
        label: info.label,
        query: stored,
        supported: true,
        warnings: ["Lambda handler is a curated implementation — not generated from Sigma"],
        source: "stored",
        extension: info.extension,
      };
    }
    return {
      language,
      label: info.label,
      query: "",
      supported: false,
      warnings: [
        "Lambda Python handlers are not auto-generated from Sigma. Use a curated rule variant when available, or implement from the Sigma conditions manually.",
      ],
      source: "converted",
      extension: info.extension,
    };
  }

  if (preferStored && stored) {
    return {
      language,
      label: info.label,
      query: stored,
      supported: true,
      warnings: ["Showing curated stored query (preferStored=true)"],
      source: "stored",
      extension: info.extension,
    };
  }

  const parsed = parseSigmaRule(sigmaYaml || "");
  const backend = BACKENDS[language];

  if (!backend) {
    if (stored) {
      return {
        language,
        label: info.label,
        query: stored,
        supported: true,
        warnings: [`No converter for '${language}' — using curated stored query`],
        source: "stored",
        extension: info.extension,
      };
    }
    return {
      language,
      label: info.label,
      query: "",
      supported: false,
      warnings: [`Target language '${language}' is not supported by the Sigma converter`],
      source: "converted",
      extension: info.extension,
    };
  }

  if (parsed.selections.length === 0) {
    if (stored) {
      return {
        language,
        label: info.label,
        query: stored,
        supported: true,
        warnings: dedupeWarnings([
          ...parsed.parseWarnings,
          "Sigma parse produced no selections — using curated stored query",
        ]),
        source: "stored",
        extension: info.extension,
      };
    }
    return {
      language,
      label: info.label,
      query: "",
      supported: false,
      warnings: dedupeWarnings([...parsed.parseWarnings, "Unable to convert empty/invalid Sigma rule"]),
      source: "converted",
      extension: info.extension,
    };
  }

  const { query, warnings } = backend(parsed);

  if (!query?.trim()) {
    if (stored) {
      return {
        language,
        label: info.label,
        query: stored,
        supported: true,
        warnings: dedupeWarnings([
          ...warnings,
          "Conversion produced an empty query — using curated stored query",
        ]),
        source: "stored",
        extension: info.extension,
      };
    }
    return {
      language,
      label: info.label,
      query: "",
      supported: false,
      warnings: dedupeWarnings([...warnings, `Conversion to ${info.label} is not supported for this rule`]),
      source: "converted",
      extension: info.extension,
    };
  }

  const source = stored ? "hybrid" : "converted";
  const extra =
    source === "hybrid"
      ? ["Converted from Sigma (canonical). A curated stored variant also exists for this detection."]
      : [];

  return {
    language,
    label: info.label,
    query,
    supported: true,
    warnings: dedupeWarnings([...warnings, ...extra]),
    source,
    extension: info.extension,
  };
}

/** List convertible / display targets for the UI */
export function listConvertibleTargets(): typeof TARGET_LANGUAGES {
  return TARGET_LANGUAGES;
}

/** Convenience: convert to every supported backend */
export function convertSigmaToAll(
  sigmaYaml: string,
  options: ConvertOptions = {}
): ConversionResult[] {
  return TARGET_LANGUAGES.map((t) => convertSigma(sigmaYaml, t.id, options));
}
