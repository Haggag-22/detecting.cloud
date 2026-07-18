/** Target query languages for Sigma conversion */
export type SigmaTargetLanguage =
  | "cortexxdr"
  | "crowdstrike"
  | "datadog"
  | "snowflake"
  | "splunk"
  | "elasticsearch"
  | "opensearch"
  | "sentinelone"
  | "qradar";

export type SigmaFieldModifier =
  | "equals"
  | "contains"
  | "startswith"
  | "endswith"
  | "re"
  | "cidr"
  | "all"
  | "windash";

export interface SigmaFieldMatch {
  field: string;
  modifier: SigmaFieldModifier;
  values: Array<string | number | boolean>;
  /** When true, all list values must match (modifier `|all`) */
  allValues?: boolean;
}

export interface SigmaSelection {
  name: string;
  matches: SigmaFieldMatch[];
}

export interface ParsedSigmaRule {
  title?: string;
  status?: string;
  level?: string;
  description?: string;
  logsource?: {
    product?: string;
    service?: string;
    category?: string;
  };
  selections: SigmaSelection[];
  condition: string;
  /** Raw detection map keys in document order */
  selectionNames: string[];
  parseWarnings: string[];
}

export type ConversionSource = "converted" | "stored" | "hybrid";

export interface ConversionResult {
  language: SigmaTargetLanguage;
  label: string;
  query: string;
  supported: boolean;
  warnings: string[];
  /** How the query was produced */
  source: ConversionSource;
  /** Suggested download filename extension */
  extension: string;
}

export interface ConvertOptions {
  /** Optional curated rule strings already shipped with the detection */
  storedRules?: Partial<Record<SigmaTargetLanguage | "sigma", string>>;
  /** Prefer stored curated queries when available (default: false — Sigma-first) */
  preferStored?: boolean;
  /** Detection metadata for richer stubs */
  meta?: {
    id?: string;
    title?: string;
    awsService?: string;
  };
}

export interface TargetLanguageInfo {
  id: SigmaTargetLanguage;
  label: string;
  shortLabel: string;
  extension: string;
  /** Whether the engine can generate from Sigma (vs stored-only) */
  convertible: boolean;
}

export const TARGET_LANGUAGES: TargetLanguageInfo[] = [
  { id: "cortexxdr", label: "Cortex XDR", shortLabel: "Cortex XDR", extension: "xql", convertible: true },
  { id: "crowdstrike", label: "CrowdStrike", shortLabel: "CrowdStrike", extension: "cql", convertible: true },
  { id: "datadog", label: "Datadog", shortLabel: "Datadog", extension: "txt", convertible: true },
  { id: "snowflake", label: "Snowflake", shortLabel: "Snowflake", extension: "sql", convertible: true },
  { id: "splunk", label: "Splunk", shortLabel: "Splunk", extension: "spl", convertible: true },
  { id: "elasticsearch", label: "Elasticsearch", shortLabel: "Elasticsearch", extension: "esql", convertible: true },
  { id: "opensearch", label: "OpenSearch", shortLabel: "OpenSearch", extension: "lucene", convertible: true },
  { id: "sentinelone", label: "SentinelOne", shortLabel: "SentinelOne", extension: "s1ql", convertible: true },
  { id: "qradar", label: "QRadar", shortLabel: "QRadar", extension: "aql", convertible: true },
];

export function getTargetInfo(language: SigmaTargetLanguage): TargetLanguageInfo {
  return TARGET_LANGUAGES.find((t) => t.id === language) ?? {
    id: language,
    label: language,
    shortLabel: language,
    extension: "txt",
    convertible: false,
  };
}
