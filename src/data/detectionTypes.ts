export type RuleFormat =
  | "sigma"
  | "splunk"
  | "cloudtrail"
  | "cloudwatch"
  | "eventbridge"
  | "lambda"
  | "esql"
  | "datadog";

export interface RuleFormats {
  /** Canonical detection rule format */
  sigma?: string;
  splunk?: string;
  cloudtrail?: string;
  cloudwatch?: string;
  /** EventBridge rule pattern (detection logic, not deployment) */
  eventbridge?: string;
  /** AWS Lambda / Python implementation for real-time or enriched detections */
  lambda?: string;
  /** Optional curated Elastic ES|QL (prefer Sigma convert when absent) */
  esql?: string;
  /** Optional curated Datadog query (prefer Sigma convert when absent) */
  datadog?: string;
}

/** Telemetry source metadata for detection engineering context */
export interface TelemetrySource {
  /** Primary log source (e.g., AWS CloudTrail) */
  primaryLogSource: string;
  /** AWS service that generates the telemetry */
  generatingService: string;
  /** Key event fields used by the detection */
  importantFields: string[];
  /** Sample AWS event JSON */
  exampleEvent: string;
}

/** Threat context (Phase 1) */
export interface ThreatContext {
  attackerBehavior: string;
  realWorldUsage?: string;
  whyItMatters: string;
  riskAndImpact: string;
}

/** Telemetry validation (Phase 2) */
export interface TelemetryValidation {
  requiredLogSources: string[];
  requiredFields: string[];
  loggingRequirements: string[];
  limitations?: string[];
}

/** Field mapping for normalization */
export interface FieldMapping {
  rawPath: string;
  normalizedPath: string;
  notes?: string;
}

/** Data modeling (Phase 3) */
export interface DataModeling {
  rawToNormalized: FieldMapping[];
  exampleNormalizedEvent: string;
}

/** Enrichment context (Phase 4) */
export interface EnrichmentContext {
  dimension: string;
  description: string;
  examples: string[];
  falsePositiveReduction?: string;
}

/** Human-readable detection logic explanation (Phase 5 Detection Logic tab) */
export interface DetectionLogicExplanation {
  humanReadable: string;
  /** Exact conditions that trigger the detection */
  conditions?: string[];
  /** Optional tuning guidance for reducing false positives */
  tuningGuidance?: string;
  /** Context about when the detection should fire */
  whenToFire?: string;
}

/** Detection quality metrics */
export interface DetectionQuality {
  signalQuality: number;
  falsePositiveRate: string;
  expectedVolume: string;
  productionReadiness: "experimental" | "validated" | "production";
}

/** Community confidence voting */
export interface CommunityConfidence {
  accurate: number;
  needsTuning: number;
  noisy: number;
  feedback?: string[];
}

/** Detection pipeline step for flow visualization */
export interface DetectionFlowStep {
  id: string;
  label: string;
  type: "source" | "transform" | "rule" | "alert";
}

/** Full detection lifecycle metadata */
export interface DetectionLifecycle {
  /** Short statement for overview: why this detection matters */
  whyItMatters?: string;
  threatContext?: ThreatContext;
  telemetryValidation?: TelemetryValidation;
  dataModeling?: DataModeling;
  enrichment?: EnrichmentContext[];
  logicExplanation?: DetectionLogicExplanation;
  /** Example CLI/API command to simulate the attack (for testing section) */
  simulationCommand?: string;
  detectionFlow?: DetectionFlowStep[];
  quality?: DetectionQuality;
  communityConfidence?: CommunityConfidence;
}

/** Top-level cloud / platform family for Detection Rules browse UI */
export type DetectionCloudProvider = "aws" | "azure" | "gcp" | "kubernetes";

export interface Detection {
  id: string;
  title: string;
  description: string;
  /** Primary AWS service this rule belongs to (also used as service key for non-AWS later) */
  awsService: string;
  /** Additional AWS services involved in the attack/detection */
  relatedServices: string[];
  /**
   * Cloud provider bucket for the Detection Rules provider tabs.
   * Defaults to `"aws"` when omitted (current catalog is AWS-first).
   */
  cloudProvider?: DetectionCloudProvider;
  severity: "Critical" | "High" | "Medium" | "Low";
  tags: string[];
  logSources: string[];
  falsePositives: string[];
  rules: RuleFormats;
  relatedAttackSlugs: string[];
  /** Telemetry source context for detection engineers */
  telemetry?: TelemetrySource;
  /** Steps for SOC analysts to investigate the alert */
  investigationSteps?: string[];
  /** Safe lab testing procedures */
  testingSteps?: string[];
  /** Full detection lifecycle metadata (8-section page) */
  lifecycle?: DetectionLifecycle;
}

export function getDetectionCloudProvider(d: Detection): DetectionCloudProvider {
  return d.cloudProvider ?? "aws";
}
