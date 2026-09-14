import type {
  Detection,
  DetectionLifecycle,
  RuleFormats,
  TelemetrySource,
} from "./detectionTypes";

type MetaFile = Omit<Detection, "rules" | "telemetry" | "investigationSteps" | "testingSteps" | "lifecycle">;

/** Load all providers: rules/{aws,azure,gcp,...}/<slug>/... */
const metaFiles = import.meta.glob("../../rules/*/*/meta.json", {
  eager: true,
  import: "default",
}) as Record<string, MetaFile>;

const sigmaFiles = import.meta.glob("../../rules/*/*/sigma.yml", {
  eager: true,
  query: "?raw",
  import: "default",
}) as Record<string, string>;

const splunkFiles = import.meta.glob("../../rules/*/*/formats/splunk.txt", {
  eager: true,
  query: "?raw",
  import: "default",
}) as Record<string, string>;

const cloudtrailFiles = import.meta.glob("../../rules/*/*/formats/cloudtrail.sql", {
  eager: true,
  query: "?raw",
  import: "default",
}) as Record<string, string>;

const cloudwatchFiles = import.meta.glob("../../rules/*/*/formats/cloudwatch.txt", {
  eager: true,
  query: "?raw",
  import: "default",
}) as Record<string, string>;

const eventbridgeFiles = import.meta.glob("../../rules/*/*/formats/eventbridge.json", {
  eager: true,
  query: "?raw",
  import: "default",
}) as Record<string, string>;

const lambdaFiles = import.meta.glob("../../rules/*/*/formats/lambda.py", {
  eager: true,
  query: "?raw",
  import: "default",
}) as Record<string, string>;

const esqlFiles = import.meta.glob("../../rules/*/*/formats/esql.txt", {
  eager: true,
  query: "?raw",
  import: "default",
}) as Record<string, string>;

const datadogFiles = import.meta.glob("../../rules/*/*/formats/datadog.txt", {
  eager: true,
  query: "?raw",
  import: "default",
}) as Record<string, string>;

const telemetryFiles = import.meta.glob("../../rules/*/*/telemetry.json", {
  eager: true,
  import: "default",
}) as Record<string, TelemetrySource>;

const investigationFiles = import.meta.glob("../../rules/*/*/investigation.json", {
  eager: true,
  import: "default",
}) as Record<string, string[]>;

const testingFiles = import.meta.glob("../../rules/*/*/testing.json", {
  eager: true,
  import: "default",
}) as Record<string, string[]>;

const lifecycleFiles = import.meta.glob("../../rules/*/*/lifecycle.json", {
  eager: true,
  import: "default",
}) as Record<string, DetectionLifecycle>;

function ruleDirFromMetaPath(metaPath: string): string {
  return metaPath.replace(/\/meta\.json$/, "");
}

function lookup<T>(map: Record<string, T>, dir: string, file: string): T | undefined {
  return map[`${dir}/${file}`];
}

function buildRules(dir: string): RuleFormats {
  const rules: RuleFormats = {};
  const sigma = lookup(sigmaFiles, dir, "sigma.yml");
  if (sigma) rules.sigma = sigma.trimEnd();
  const splunk = lookup(splunkFiles, dir, "formats/splunk.txt");
  if (splunk) rules.splunk = splunk.trimEnd();
  const cloudtrail = lookup(cloudtrailFiles, dir, "formats/cloudtrail.sql");
  if (cloudtrail) rules.cloudtrail = cloudtrail.trimEnd();
  const cloudwatch = lookup(cloudwatchFiles, dir, "formats/cloudwatch.txt");
  if (cloudwatch) rules.cloudwatch = cloudwatch.trimEnd();
  const eventbridge = lookup(eventbridgeFiles, dir, "formats/eventbridge.json");
  if (eventbridge) rules.eventbridge = eventbridge.trimEnd();
  const lambda = lookup(lambdaFiles, dir, "formats/lambda.py");
  if (lambda) rules.lambda = lambda.trimEnd();
  const esql = lookup(esqlFiles, dir, "formats/esql.txt");
  if (esql) rules.esql = esql.trimEnd();
  const datadog = lookup(datadogFiles, dir, "formats/datadog.txt");
  if (datadog) rules.datadog = datadog.trimEnd();
  return rules;
}

function loadDetectionsFromRulesDir(): Detection[] {
  const detections: Detection[] = [];

  for (const [metaPath, meta] of Object.entries(metaFiles)) {
    const dir = ruleDirFromMetaPath(metaPath);
    detections.push({
      ...meta,
      relatedServices: meta.relatedServices ?? [],
      tags: meta.tags ?? [],
      logSources: meta.logSources ?? [],
      falsePositives: meta.falsePositives ?? [],
      relatedAttackSlugs: meta.relatedAttackSlugs ?? [],
      cloudProvider: meta.cloudProvider ?? "aws",
      rules: buildRules(dir),
      telemetry: lookup(telemetryFiles, dir, "telemetry.json"),
      investigationSteps: lookup(investigationFiles, dir, "investigation.json"),
      testingSteps: lookup(testingFiles, dir, "testing.json"),
      lifecycle: lookup(lifecycleFiles, dir, "lifecycle.json"),
    });
  }

  detections.sort((a, b) => {
    const providerOrder = { aws: 0, azure: 1, gcp: 2, kubernetes: 3 } as const;
    const pa = providerOrder[a.cloudProvider ?? "aws"] ?? 9;
    const pb = providerOrder[b.cloudProvider ?? "aws"] ?? 9;
    if (pa !== pb) return pa - pb;

    const an = Number((a.id.match(/(\d+)$/) || [])[1] || 0);
    const bn = Number((b.id.match(/(\d+)$/) || [])[1] || 0);
    if (an && bn && an !== bn) return an - bn;
    return a.title.localeCompare(b.title);
  });

  return detections;
}

export const detectionsFromRules: Detection[] = loadDetectionsFromRulesDir();
