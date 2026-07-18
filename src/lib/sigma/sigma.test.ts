import { describe, expect, it } from "vitest";
import { parseCondition, expandWildcards } from "./condition";
import { convertSigma, listConvertibleTargets } from "./convert";
import { parseSigmaRule } from "./parse";
import { TARGET_LANGUAGES } from "./types";

const SAMPLE_SIGMA = `title: IAM PassRole Privilege Escalation via Lambda
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: lambda.amazonaws.com
    eventName: CreateFunction20150331
  selection_role:
    requestParameters.role|contains:
      - 'Admin'
      - 'AdministratorAccess'
  condition: selection and selection_role
level: critical`;

const COMPLEX_SIGMA = `title: S3 Public Access Block Removed
detection:
  selection_delete:
    eventSource: s3.amazonaws.com
    eventName: DeletePublicAccessBlock
  selection_put:
    eventSource: s3.amazonaws.com
    eventName: PutPublicAccessBlock
  weaken_policy:
    requestParameters.PublicAccessBlockConfiguration.BlockPublicPolicy: false
  condition: selection_delete or (selection_put and 1 of weaken_*)
level: critical`;

describe("parseSigmaRule", () => {
  it("parses selections, modifiers, and condition", () => {
    const rule = parseSigmaRule(SAMPLE_SIGMA);
    expect(rule.title).toBe("IAM PassRole Privilege Escalation via Lambda");
    expect(rule.selections).toHaveLength(2);
    expect(rule.condition).toBe("selection and selection_role");
    const role = rule.selections.find((s) => s.name === "selection_role");
    expect(role?.matches[0]?.modifier).toBe("contains");
    expect(role?.matches[0]?.values).toContain("Admin");
  });

  it("expands 1 of wildcards in condition", () => {
    const rule = parseSigmaRule(COMPLEX_SIGMA);
    const ast = expandWildcards(rule, parseCondition(rule.condition));
    expect(ast.type).toBe("or");
  });
});

describe("listConvertibleTargets", () => {
  it("exposes exactly the nine product targets", () => {
    const ids = listConvertibleTargets().map((t) => t.id);
    expect(ids).toEqual([
      "cortexxdr",
      "crowdstrike",
      "datadog",
      "snowflake",
      "splunk",
      "elasticsearch",
      "opensearch",
      "sentinelone",
      "qradar",
    ]);
    expect(TARGET_LANGUAGES.every((t) => t.convertible)).toBe(true);
    expect(ids).not.toContain("cloudtrail");
    expect(ids).not.toContain("cloudwatch");
    expect(ids).not.toContain("eventbridge");
    expect(ids).not.toContain("lambda");
    expect(ids).not.toContain("esql");
  });
});

describe("convertSigma", () => {
  it("converts to Elasticsearch (ES|QL)", () => {
    const result = convertSigma(SAMPLE_SIGMA, "elasticsearch");
    expect(result.supported).toBe(true);
    expect(result.label).toBe("Elasticsearch");
    expect(result.query).toContain("FROM logs-aws.cloudtrail-*");
    expect(result.query).toContain("lambda.amazonaws.com");
    expect(result.source).toBe("converted");
  });

  it("converts to Splunk", () => {
    const result = convertSigma(SAMPLE_SIGMA, "splunk");
    expect(result.supported).toBe(true);
    expect(result.query).toContain("index=aws");
    expect(result.query).toContain("CreateFunction20150331");
  });

  it("converts to Datadog", () => {
    const result = convertSigma(SAMPLE_SIGMA, "datadog");
    expect(result.supported).toBe(true);
    expect(result.query).toContain("source:cloudtrail");
    expect(result.query).toContain("@evt.name");
  });

  it("converts to Cortex XDR, CrowdStrike, OpenSearch, SentinelOne, QRadar, Snowflake", () => {
    const cortex = convertSigma(SAMPLE_SIGMA, "cortexxdr");
    expect(cortex.supported).toBe(true);
    expect(cortex.query).toContain("dataset =");
    expect(cortex.query).toContain("CreateFunction20150331");

    const cs = convertSigma(SAMPLE_SIGMA, "crowdstrike");
    expect(cs.supported).toBe(true);
    expect(cs.query).toContain("eventName=");

    const os = convertSigma(SAMPLE_SIGMA, "opensearch");
    expect(os.supported).toBe(true);
    expect(os.query).toContain("eventName:");

    const s1 = convertSigma(SAMPLE_SIGMA, "sentinelone");
    expect(s1.supported).toBe(true);
    expect(s1.query).toContain("eventName");

    const qr = convertSigma(SAMPLE_SIGMA, "qradar");
    expect(qr.supported).toBe(true);
    expect(qr.query).toContain("SELECT");
    expect(qr.query).toContain("FROM events");

    const snow = convertSigma(SAMPLE_SIGMA, "snowflake");
    expect(snow.supported).toBe(true);
    expect(snow.query).toContain("SELECT");
    expect(snow.query).toContain("FROM cloudtrail_logs");
  });

  it("falls back to stored curated query when provided", () => {
    const result = convertSigma(SAMPLE_SIGMA, "elasticsearch", {
      storedRules: { elasticsearch: "FROM logs-* | WHERE false" },
      preferStored: true,
    });
    expect(result.supported).toBe(true);
    expect(result.source).toBe("stored");
    expect(result.query).toBe("FROM logs-* | WHERE false");
  });

  it("prefers conversion over stored when preferStored is false", () => {
    const result = convertSigma(SAMPLE_SIGMA, "splunk", {
      storedRules: { splunk: "index=aws curated" },
      preferStored: false,
    });
    expect(result.source).toBe("hybrid");
    expect(result.query).not.toBe("index=aws curated");
  });
});
