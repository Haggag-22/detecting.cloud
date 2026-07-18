import { describe, expect, it } from "vitest";
import { parseCondition, expandWildcards } from "./condition";
import { convertSigma } from "./convert";
import { parseSigmaRule } from "./parse";

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

describe("convertSigma", () => {
  it("converts to ES|QL", () => {
    const result = convertSigma(SAMPLE_SIGMA, "esql");
    expect(result.supported).toBe(true);
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

  it("converts to Athena / CloudWatch / EventBridge", () => {
    expect(convertSigma(SAMPLE_SIGMA, "cloudtrail").query).toContain("SELECT");
    expect(convertSigma(SAMPLE_SIGMA, "cloudwatch").query).toContain("fields");
    const eb = convertSigma(SAMPLE_SIGMA, "eventbridge");
    expect(eb.supported).toBe(true);
    expect(JSON.parse(eb.query).detail.eventName).toContain("CreateFunction20150331");
  });

  it("falls back to stored lambda and marks unsupported without store", () => {
    const unsupported = convertSigma(SAMPLE_SIGMA, "lambda");
    expect(unsupported.supported).toBe(false);
    const stored = convertSigma(SAMPLE_SIGMA, "lambda", {
      storedRules: { lambda: "def lambda_handler(event, context):\n    pass\n" },
    });
    expect(stored.supported).toBe(true);
    expect(stored.source).toBe("stored");
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
