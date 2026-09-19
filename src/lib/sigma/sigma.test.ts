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

const AZURE_ACTIVITY_SIGMA = `title: Azure Firewall Modified or Deleted
logsource:
    product: azure
    service: activitylogs
detection:
    selection:
        operationName:
            - MICROSOFT.NETWORK/AZUREFIREWALLS/WRITE
            - MICROSOFT.NETWORK/AZUREFIREWALLS/DELETE
    condition: selection
level: medium`;

const AZURE_AUDIT_SIGMA = `title: Users Added to Global or Device Admin Roles
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        Category: RoleManagement
        OperationName|contains|all:
            - 'Add'
            - 'member to role'
    condition: selection
level: high`;

const GCP_AUDIT_SIGMA = `title: GCP Access Policy Deleted
logsource:
    product: gcp
    service: gcp.audit
detection:
    selection:
        data.protoPayload.authorizationInfo.permission:
            - 'accesscontextmanager.accessPolicies.delete'
        data.protoPayload.authorizationInfo.granted: 'true'
        data.protoPayload.serviceName: 'accesscontextmanager.googleapis.com'
    condition: selection
level: medium`;

const GCP_WORKSPACE_SIGMA = `title: Google Workspace MFA Disabled
logsource:
    product: gcp
    service: google_workspace.admin
detection:
    selection:
        eventService: admin.googleapis.com
        eventName:
            - ENFORCE_STRONG_AUTHENTICATION
            - ALLOW_STRONG_AUTHENTICATION
    condition: selection
level: medium`;

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

  it("uses source:azure for Azure Sigma logsource, not CloudTrail", () => {
    const result = convertSigma(AZURE_ACTIVITY_SIGMA, "datadog");
    expect(result.supported).toBe(true);
    expect(result.query).toMatch(/^source:azure /);
    expect(result.query).not.toContain("source:cloudtrail");
    expect(result.query).toContain("@operationName:MICROSOFT.NETWORK/AZUREFIREWALLS/WRITE");
  });

  it("uses source:gcp for GCP audit Sigma logsource", () => {
    const result = convertSigma(GCP_AUDIT_SIGMA, "datadog");
    expect(result.query).toMatch(/^source:gcp /);
    expect(result.query).not.toContain("source:cloudtrail");
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

describe("provider-aware conversions", () => {
  it("maps Azure activity logs off CloudTrail for Splunk, ES|QL, Snowflake, Cortex, and QRadar", () => {
    const splunk = convertSigma(AZURE_ACTIVITY_SIGMA, "splunk");
    expect(splunk.query).toContain("index=azure");
    expect(splunk.query).toContain("sourcetype=azure:activitylogs");
    expect(splunk.query).toContain("operationName=");
    expect(splunk.query).not.toContain("index=aws");
    expect(splunk.query).not.toContain("aws:cloudtrail");

    const es = convertSigma(AZURE_ACTIVITY_SIGMA, "elasticsearch");
    expect(es.query).toContain("FROM logs-azure.activitylogs-*");
    expect(es.query).toContain("operationName");
    expect(es.query).not.toContain("logs-aws.cloudtrail");

    const snow = convertSigma(AZURE_ACTIVITY_SIGMA, "snowflake");
    expect(snow.query).toContain("FROM azure_activity_logs");
    expect(snow.query).not.toContain("cloudtrail_logs");

    const cortex = convertSigma(AZURE_ACTIVITY_SIGMA, "cortexxdr");
    expect(cortex.query).toContain("dataset = cloud_audit_logs");

    const qradar = convertSigma(AZURE_ACTIVITY_SIGMA, "qradar");
    expect(qradar.query).toContain("%Azure%");
    expect(qradar.query).toContain('"operationName"');
    expect(qradar.query).not.toContain("AWS CloudTrail");
  });

  it("maps Entra audit logs to Azure AD sources, not activity logs or CloudTrail", () => {
    const datadog = convertSigma(AZURE_AUDIT_SIGMA, "datadog");
    expect(datadog.query).toMatch(/^source:azure\.activedirectory /);
    expect(datadog.query).toContain("@OperationName");
    expect(datadog.query).not.toContain("@evt.name");
    expect(datadog.query).not.toContain("source:cloudtrail");

    const splunk = convertSigma(AZURE_AUDIT_SIGMA, "splunk");
    expect(splunk.query).toContain("sourcetype=azure:aad:audit");
    expect(splunk.query).not.toContain("aws:cloudtrail");

    const es = convertSigma(AZURE_AUDIT_SIGMA, "elasticsearch");
    expect(es.query).toContain("FROM logs-azure.auditlogs-*");
  });

  it("maps GCP audit logs off CloudTrail for every index-based backend", () => {
    const datadog = convertSigma(GCP_AUDIT_SIGMA, "datadog");
    expect(datadog.query).toMatch(/^source:gcp /);
    expect(datadog.query).toContain("@data.protoPayload.serviceName");
    expect(datadog.query).not.toContain("@evt.name");

    const splunk = convertSigma(GCP_AUDIT_SIGMA, "splunk");
    expect(splunk.query).toContain("index=gcp");
    expect(splunk.query).toContain("sourcetype=google:gcp:pubsub:message");
    expect(splunk.query).not.toContain("index=aws");

    const es = convertSigma(GCP_AUDIT_SIGMA, "elasticsearch");
    expect(es.query).toContain("FROM logs-gcp.audit-*");
    expect(es.query).not.toContain("logs-aws.cloudtrail");

    const snow = convertSigma(GCP_AUDIT_SIGMA, "snowflake");
    expect(snow.query).toContain("FROM gcp_audit_logs");

    const qradar = convertSigma(GCP_AUDIT_SIGMA, "qradar");
    expect(qradar.query).toContain("Google Cloud");
    expect(qradar.query).not.toContain("AWS CloudTrail");
  });

  it("maps Google Workspace eventName to gsuite, not CloudTrail @evt.name", () => {
    const datadog = convertSigma(GCP_WORKSPACE_SIGMA, "datadog");
    expect(datadog.query).toMatch(/^source:gsuite /);
    expect(datadog.query).toContain("@eventName:ENFORCE_STRONG_AUTHENTICATION");
    expect(datadog.query).not.toContain("@evt.name");
    expect(datadog.query).not.toContain("source:cloudtrail");
    expect(datadog.query).not.toContain("source:gcp ");

    const es = convertSigma(GCP_WORKSPACE_SIGMA, "elasticsearch");
    expect(es.query).toContain("FROM logs-google_workspace.admin-*");

    const splunk = convertSigma(GCP_WORKSPACE_SIGMA, "splunk");
    expect(splunk.query).toContain("index=gws");
    expect(splunk.query).toContain("sourcetype=google:workspace:reports");
  });
});
