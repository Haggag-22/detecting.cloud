import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { convertSigmaToAll } from "./convert";
import type { SigmaTargetLanguage } from "./types";

function load(path: string): string {
  return readFileSync(path, "utf8");
}

const RULES = {
  aws: load("rules/aws/iam-passrole-privilege-escalation/sigma.yml"),
  azureActivity: load("rules/azure/azure-firewall-modified-or-deleted/sigma.yml"),
  azureAudit: load("rules/azure/users-added-to-global-or-device-admin-roles/sigma.yml"),
  azureSignin: load("rules/azure/users-authenticating-to-other-azure-ad-tenants/sigma.yml"),
  azurePim: load("rules/azure/too-many-global-admins/sigma.yml"),
  azureRisk: load("rules/azure/unfamiliar-sign-in-properties/sigma.yml"),
  gcpAudit: load("rules/gcp/gcp-access-policy-deleted/sigma.yml"),
  gcpWorkspace: load("rules/gcp/google-workspace-mfa-disabled/sigma.yml"),
} as const;

const CLOUDTRAIL_LEAKS = [
  "source:cloudtrail",
  "index=aws",
  "sourcetype=aws:cloudtrail",
  "logs-aws.cloudtrail",
  "FROM cloudtrail_logs",
  "AWS CloudTrail",
  "@evt.name",
  "@evt.source",
];

function queries(sigma: string): Record<SigmaTargetLanguage, string> {
  return Object.fromEntries(convertSigmaToAll(sigma).map((r) => [r.language, r.query])) as Record<
    SigmaTargetLanguage,
    string
  >;
}

function expectNoCloudTrail(sigma: string, label: string) {
  const all = convertSigmaToAll(sigma);
  for (const result of all) {
    expect(result.supported, `${label} ${result.language} should convert`).toBe(true);
    expect(result.query.trim().length, `${label} ${result.language} empty`).toBeGreaterThan(0);
    for (const leak of CLOUDTRAIL_LEAKS) {
      expect(result.query, `${label} ${result.language} leaked ${leak}`).not.toContain(leak);
    }
  }
}

describe("full provider × language matrix", () => {
  it("AWS CloudTrail keeps CloudTrail sources and eventName facets", () => {
    const q = queries(RULES.aws);
    expect(q.datadog).toMatch(/^source:cloudtrail /);
    expect(q.datadog).toContain("@evt.name");
    expect(q.splunk).toContain("index=aws sourcetype=aws:cloudtrail");
    expect(q.elasticsearch).toContain("FROM logs-aws.cloudtrail-*");
    expect(q.snowflake).toContain("FROM cloudtrail_logs");
    expect(q.qradar).toContain("AWS CloudTrail");
    expect(q.cortexxdr).toContain("dataset = cloud_audit_logs");
    expect(q.crowdstrike).toContain("eventName=");
    expect(q.opensearch).toContain("eventName:");
    expect(q.sentinelone).toContain("eventName");
    expect(q.crowdstrike).toContain("CreateFunction20150331");
  });

  it("Azure activity logs never use CloudTrail in any language", () => {
    expectNoCloudTrail(RULES.azureActivity, "azure-activity");
    const q = queries(RULES.azureActivity);
    expect(q.datadog).toMatch(/^source:azure /);
    expect(q.datadog).toContain("@operationName");
    expect(q.splunk).toContain("index=azure sourcetype=azure:activitylogs");
    expect(q.splunk).toContain("operationName=");
    expect(q.elasticsearch).toContain("FROM logs-azure.activitylogs-*");
    expect(q.elasticsearch).toContain("operationName");
    expect(q.snowflake).toContain("FROM azure_activity_logs");
    expect(q.qradar).toContain("%Azure%");
    expect(q.qradar).toContain("operationName");
    expect(q.cortexxdr).toContain("dataset = cloud_audit_logs");
    expect(q.cortexxdr).toContain("operationName");
    expect(q.crowdstrike).toContain("operationName=");
    expect(q.opensearch).toContain("operationName:");
    expect(q.sentinelone).toContain("operationName");
  });

  it("Azure Entra audit logs map to Azure AD, not activity logs or CloudTrail", () => {
    expectNoCloudTrail(RULES.azureAudit, "azure-audit");
    const q = queries(RULES.azureAudit);
    expect(q.datadog).toMatch(/^source:azure\.activedirectory /);
    expect(q.datadog).toContain("@OperationName");
    expect(q.splunk).toContain("sourcetype=azure:aad:audit");
    expect(q.elasticsearch).toContain("FROM logs-azure.auditlogs-*");
    expect(q.snowflake).toContain("FROM azure_audit_logs");
    expect(q.crowdstrike).toContain("OperationName=");
    expect(q.opensearch).toContain("OperationName:");
    expect(q.sentinelone).toContain("OperationName");
  });

  it("Azure sign-in, PIM, and risk detection pick distinct sources", () => {
    expectNoCloudTrail(RULES.azureSignin, "azure-signin");
    expectNoCloudTrail(RULES.azurePim, "azure-pim");
    expectNoCloudTrail(RULES.azureRisk, "azure-risk");

    const signin = queries(RULES.azureSignin);
    expect(signin.splunk).toContain("sourcetype=azure:aad:signin");
    expect(signin.elasticsearch).toContain("FROM logs-azure.signinlogs-*");
    expect(signin.snowflake).toContain("FROM azure_signin_logs");
    expect(signin.datadog).toMatch(/^source:azure\.activedirectory /);

    const pim = queries(RULES.azurePim);
    expect(pim.splunk).toContain("sourcetype=azure:aad:pim");
    expect(pim.datadog).toContain("source:azure.activedirectory");
    expect(pim.crowdstrike).toContain("riskEventType=");

    const risk = queries(RULES.azureRisk);
    expect(risk.splunk).toContain("sourcetype=azure:aad:identityprotection");
    expect(risk.elasticsearch).toContain("FROM logs-azure.identity_protection-*");
    expect(risk.snowflake).toContain("FROM azure_identity_protection_logs");
  });

  it("GCP audit logs never use CloudTrail in any language", () => {
    expectNoCloudTrail(RULES.gcpAudit, "gcp-audit");
    const q = queries(RULES.gcpAudit);
    expect(q.datadog).toMatch(/^source:gcp /);
    expect(q.datadog).toContain("@data.protoPayload");
    expect(q.splunk).toContain("index=gcp sourcetype=google:gcp:pubsub:message");
    expect(q.elasticsearch).toContain("FROM logs-gcp.audit-*");
    expect(q.snowflake).toContain("FROM gcp_audit_logs");
    expect(q.qradar).toContain("Google Cloud");
    expect(q.cortexxdr).toContain("dataset = cloud_audit_logs");
    expect(q.crowdstrike).toContain("data.protoPayload");
    expect(q.opensearch).toContain("data.protoPayload");
    expect(q.sentinelone).toContain("data.protoPayload");
  });

  it("Google Workspace uses gsuite source and keeps eventName (not @evt.name)", () => {
    const q = queries(RULES.gcpWorkspace);
    for (const [lang, query] of Object.entries(q)) {
      expect(query, `${lang} leaked CloudTrail source`).not.toContain("source:cloudtrail");
      expect(query, `${lang} leaked AWS index`).not.toContain("index=aws");
      expect(query, `${lang} leaked CloudTrail stream`).not.toContain("logs-aws.cloudtrail");
      expect(query, `${lang} leaked @evt.name`).not.toContain("@evt.name");
    }
    expect(q.datadog).toMatch(/^source:gsuite /);
    expect(q.datadog).toContain("@eventName:ENFORCE_STRONG_AUTHENTICATION");
    expect(q.splunk).toContain("index=gws sourcetype=google:workspace:reports");
    expect(q.elasticsearch).toContain("FROM logs-google_workspace.admin-*");
    expect(q.snowflake).toContain("FROM google_workspace_logs");
    expect(q.crowdstrike).toContain("eventName=");
    expect(q.opensearch).toContain("eventName:");
    expect(q.sentinelone).toContain("eventName");
  });

  it("every language converts every sampled provider rule", () => {
    for (const [name, sigma] of Object.entries(RULES)) {
      for (const result of convertSigmaToAll(sigma)) {
        expect(result.supported, `${name}/${result.language}`).toBe(true);
        expect(result.query.trim().length, `${name}/${result.language}`).toBeGreaterThan(4);
      }
    }
  });
});
