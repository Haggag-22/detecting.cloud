import type { ParsedSigmaRule } from "./types";

export type LogsourceFamily =
  | "aws.cloudtrail"
  | "azure.activitylogs"
  | "azure.auditlogs"
  | "azure.signinlogs"
  | "azure.pim"
  | "azure.riskdetection"
  | "gcp.audit"
  | "gcp.workspace"
  | "kubernetes"
  | "unknown";

export type CloudProvider = "aws" | "azure" | "gcp" | "kubernetes" | "unknown";

export interface LogsourceMapping {
  family: LogsourceFamily;
  provider: CloudProvider;
  product: string;
  service: string;
  datadogSource: string;
  splunkIndex: string;
  splunkSourcetype: string;
  elasticsearchFrom: string;
  snowflakeTable: string;
  snowflakeTimeColumn: string;
  cortexDataset: string;
  qradarLogSourceFilter: string;
  outputFields: string[];
  /** Equals-matches lifted into the Splunk base search */
  splunkBaseFields: string[];
  /** Datadog Cloud SIEM facet remaps; empty means keep `@field` */
  datadogFacetMap: Record<string, string>;
}

const AWS_DATADOG_FACETS: Record<string, string> = {
  eventName: "@evt.name",
  eventSource: "@evt.source",
  "userIdentity.arn": "@userIdentity.arn",
  "userIdentity.type": "@userIdentity.type",
  sourceIPAddress: "@network.client.ip",
};

const AWS_OUTPUT = ["eventName", "eventSource", "userIdentity.arn", "sourceIPAddress"];
const AZURE_ACTIVITY_OUTPUT = ["operationName", "caller", "resourceId", "resultType"];
const AZURE_ENTRA_OUTPUT = ["OperationName", "Category", "ResultType", "ResultDescription"];
const GCP_AUDIT_OUTPUT = [
  "data.protoPayload.methodName",
  "data.protoPayload.serviceName",
  "data.protoPayload.authenticationInfo.principalEmail",
];
const GCP_WORKSPACE_OUTPUT = ["eventName", "eventService"];
const K8S_OUTPUT = ["verb", "objectRef.resource", "user.username", "sourceIPs"];

function mapping(
  partial: Omit<LogsourceMapping, "product" | "service"> & { product?: string; service?: string },
  product: string,
  service: string
): LogsourceMapping {
  return { ...partial, product, service };
}

function azureFamily(service: string): LogsourceFamily {
  if (service.includes("signin")) return "azure.signinlogs";
  if (service.includes("activity")) return "azure.activitylogs";
  if (service === "pim") return "azure.pim";
  if (service.includes("risk")) return "azure.riskdetection";
  return "azure.auditlogs";
}

function isAzureService(service: string): boolean {
  return (
    service.includes("activitylog") ||
    service.includes("auditlog") ||
    service.includes("signinlog") ||
    service === "pim" ||
    service.includes("riskdetection") ||
    service.includes("azure")
  );
}

/**
 * Resolve Sigma logsource to SIEM index/source/table mappings.
 * Never assume CloudTrail unless the rule is actually AWS.
 */
export function classifyLogsource(rule: ParsedSigmaRule): LogsourceMapping {
  const product = (rule.logsource?.product ?? "").toLowerCase().trim();
  const service = (rule.logsource?.service ?? "").toLowerCase().trim();

  if (product === "kubernetes" || service.startsWith("kube")) {
    return mapping(
      {
        family: "kubernetes",
        provider: "kubernetes",
        datadogSource: "source:kubernetes",
        splunkIndex: "k8s",
        splunkSourcetype: "kube:apiserver",
        elasticsearchFrom: "logs-kubernetes.audit_logs-*",
        snowflakeTable: "kubernetes_audit_logs",
        snowflakeTimeColumn: "timestamp",
        cortexDataset: "xdr_data",
        qradarLogSourceFilter: "LOGSOURCETYPENAME(devicetype) ILIKE '%Kubernetes%'",
        outputFields: K8S_OUTPUT,
        splunkBaseFields: ["verb", "objectRef.resource"],
        datadogFacetMap: {},
      },
      product,
      service
    );
  }

  if (product === "azure" || isAzureService(service)) {
    const family = azureFamily(service);
    const entra = family !== "azure.activitylogs";
    const elasticsearchFrom =
      family === "azure.activitylogs"
        ? "logs-azure.activitylogs-*"
        : family === "azure.signinlogs"
          ? "logs-azure.signinlogs-*"
          : family === "azure.riskdetection"
            ? "logs-azure.identity_protection-*"
            : "logs-azure.auditlogs-*";
    const splunkSourcetype =
      family === "azure.activitylogs"
        ? "azure:activitylogs"
        : family === "azure.signinlogs"
          ? "azure:aad:signin"
          : family === "azure.riskdetection"
            ? "azure:aad:identityprotection"
            : family === "azure.pim"
              ? "azure:aad:pim"
              : "azure:aad:audit";
    const snowflakeTable =
      family === "azure.activitylogs"
        ? "azure_activity_logs"
        : family === "azure.signinlogs"
          ? "azure_signin_logs"
          : family === "azure.riskdetection"
            ? "azure_identity_protection_logs"
            : family === "azure.pim"
              ? "azure_pim_logs"
              : "azure_audit_logs";

    return mapping(
      {
        family,
        provider: "azure",
        datadogSource: entra ? "source:azure.activedirectory" : "source:azure",
        splunkIndex: "azure",
        splunkSourcetype,
        elasticsearchFrom,
        snowflakeTable,
        snowflakeTimeColumn: "TimeGenerated",
        cortexDataset: "cloud_audit_logs",
        qradarLogSourceFilter: "LOGSOURCETYPENAME(devicetype) ILIKE '%Azure%'",
        outputFields: entra ? AZURE_ENTRA_OUTPUT : AZURE_ACTIVITY_OUTPUT,
        splunkBaseFields: entra ? ["OperationName", "Category"] : ["operationName"],
        datadogFacetMap: {},
      },
      product,
      service
    );
  }

  if (service.startsWith("google_workspace") || service.includes("gsuite") || product === "google_workspace") {
    const workspaceStream = service.includes("login")
      ? "logs-google_workspace.login-*"
      : "logs-google_workspace.admin-*";
    return mapping(
      {
        family: "gcp.workspace",
        provider: "gcp",
        datadogSource: "source:gsuite",
        splunkIndex: "gws",
        splunkSourcetype: "google:workspace:reports",
        elasticsearchFrom: workspaceStream,
        snowflakeTable: "google_workspace_logs",
        snowflakeTimeColumn: "timestamp",
        cortexDataset: "cloud_audit_logs",
        qradarLogSourceFilter: "LOGSOURCETYPENAME(devicetype) ILIKE '%Google Workspace%' OR LOGSOURCETYPENAME(devicetype) ILIKE '%GSuite%'",
        outputFields: GCP_WORKSPACE_OUTPUT,
        splunkBaseFields: ["eventName", "eventService"],
        datadogFacetMap: {},
      },
      product,
      service
    );
  }

  if (product === "gcp" || service.includes("gcp") || service === "gcp.audit") {
    return mapping(
      {
        family: "gcp.audit",
        provider: "gcp",
        datadogSource: "source:gcp",
        splunkIndex: "gcp",
        splunkSourcetype: "google:gcp:pubsub:message",
        elasticsearchFrom: "logs-gcp.audit-*",
        snowflakeTable: "gcp_audit_logs",
        snowflakeTimeColumn: "timestamp",
        cortexDataset: "cloud_audit_logs",
        qradarLogSourceFilter: "LOGSOURCETYPENAME(devicetype) ILIKE '%Google Cloud%'",
        outputFields: GCP_AUDIT_OUTPUT,
        splunkBaseFields: [
          "data.protoPayload.methodName",
          "gcp.audit.method_name",
          "data.protoPayload.serviceName",
        ],
        datadogFacetMap: {},
      },
      product,
      service
    );
  }

  if (product === "aws" || service === "cloudtrail" || service === "" || product === "") {
    return mapping(
      {
        family: "aws.cloudtrail",
        provider: "aws",
        datadogSource: "source:cloudtrail",
        splunkIndex: "aws",
        splunkSourcetype: "aws:cloudtrail",
        elasticsearchFrom: "logs-aws.cloudtrail-*",
        snowflakeTable: "cloudtrail_logs",
        snowflakeTimeColumn: "event_time",
        cortexDataset: "cloud_audit_logs",
        qradarLogSourceFilter: "LOGSOURCETYPENAME(devicetype) = 'AWS CloudTrail'",
        outputFields: AWS_OUTPUT,
        splunkBaseFields: ["eventName", "eventSource"],
        datadogFacetMap: AWS_DATADOG_FACETS,
      },
      product,
      service
    );
  }

  return mapping(
    {
      family: "unknown",
      provider: "unknown",
      datadogSource: product ? `source:${product}` : "source:*",
      splunkIndex: product || "*",
      splunkSourcetype: service || "*",
      elasticsearchFrom: "logs-*",
      snowflakeTable: "logs",
      snowflakeTimeColumn: "event_time",
      cortexDataset: "xdr_data",
      qradarLogSourceFilter: "1=1",
      outputFields: [],
      splunkBaseFields: [],
      datadogFacetMap: {},
    },
    product,
    service
  );
}

export function logsourceLabel(mapping: LogsourceMapping): string {
  const product = mapping.product || "aws";
  const service = mapping.service || (mapping.provider === "aws" ? "cloudtrail" : "");
  return service ? `${product}/${service}` : product;
}
