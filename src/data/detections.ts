/**
 * Detection catalog.
 *
 * Rule content lives on disk under rules/<provider>/<rule-slug>/ and is loaded
 * by loadRulesFromDir.ts. This module keeps the public API stable for pages.
 */
export type {
  RuleFormat,
  RuleFormats,
  TelemetrySource,
  ThreatContext,
  TelemetryValidation,
  FieldMapping,
  DataModeling,
  EnrichmentContext,
  DetectionLogicExplanation,
  DetectionQuality,
  CommunityConfidence,
  DetectionFlowStep,
  DetectionLifecycle,
  DetectionCloudProvider,
  Detection,
} from "./detectionTypes";

export { getDetectionCloudProvider } from "./detectionTypes";

import type { Detection, DetectionCloudProvider, TelemetrySource } from "./detectionTypes";
import { getDetectionCloudProvider } from "./detectionTypes";
import { detectionsFromRules } from "./loadRulesFromDir";

export const detections: Detection[] = detectionsFromRules;

/** Identity-related AWS services shown under IAM in Detection Rules / Coverage */
const IAM_BROWSE_SERVICES = new Set([
  "STS",
  "IAM Identity Center",
  "Directory Service",
  "SSO",
]);

/**
 * Browse/nav primary service. Identity services (STS, IAM Identity Center,
 * Directory Service) fold into IAM so they are not separate empty categories.
 */
export function getBrowseService(service: string): string {
  return IAM_BROWSE_SERVICES.has(service) ? "IAM" : service;
}

/**
 * Get detections grouped by PRIMARY AWS service only (for sidebar navigation).
 * Each rule appears once under its primary service — no duplicates.
 * STS rules are grouped under IAM.
 */
export function getDetectionsByService(
  provider?: DetectionCloudProvider | "all"
): Record<string, Detection[]> {
  const grouped: Record<string, Detection[]> = {};
  const serviceOrder = [
    "IAM",
    "Lambda",
    "EC2",
    "S3",
    "EBS",
    "EFS",
    "DynamoDB",
    "RDS",
    "CloudTrail",
    "Config",
    "KMS",
    "EKS",
    "ECS",
    "Secrets Manager",
    "SSM",
    "SageMaker",
    "SES",
    "CodeBuild",
    "Elastic Beanstalk",
    "CloudFront",
    "Organizations",
    "GuardDuty",
    "Security Hub",
    "VPC",
    "ELB",
    "Route 53",
    "Glue",
  ];

  const pool =
    !provider || provider === "all"
      ? detections
      : detections.filter((d) => getDetectionCloudProvider(d) === provider);

  for (const service of serviceOrder) {
    const serviceDetections = pool.filter((d) => getBrowseService(d.awsService) === service);
    if (serviceDetections.length > 0) {
      grouped[service] = serviceDetections;
    }
  }

  // Include any services not in the fixed AWS order (future Azure/GCP/K8s services)
  for (const d of pool) {
    const browse = getBrowseService(d.awsService);
    if (!grouped[browse]) {
      grouped[browse] = pool.filter((x) => getBrowseService(x.awsService) === browse);
    }
  }

  return grouped;
}

/** Counts for the All / AWS / Azure / GCP / Kubernetes provider tabs */
export function getDetectionCountsByCloudProvider(): Record<
  "all" | DetectionCloudProvider,
  number
> {
  const counts = {
    all: detections.length,
    aws: 0,
    azure: 0,
    gcp: 0,
    kubernetes: 0,
  } as Record<"all" | DetectionCloudProvider, number>;

  for (const d of detections) {
    counts[getDetectionCloudProvider(d)] += 1;
  }
  return counts;
}

/**
 * Get detections for a specific service (primary + related).
 * Identity services are treated as part of IAM for browse/filter.
 */
export function getDetectionsForService(service: string): Detection[] {
  const browse = getBrowseService(service);
  return detections.filter((d) => {
    const primary = getBrowseService(d.awsService);
    if (primary === browse) return true;
    if (d.relatedServices.includes(service) || d.relatedServices.includes(browse)) return true;
    if (
      browse === "IAM" &&
      (IAM_BROWSE_SERVICES.has(d.awsService) ||
        d.relatedServices.some((s) => IAM_BROWSE_SERVICES.has(s)))
    ) {
      return true;
    }
    return false;
  });
}

/**
 * Get all unique services that have detection rules.
 */
export function getServicesWithDetections(): string[] {
  const services = new Set<string>();
  detections.forEach((d) => {
    services.add(getBrowseService(d.awsService));
    d.relatedServices.forEach((s) => {
      const browse = getBrowseService(s);
      if (browse !== getBrowseService(d.awsService)) services.add(browse);
    });
  });
  const order = [
    "IAM",
    "Lambda",
    "EC2",
    "S3",
    "EBS",
    "EFS",
    "DynamoDB",
    "RDS",
    "CloudTrail",
    "Config",
    "KMS",
    "EKS",
    "ECS",
    "Secrets Manager",
    "SSM",
    "SageMaker",
    "SES",
    "CodeBuild",
    "Elastic Beanstalk",
    "CloudFront",
    "Organizations",
    "GuardDuty",
    "Security Hub",
    "VPC",
    "ELB",
    "Route 53",
    "Glue",
  ];
  const ordered = order.filter((s) => services.has(s));
  const rest = [...services].filter((s) => !order.includes(s)).sort();
  return [...ordered, ...rest];
}

/**
 * Default telemetry for CloudTrail-based detections when not specified.
 */
export function getDefaultTelemetry(d: Detection): TelemetrySource {
  const primaryLogSource = d.logSources[0] || "AWS CloudTrail";
  return {
    primaryLogSource,
    generatingService: d.awsService.toLowerCase() + ".amazonaws.com",
    importantFields: ["eventName", "userIdentity.arn", "userIdentity.type", "requestParameters", "sourceIPAddress", "eventSource", "eventTime"],
    exampleEvent: JSON.stringify(
      {
        eventVersion: "1.08",
        eventSource: d.awsService.toLowerCase() + ".amazonaws.com",
        eventName: "ExampleEvent",
        userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/dev-user" },
        requestParameters: {},
        sourceIPAddress: "203.0.113.10",
        eventTime: new Date().toISOString(),
      },
      null,
      2
    ),
  };
}

