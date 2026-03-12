/**
 * Maps detection rules to techniques based on event patterns.
 * Used for Detection Coverage Mapping.
 */

import { detections } from "@/data/detections";
import { techniques } from "@/data/techniques";

export interface TechniqueCoverage {
  techniqueId: string;
  techniqueName: string;
  coverage: "covered" | "partial" | "not_covered";
  detectionIds: string[];
  eventPatterns: string[];
}

const eventPatternToTechnique: Record<string, string[]> = {
  CreateAccessKey: ["tech-beanstalk-credential-pivot", "tech-iam-access-key"],
  AssumeRole: ["tech-beanstalk-credential-pivot"],
  CreateAccessEntry: ["tech-eks-access-entry"],
  AssociateAccessPolicy: ["tech-eks-access-entry"],
  PutBucketAcl: ["tech-s3-acl-persistence"],
  PutObjectAcl: ["tech-s3-acl-persistence"],
  DescribeConfigurationSettings: ["tech-beanstalk-env-theft", "tech-beanstalk-credential-pivot"],
  StartBuild: ["tech-codebuild-env-theft"],
  DeleteFlowLogs: ["tech-vpc-flow-logs-removal"],
  LeaveOrganization: ["tech-organizations-leave"],
  SendSSHPublicKey: ["tech-ec2-instance-connect"],
  SendSerialConsoleSSHPublicKey: ["tech-ec2-serial-console"],
  StartSession: ["tech-ssm-session"],
  CreateSnapshot: ["tech-volume-snapshot-loot"],
  ModifySnapshotAttribute: ["tech-volume-snapshot-loot", "tech-public-snapshot-loot"],
  CopySnapshot: ["tech-volume-snapshot-loot", "tech-public-snapshot-loot"],
  ListIdentities: ["tech-ses-enumeration"],
  GetIdentityVerificationAttributes: ["tech-ses-enumeration"],
};

/**
 * Extract event names from a detection rule (from EventBridge or CloudTrail).
 */
function extractEventNamesFromDetection(detection: { id: string; rules: { eventbridge?: string; cloudtrail?: string } }): string[] {
  const names: string[] = [];
  if (detection.rules.eventbridge) {
    try {
      const p = JSON.parse(detection.rules.eventbridge) as { detail?: { eventName?: string[] } };
      if (p.detail?.eventName) names.push(...p.detail.eventName);
    } catch {}
  }
  if (detection.rules.cloudtrail) {
    const matches = detection.rules.cloudtrail.matchAll(/eventName\s*(?:=\s*['"]([^'"]+)['"]|IN\s*\(([^)]+)\))/g);
    for (const m of matches) {
      if (m[1]) names.push(m[1]);
      if (m[2]) names.push(...m[2].split(",").map((s) => s.trim().replace(/^['"]|['"]$/g, "")));
    }
  }
  return [...new Set(names)];
}

/**
 * Compute coverage for each technique based on uploaded/selected detection rules.
 */
export function computeCoverage(detectionIds: string[]): TechniqueCoverage[] {
  const selectedDetections = detections.filter((d) => detectionIds.includes(d.id));
  const allEventNames = new Set<string>();
  selectedDetections.forEach((d) => extractEventNamesFromDetection(d).forEach((n) => allEventNames.add(n)));

  const techniqueToDetections: Record<string, Set<string>> = {};
  const techniqueToPatterns: Record<string, Set<string>> = {};

  for (const [eventName, techIds] of Object.entries(eventPatternToTechnique)) {
    for (const techId of techIds) {
      if (!techniqueToDetections[techId]) techniqueToDetections[techId] = new Set();
      if (!techniqueToPatterns[techId]) techniqueToPatterns[techId] = new Set();
      techniqueToPatterns[techId].add(eventName);
      if (allEventNames.has(eventName)) {
        const dets = selectedDetections.filter((d) => extractEventNamesFromDetection(d).includes(eventName));
        dets.forEach((d) => techniqueToDetections[techId].add(d.id));
      }
    }
  }

  // Also use technique.detectionIds from our data
  const result: TechniqueCoverage[] = [];

  for (const tech of techniques) {
    const directDets = tech.detectionIds?.filter((id) => detectionIds.includes(id)) ?? [];
    const patternDets = techniqueToDetections[tech.id] ?? new Set();
    const allDets = new Set([...directDets, ...patternDets]);
    const patterns = techniqueToPatterns[tech.id] ?? new Set();

    let coverage: "covered" | "partial" | "not_covered" = "not_covered";
    if (allDets.size >= 2) coverage = "covered";
    else if (allDets.size === 1) coverage = "partial";

    result.push({
      techniqueId: tech.id,
      techniqueName: tech.name,
      coverage,
      detectionIds: Array.from(allDets),
      eventPatterns: Array.from(patterns),
    });
  }

  return result.sort((a, b) => {
    const order = { covered: 0, partial: 1, not_covered: 2 };
    return order[a.coverage] - order[b.coverage];
  });
}

/**
 * Compute overall coverage score (0-100).
 */
export function computeCoverageScore(detectionIds: string[]): number {
  const coverage = computeCoverage(detectionIds);
  const covered = coverage.filter((c) => c.coverage === "covered").length;
  const partial = coverage.filter((c) => c.coverage === "partial").length;
  const total = coverage.length;
  if (total === 0) return 0;
  return Math.round(((covered + partial * 0.5) / total) * 100);
}
