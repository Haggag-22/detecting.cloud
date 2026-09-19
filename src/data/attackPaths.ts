import type { AttackObjective, AttackPath } from "./attackPathTypes";
import { attackPathsFromDir } from "./loadAttackPathsFromDir";

export type { AttackPath, AttackPathStep, AttackObjective } from "./attackPathTypes";

export const attackObjectiveLabels: Record<AttackObjective, string> = {
  "initial-access": "Initial Access",
  "credential-access": "Credential Access",
  "privilege-escalation": "Privilege Escalation",
  persistence: "Persistence",
  "lateral-movement": "Lateral Movement",
  discovery: "Discovery",
  exfiltration: "Data Exfiltration",
  "defense-evasion": "Defense Evasion",
  impact: "Impact",
};

export function getAttackPathCloudProvider(ap: AttackPath): "aws" | "azure" | "gcp" | "kubernetes" {
  return ap.cloudProvider ?? "aws";
}

export const attackPaths: AttackPath[] = attackPathsFromDir;

export function getAttackPathBySlug(slug: string): AttackPath | undefined {
  return attackPaths.find((ap) => ap.slug === slug);
}

/** Get all attack paths that include a given technique */
export function getAttackPathsForTechnique(techniqueId: string): AttackPath[] {
  return attackPaths.filter((ap) => ap.steps.some((s) => s.techniqueId === techniqueId));
}

export function getAttackPathCountsByCloudProvider(): Record<
  "all" | "aws" | "azure" | "gcp" | "kubernetes",
  number
> {
  const counts = {
    all: attackPaths.length,
    aws: 0,
    azure: 0,
    gcp: 0,
    kubernetes: 0,
  } as Record<"all" | "aws" | "azure" | "gcp" | "kubernetes", number>;

  for (const ap of attackPaths) {
    counts[getAttackPathCloudProvider(ap)] += 1;
  }
  return counts;
}
