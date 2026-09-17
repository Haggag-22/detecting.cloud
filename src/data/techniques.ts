import type { Technique, TechniqueCategory } from "./techniqueTypes";
import { techniquesFromDir } from "./loadTechniquesFromDir";

export type { Technique, TechniqueCategory } from "./techniqueTypes";

export const techniqueCategories: Record<TechniqueCategory, { label: string; description: string }> = {
  "initial-access": { label: "Initial Access", description: "Gaining a foothold in the cloud environment" },
  "credential-access": { label: "Credential Access", description: "Stealing or forging credentials" },
  "privilege-escalation": { label: "Privilege Escalation", description: "Gaining higher privileges" },
  persistence: { label: "Persistence", description: "Maintaining long-term access" },
  "lateral-movement": { label: "Lateral Movement", description: "Moving across accounts and services" },
  exfiltration: { label: "Exfiltration", description: "Stealing data from cloud resources" },
  "defense-evasion": { label: "Defense Evasion", description: "Avoiding detection" },
  discovery: { label: "Discovery", description: "Enumerating accounts, services, and defensive coverage" },
  impact: { label: "Impact", description: "Destroying, disrupting, or encrypting cloud resources" },
};

export function getTechniqueCloudProvider(t: Technique): "aws" | "azure" | "gcp" | "kubernetes" {
  return t.cloudProvider ?? "aws";
}

export const techniques: Technique[] = techniquesFromDir;

export function getTechniqueById(id: string): Technique | undefined {
  return techniques.find((t) => t.id === id);
}

export function getTechniquesByIds(ids: string[]): Technique[] {
  return ids.map((id) => techniques.find((t) => t.id === id)).filter(Boolean) as Technique[];
}

export function getTechniquesByCategory(category: TechniqueCategory): Technique[] {
  return techniques.filter((t) => t.category === category);
}

/** Counts for the All / AWS / Azure / GCP / Kubernetes provider tabs */
export function getTechniqueCountsByCloudProvider(): Record<
  "all" | "aws" | "azure" | "gcp" | "kubernetes",
  number
> {
  const counts = {
    all: techniques.length,
    aws: 0,
    azure: 0,
    gcp: 0,
    kubernetes: 0,
  } as Record<"all" | "aws" | "azure" | "gcp" | "kubernetes", number>;

  for (const t of techniques) {
    counts[getTechniqueCloudProvider(t)] += 1;
  }
  return counts;
}
