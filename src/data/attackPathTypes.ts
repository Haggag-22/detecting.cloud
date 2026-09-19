import type { TechniqueCategory } from "./techniqueTypes";

export interface AttackPathStep {
  techniqueId: string;
  /** Optional context describing how this technique is used in this specific chain */
  context?: string;
}

export type AttackObjective = TechniqueCategory;

export interface AttackPath {
  slug: string;
  title: string;
  description: string;
  severity: "Critical" | "High" | "Medium";
  /** Primary attacker objective — determines the color accent */
  objective: AttackObjective;
  tags: string[];
  /** Ordered chain of technique steps */
  steps: AttackPathStep[];
  /** Attribution to sources (Hacking the Cloud, CloudGoat, etc.) */
  references?: Array<{ source: string; url?: string }>;
  /** Cloud family this path belongs to. Defaults to AWS. */
  cloudProvider?: "aws" | "azure" | "gcp" | "kubernetes";
}
