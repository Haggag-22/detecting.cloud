export type TechniqueCategory =
  | "initial-access"
  | "credential-access"
  | "privilege-escalation"
  | "persistence"
  | "lateral-movement"
  | "exfiltration"
  | "defense-evasion"
  | "discovery"
  | "impact";

export interface Technique {
  id: string;
  name: string;
  shortName: string;
  description: string;
  /** AWS services involved in this technique */
  services: string[];
  /** IAM permissions required to execute this technique */
  permissions: string[];
  /** Detection rule IDs that can detect this technique */
  detectionIds: string[];
  mitigations: string[];
  category: TechniqueCategory;
  /** Example CloudTrail log event for this technique */
  cloudtrailSample?: string;
  /** Example AWS CLI commands or API calls used to execute this technique */
  commands?: string[];
  /** Attribution to sources (Hacking the Cloud, CloudGoat, etc.) */
  references?: Array<{ source: string; url?: string }>;
  /** Short detection strategy explanation for techniques with detection rules */
  detectionStrategy?: string;
  /** Cloud family this technique belongs to. Defaults to AWS. */
  cloudProvider?: "aws" | "azure" | "gcp" | "kubernetes";
}
