/**
 * Detection coverage matrix — maps techniques to the same tactics as the Techniques Library sidebar.
 */

import type { Technique, TechniqueCategory } from "@/data/techniques";
import { techniques, techniqueCategories } from "@/data/techniques";
import { detections, type Detection } from "@/data/detections";
import { attackPaths } from "@/data/attackPaths";
import { communityRules } from "@/data/communityRules";

/** Matrix columns = Techniques Library categories only (same order as sidebar under Techniques Library). */
export type MatrixTactic = TechniqueCategory;

/** Exact sidebar order: Initial Access → … → Defense Evasion */
export const MATRIX_TACTIC_ORDER: MatrixTactic[] = [
  "initial-access",
  "credential-access",
  "privilege-escalation",
  "persistence",
  "lateral-movement",
  "exfiltration",
  "defense-evasion",
];

export const matrixTacticLabels: Record<MatrixTactic, string> = {
  "initial-access": techniqueCategories["initial-access"].label,
  "credential-access": techniqueCategories["credential-access"].label,
  "privilege-escalation": techniqueCategories["privilege-escalation"].label,
  persistence: techniqueCategories.persistence.label,
  "lateral-movement": techniqueCategories["lateral-movement"].label,
  exfiltration: techniqueCategories.exfiltration.label,
  "defense-evasion": techniqueCategories["defense-evasion"].label,
};

export function getMatrixTacticForTechnique(t: Technique): MatrixTactic {
  return t.category;
}

export type CoverageBand = "covered" | "partial" | "none";

export function getCoverageBand(detectionIds: string[]): CoverageBand {
  if (detectionIds.length === 0) return "none";
  const matched = detectionIds.filter((id) => detections.some((d) => d.id === id)).length;
  if (matched === 0) return "none";
  if (matched < detectionIds.length) return "partial";
  return "covered";
}

export function getLinkedDetections(tech: Technique): Detection[] {
  return detections.filter((d) => tech.detectionIds.includes(d.id));
}

export type SignalQualityLabel = "High" | "Medium" | "Low";

export function aggregateSignalQuality(dets: Detection[]): SignalQualityLabel {
  if (dets.length === 0) return "Low";
  const scores = dets
    .map((d) => d.lifecycle?.quality?.signalQuality)
    .filter((n): n is number => typeof n === "number");
  if (scores.length === 0) return "Medium";
  const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
  if (avg >= 7) return "High";
  if (avg >= 5) return "Medium";
  return "Low";
}

export type TestingStatusLabel = "Tested" | "Not Tested";

export function getTestingStatus(dets: Detection[]): TestingStatusLabel {
  if (dets.length === 0) return "Not Tested";
  const any =
    dets.some(
      (d) =>
        (d.testingSteps && d.testingSteps.length > 0) ||
        Boolean(d.lifecycle?.simulationCommand?.trim())
    );
  return any ? "Tested" : "Not Tested";
}

export function countAttackPathsForTechnique(techniqueId: string): number {
  return attackPaths.filter((ap) => ap.steps.some((s) => s.techniqueId === techniqueId)).length;
}

export function getUniqueCommunityAuthors(): number {
  return new Set(communityRules.map((r) => r.author)).size;
}

export interface TechniqueMatrixEntry {
  technique: Technique;
  tactic: MatrixTactic;
  coverage: CoverageBand;
  detectionCount: number;
  signalQuality: SignalQualityLabel;
  testingStatus: TestingStatusLabel;
  attackPathCount: number;
}

export function buildTechniqueMatrixEntries(): TechniqueMatrixEntry[] {
  return techniques.map((technique) => {
    const dets = getLinkedDetections(technique);
    return {
      technique,
      tactic: getMatrixTacticForTechnique(technique),
      coverage: getCoverageBand(technique.detectionIds),
      detectionCount: dets.length,
      signalQuality: aggregateSignalQuality(dets),
      testingStatus: getTestingStatus(dets),
      attackPathCount: countAttackPathsForTechnique(technique.id),
    };
  });
}

export function overallCoveragePercent(entries: TechniqueMatrixEntry[]): number {
  if (entries.length === 0) return 0;
  const score = entries.reduce((acc, e) => {
    if (e.coverage === "covered") return acc + 1;
    if (e.coverage === "partial") return acc + 0.5;
    return acc;
  }, 0);
  return Math.round((score / entries.length) * 100);
}

const SEVERITY_RANK: Record<string, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
};

export function getTopDetectionGaps(entries: TechniqueMatrixEntry[], limit = 8): TechniqueMatrixEntry[] {
  const gap = entries.filter((e) => e.coverage === "none");
  return gap
    .map((e) => {
      const paths = attackPaths.filter((ap) => ap.steps.some((s) => s.techniqueId === e.technique.id));
      const pathSev = Math.max(0, ...paths.map((p) => SEVERITY_RANK[p.severity] ?? 0));
      const iamBoost = e.technique.services.some((s) => /IAM|STS|Organizations/i.test(s)) ? 1 : 0;
      const score = pathSev * 2 + e.attackPathCount * 0.75 + iamBoost;
      return { entry: e, score };
    })
    .sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      return b.entry.attackPathCount - a.entry.attackPathCount;
    })
    .slice(0, limit)
    .map((x) => x.entry);
}

export function getAllMatrixServices(): string[] {
  const set = new Set<string>();
  techniques.forEach((t) => t.services.forEach((s) => set.add(s)));
  return Array.from(set).sort((a, b) => a.localeCompare(b));
}
