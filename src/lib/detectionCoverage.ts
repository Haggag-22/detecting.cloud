import { techniques, type Technique } from "@/data/techniques";
import { attackPaths, type AttackPath } from "@/data/attackPaths";

/**
 * Get techniques that are detected by the given detection rule.
 */
export function getTechniquesForDetection(detectionId: string): Technique[] {
  return techniques.filter((t) => t.detectionIds.includes(detectionId));
}

/**
 * Get attack paths that include techniques detected by the given detection rule.
 */
export function getAttackPathsForDetection(detectionId: string): AttackPath[] {
  const techniqueIds = getTechniquesForDetection(detectionId).map((t) => t.id);
  return attackPaths.filter((ap) =>
    ap.steps.some((s) => techniqueIds.includes(s.techniqueId))
  );
}
