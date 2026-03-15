/**
 * Map detection matches to techniques and attack paths.
 */

import { getTechniquesForDetection } from "@/lib/detectionCoverage";
import { getAttackPathsForDetection } from "@/lib/detectionCoverage";

export interface TechniqueMatch {
  techniqueId: string;
  name: string;
  category: string;
}

export interface AttackPathMatch {
  slug: string;
  title: string;
  objective: string;
}

/** Get techniques for a list of matching detection IDs */
export function getTechniquesForDetections(detectionIds: string[]): TechniqueMatch[] {
  const seen = new Set<string>();
  const results: TechniqueMatch[] = [];
  for (const detId of detectionIds) {
    const techs = getTechniquesForDetection(detId);
    for (const t of techs) {
      if (!seen.has(t.id)) {
        seen.add(t.id);
        results.push({
          techniqueId: t.id,
          name: t.name,
          category: t.category,
        });
      }
    }
  }
  return results;
}

/** Get attack paths for a list of matching detection IDs */
export function getAttackPathsForDetections(detectionIds: string[]): AttackPathMatch[] {
  const seen = new Set<string>();
  const results: AttackPathMatch[] = [];
  for (const detId of detectionIds) {
    const paths = getAttackPathsForDetection(detId);
    for (const p of paths) {
      if (!seen.has(p.slug)) {
        seen.add(p.slug);
        results.push({
          slug: p.slug,
          title: p.title,
          objective: p.objective,
        });
      }
    }
  }
  return results;
}
