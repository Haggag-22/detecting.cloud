/**
 * Detection deduplication.
 * Groups detections by technique/behavior for aggregated alerts.
 */

import type { Detection } from "@/data/detections";

export interface DeduplicatedDetection {
  techniqueKey: string;
  techniqueName: string;
  detectionIds: string[];
  detectionTitles: string[];
  combinedConfidenceScore: number;
  severity: string;
  relatedAttackSlugs: string[];
}

/**
 * Get technique key for deduplication (from relatedAttackSlugs or detection title).
 */
function getTechniqueKey(detection: Detection): string {
  if (detection.relatedAttackSlugs?.length > 0) {
    return detection.relatedAttackSlugs[0];
  }
  return detection.title.toLowerCase().replace(/\s+/g, "-").slice(0, 50);
}

/**
 * Group detections by technique. Multiple rules detecting the same technique become one aggregated alert.
 */
export function deduplicateDetections(
  detections: Detection[],
  detectionIds: string[],
  confidenceScores: Record<string, number>
): DeduplicatedDetection[] {
  const groups = new Map<string, { detection: Detection; score: number }[]>();

  for (const detId of detectionIds) {
    const detection = detections.find((d) => d.id === detId);
    if (!detection) continue;

    const key = getTechniqueKey(detection);
    const score = confidenceScores[detId] ?? 50;

    if (!groups.has(key)) {
      groups.set(key, []);
    }
    groups.get(key)!.push({ detection, score });
  }

  return Array.from(groups.entries()).map(([key, items]) => {
    const combinedScore = Math.round(
      items.reduce((sum, i) => sum + i.score, 0) / items.length
    );
    const severity = items[0].detection.severity;
    const slugs = items[0].detection.relatedAttackSlugs ?? [];

    return {
      techniqueKey: key,
      techniqueName: items.length > 1
        ? `${items[0].detection.title} (and ${items.length - 1} more)`
        : items[0].detection.title,
      detectionIds: items.map((i) => i.detection.id),
      detectionTitles: items.map((i) => i.detection.title),
      combinedConfidenceScore: Math.min(combinedScore, 100),
      severity,
      relatedAttackSlugs: slugs,
    };
  });
}
