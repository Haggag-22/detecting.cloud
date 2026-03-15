/**
 * Run the correlation detection engine on a batch of events.
 * Returns a map of event_id -> DetectionResult[] for UI display.
 */

import type { NormalizedCloudTrailEvent } from "@/features/cloudtrail-analyzer";
import type { DetectionResult } from "../types";
import { EventStore } from "../event_store/event_store";
import { toStoredEvent } from "../event_store/resource_extractor";
import { runDetection } from "../correlation_engine/correlation_engine";

/** Run detection on events (sorted by time) and return event_id -> DetectionResult[] */
export function runCorrelationEngine(
  events: NormalizedCloudTrailEvent[]
): Map<string, DetectionResult[]> {
  const store = new EventStore({ retentionMs: 7 * 24 * 60 * 60 * 1000 });
  const eventIdToResults = new Map<string, DetectionResult[]>();

  const sorted = [...events].sort((a, b) => a.event_time.localeCompare(b.event_time));

  for (const norm of sorted) {
    const stored = toStoredEvent(norm);
    store.add(stored);

    const results = runDetection(store, stored);

    for (const res of results) {
      for (const me of res.matchedEvents) {
        const list = eventIdToResults.get(me.event_id) ?? [];
        if (!list.some((r) => r.ruleId === res.ruleId)) list.push(res);
        eventIdToResults.set(me.event_id, list);
      }
    }
  }

  return eventIdToResults;
}
