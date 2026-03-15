/**
 * Correlation engine - evaluates multi-step rules.
 * Only triggers when ALL required events occur and conditions are satisfied.
 */

import type { StoredEvent } from "../types";
import type { CorrelationRule, CorrelationCondition, DetectionResult } from "../types";
import { correlationRules } from "../rule_engine/rules";
import { singleEventRules } from "../rule_engine/rules";
import type { EventStore } from "../event_store/event_store";

function getResourceValue(ev: StoredEvent, field?: string): string {
  if (!field) return ev.resource;
  if (field === "bucketName" && ev.resource_type === "bucket") return ev.resource;
  if (field === "userName" && ev.resource_type === "user") return ev.resource;
  if (field === "roleName" && ev.resource_type === "role") return ev.resource;
  const val = (ev.request_parameters as Record<string, unknown>)?.[field];
  return typeof val === "string" ? val : ev.resource;
}

function parseTime(iso: string): number {
  return new Date(iso).getTime();
}

function satisfiesTimeWindow(
  events: StoredEvent[],
  steps: CorrelationRule["steps"],
  windowSeconds: number
): boolean {
  if (events.length < 2) return true;
  const times = events.map((e) => parseTime(e.event_time));
  const min = Math.min(...times);
  const max = Math.max(...times);
  return max - min <= windowSeconds * 1000;
}

function satisfiesTimeOrder(
  events: StoredEvent[],
  steps: CorrelationRule["steps"],
  condition: CorrelationCondition
): boolean {
  if (!condition.afterStepId || events.length < 2) return true;
  const afterIdx = steps.findIndex((s) => s.stepId === condition.afterStepId);
  if (afterIdx < 0) return true;
  const afterStep = steps[afterIdx];
  const afterEvent = events[afterIdx];
  const currentEvent = events[afterIdx + 1];
  if (!afterEvent || !currentEvent) return true;
  return parseTime(currentEvent.event_time) >= parseTime(afterEvent.event_time);
}

function satisfiesResourceMatch(
  events: StoredEvent[],
  steps: CorrelationRule["steps"],
  resourceField?: string
): boolean {
  if (events.length < 2 || !resourceField) return true;
  const values = events.map((e, i) => getResourceValue(e, steps[i]?.resourceField ?? resourceField));
  const first = values[0];
  if (!first) return true;
  return values.every((v) => v && v === first);
}

/** Evaluate single-event rule */
export function evaluateSingleRule(
  ev: StoredEvent,
  rule: (typeof singleEventRules)[0]
): boolean {
  if (ev.event_source !== rule.eventSource || ev.event_name !== rule.eventName) return false;
  if (rule.containsConditions) {
    for (const c of rule.containsConditions) {
      const val = (ev.request_parameters as Record<string, unknown>)?.[c.field];
      const str = String(val ?? "");
      if (!str.toLowerCase().includes(c.value.toLowerCase())) return false;
    }
  }
  return true;
}

/** Evaluate correlation rule - returns matched events if all conditions satisfied */
export function evaluateCorrelationRule(
  store: EventStore,
  currentEvent: StoredEvent,
  rule: CorrelationRule
): StoredEvent[] | null {
  const lastStep = rule.steps[rule.steps.length - 1];
  if (currentEvent.event_source !== lastStep.eventSource || currentEvent.event_name !== lastStep.eventName) {
    return null;
  }

  if (rule.steps.length === 1) {
    return [currentEvent];
  }

  const resourceField = lastStep.resourceField;
  const resource = getResourceValue(currentEvent, resourceField);

  const matchedEvents: StoredEvent[] = [currentEvent];

  for (let i = rule.steps.length - 2; i >= 0; i--) {
    const step = rule.steps[i];
    const windowCond = rule.conditions.find((c) => c.type === "time_window");
    const windowSec = windowCond?.windowSeconds ?? 3600;
    const minTime = new Date(parseTime(currentEvent.event_time) - windowSec * 1000).toISOString();
    const maxTime = currentEvent.event_time;

    const candidates = resource
      ? store.findByEventInWindow(step.eventSource, step.eventName, minTime, maxTime, resource)
      : store.findByEventInWindow(step.eventSource, step.eventName, minTime, maxTime);

    if (candidates.length === 0) return null;

    const prevEvent = candidates[candidates.length - 1];
    matchedEvents.unshift(prevEvent);
  }

  for (const cond of rule.conditions) {
    if (cond.type === "resource_match" && !satisfiesResourceMatch(matchedEvents, rule.steps, cond.resourceField)) {
      return null;
    }
    if (cond.type === "time_window" && cond.windowSeconds && !satisfiesTimeWindow(matchedEvents, rule.steps, cond.windowSeconds)) {
      return null;
    }
    if (cond.type === "time_order" && !satisfiesTimeOrder(matchedEvents, rule.steps, cond)) {
      return null;
    }
  }

  return matchedEvents;
}

/** Run full detection - single + correlation */
export function runDetection(
  store: EventStore,
  currentEvent: StoredEvent
): DetectionResult[] {
  const results: DetectionResult[] = [];

  for (const rule of singleEventRules) {
    if (evaluateSingleRule(currentEvent, rule)) {
      results.push({
        ruleId: rule.id,
        ruleName: rule.name,
        ruleType: "single",
        severity: rule.severity,
        matchedEvents: [
          {
            event_id: currentEvent.event_id,
            event_time: currentEvent.event_time,
            event_name: currentEvent.event_name,
            event_source: currentEvent.event_source,
            resource: currentEvent.resource || undefined,
          },
        ],
        actor: currentEvent.actor || undefined,
        resource: currentEvent.resource || undefined,
        reason: rule.description,
      });
    }
  }

  for (const rule of correlationRules) {
    const matched = evaluateCorrelationRule(store, currentEvent, rule);
    if (matched && matched.length > 0) {
      const times = matched.map((e) => e.event_time);
      results.push({
        ruleId: rule.id,
        ruleName: rule.name,
        ruleType: "correlation",
        severity: rule.severity,
        matchedEvents: matched.map((e) => ({
          event_id: e.event_id,
          event_time: e.event_time,
          event_name: e.event_name,
          event_source: e.event_source,
          resource: e.resource || undefined,
        })),
        actor: currentEvent.actor || undefined,
        resource: currentEvent.resource || undefined,
        timeWindow: times.length > 1 ? { start: times[0], end: times[times.length - 1] } : undefined,
        reason: rule.reason ?? rule.description,
      });
    }
  }

  return results;
}
