/**
 * Correlation-based detection engine - type definitions.
 */

/** Stored event for correlation - indexed fields for search */
export interface StoredEvent {
  event_id: string;
  event_time: string;
  event_source: string;
  event_name: string;
  actor: string;
  resource: string;
  resource_type: string;
  source_ip: string;
  aws_region: string;
  request_parameters: Record<string, unknown>;
  /** Original normalized event for full context */
  _normalized: unknown;
}

/** Single event step in a correlation rule */
export interface CorrelationEventStep {
  stepId: string;
  eventSource: string;
  eventName: string;
  /** Resource field to match (e.g. bucketName, roleName) - must match across steps */
  resourceField?: string;
}

/** Correlation condition between steps */
export interface CorrelationCondition {
  type: "resource_match" | "time_window" | "time_order";
  /** For resource_match: field to match */
  resourceField?: string;
  /** For time_window: max seconds between steps */
  windowSeconds?: number;
  /** For time_order: step must occur after this step */
  afterStepId?: string;
}

/** Correlation rule - requires multiple events */
export interface CorrelationRule {
  id: string;
  name: string;
  description: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  /** Ordered steps - events must occur in this sequence */
  steps: CorrelationEventStep[];
  /** Conditions that must ALL be satisfied */
  conditions: CorrelationCondition[];
  /** Human-readable reason */
  reason?: string;
}

/** Single-event rule - triggers on one event */
export interface SingleEventRule {
  id: string;
  name: string;
  description: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  eventSource: string;
  eventName: string;
  /** Optional: contains check on requestParameters */
  containsConditions?: Array<{ field: string; value: string }>;
}

/** Detection result */
export interface DetectionResult {
  ruleId: string;
  ruleName: string;
  ruleType: "single" | "correlation";
  severity: string;
  matchedEvents: Array<{
    event_id: string;
    event_time: string;
    event_name: string;
    event_source: string;
    resource?: string;
  }>;
  actor?: string;
  resource?: string;
  timeWindow?: { start: string; end: string };
  reason: string;
}
