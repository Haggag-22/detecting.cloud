/**
 * Correlation-based detection engine.
 */

export * from "./types";
export { EventStore } from "./event_store/event_store";
export { toStoredEvent } from "./event_store/resource_extractor";
export { singleEventRules, correlationRules } from "./rule_engine/rules";
export { runDetection, evaluateSingleRule, evaluateCorrelationRule } from "./correlation_engine/correlation_engine";
export { runCorrelationEngine } from "./detection_output/run_engine";
