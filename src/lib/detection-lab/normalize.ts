/**
 * Event normalization layer for Detection Lab.
 * Normalizes different log formats (CloudTrail, generic JSON) to a consistent structure
 * for rule evaluation.
 */

export interface NormalizedEvent {
  eventSource?: string;
  eventName?: string;
  eventTime?: string;
  userIdentity?: {
    type?: string;
    arn?: string;
    principalId?: string;
    accountId?: string;
    sessionContext?: {
      sessionIssuer?: { arn?: string };
    };
  };
  sourceIPAddress?: string;
  userAgent?: string;
  requestParameters?: Record<string, unknown>;
  responseElements?: Record<string, unknown>;
  errorCode?: string;
  errorMessage?: string;
  recipientAccountId?: string;
  [key: string]: unknown;
}

/**
 * Normalize a raw log event to a consistent CloudTrail-like structure.
 */
export function normalizeEvent(raw: unknown): NormalizedEvent {
  if (raw == null) return {};

  const obj = typeof raw === "string" ? (() => {
    try {
      return JSON.parse(raw) as Record<string, unknown>;
    } catch {
      return {};
    }
  })() : (raw as Record<string, unknown>);

  if (typeof obj !== "object") return {};

  return {
    eventSource: getString(obj, "eventSource", "event_source"),
    eventName: getString(obj, "eventName", "event_name"),
    eventTime: getString(obj, "eventTime", "event_time", "@timestamp", "timestamp"),
    userIdentity: normalizeUserIdentity(obj.userIdentity ?? obj.user_identity),
    sourceIPAddress: getString(obj, "sourceIPAddress", "source_ip"),
    userAgent: getString(obj, "userAgent", "user_agent"),
    requestParameters: (obj.requestParameters ?? obj.request_parameters) as Record<string, unknown> | undefined,
    responseElements: (obj.responseElements ?? obj.response_elements) as Record<string, unknown> | undefined,
    errorCode: getString(obj, "errorCode", "error_code"),
    errorMessage: getString(obj, "errorMessage", "error_message"),
    recipientAccountId: getString(obj, "recipientAccountId", "recipient_account_id"),
    ...obj,
  };
}

function getString(obj: Record<string, unknown>, ...keys: string[]): string | undefined {
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === "string") return v;
  }
  return undefined;
}

function normalizeUserIdentity(identity: unknown): NormalizedEvent["userIdentity"] {
  if (identity == null || typeof identity !== "object") return undefined;
  const id = identity as Record<string, unknown>;
  return {
    type: getString(id, "type"),
    arn: getString(id, "arn"),
    principalId: getString(id, "principalId", "principal_id"),
    accountId: getString(id, "accountId", "account_id"),
    sessionContext: id.sessionContext as { sessionIssuer?: { arn?: string } } | undefined,
  };
}

/**
 * Normalize an array of events (handles nested Records array from CloudTrail).
 */
export function normalizeEvents(raw: unknown): NormalizedEvent[] {
  if (raw == null) return [];
  const obj = typeof raw === "string" ? (() => {
    try {
      return JSON.parse(raw) as Record<string, unknown>;
    } catch {
      return {};
    }
  })() : (raw as Record<string, unknown>);

  if (Array.isArray(obj)) {
    return obj.map((e) => normalizeEvent(e));
  }
  if (obj.Records && Array.isArray(obj.Records)) {
    return obj.Records.map((r: unknown) => normalizeEvent(r));
  }
  if (obj.events && Array.isArray(obj.events)) {
    return obj.events.map((e: unknown) => normalizeEvent(e));
  }
  return [normalizeEvent(obj)];
}
