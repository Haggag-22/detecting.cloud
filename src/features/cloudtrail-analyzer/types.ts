/**
 * CloudTrail Analyzer - Type definitions for ingestion and parsing layer.
 */

/** Raw CloudTrail event as received from AWS */
export interface RawCloudTrailEvent {
  eventVersion?: string;
  userIdentity?: {
    type?: string;
    principalId?: string;
    arn?: string;
    accountId?: string;
    userName?: string;
    sessionContext?: {
      sessionIssuer?: { userName?: string };
      webIdFederationData?: Record<string, unknown>;
    };
    [key: string]: unknown;
  };
  eventTime?: string;
  eventSource?: string;
  eventName?: string;
  awsRegion?: string;
  sourceIPAddress?: string;
  userAgent?: string;
  requestParameters?: Record<string, unknown>;
  responseElements?: Record<string, unknown>;
  resources?: Array<{ type?: string; ARN?: string; accountId?: string }>;
  errorCode?: string;
  errorMessage?: string;
  requestID?: string;
  eventID?: string;
  readOnly?: boolean;
  eventType?: string;
  apiVersion?: string;
  recipientAccountId?: string;
  [key: string]: unknown;
}

/** Normalized event schema for platform-wide analysis */
export interface NormalizedCloudTrailEvent {
  event_id: string;
  event_time: string;
  event_source: string;
  event_name: string;
  aws_region: string;
  source_ip: string;
  user_agent: string;
  principal_type: string;
  principal_arn: string;
  principal_account_id: string;
  request_parameters: Record<string, unknown>;
  response_elements: Record<string, unknown>;
  resources: Array<{ type?: string; arn?: string; account_id?: string }>;
  /** Additional extracted security fields */
  session_context?: Record<string, unknown>;
  error_code?: string;
  error_message?: string;
  read_only?: boolean;
  event_type?: string;
  /** True if required fields (eventTime, eventSource, eventName) are present */
  is_fully_structured: boolean;
  /** Original raw event for reference */
  _raw?: RawCloudTrailEvent;
}

/** Result of parsing a single event */
export interface ParseResult {
  success: boolean;
  event?: NormalizedCloudTrailEvent;
  error?: string;
  raw?: RawCloudTrailEvent;
}

/** Result of ingestion pipeline */
export interface IngestionResult {
  parsed_events: NormalizedCloudTrailEvent[];
  valid_count: number;
  malformed_count: number;
  total_count: number;
  errors: IngestionError[];
}

/** Error recorded during ingestion */
export interface IngestionError {
  index?: number;
  message: string;
  raw?: string;
}
