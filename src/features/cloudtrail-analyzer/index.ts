/**
 * CloudTrail Analyzer - Ingestion and Log Parsing Layer
 * Exports for use by the platform.
 */

export * from "./types";
export { parseCloudTrailInput } from "./parser/cloudtrail_parser";
export { handlePasteInput } from "./ingestion/input_handler";
export { handleFileUpload } from "./ingestion/file_upload_handler";
export { handleDatasetUpload } from "./ingestion/dataset_handler";
