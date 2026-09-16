"""Shape CloudTrail evidence for the sof-elk-docker Logstash pipeline.

Ingest path (``logstash/pipeline/20-preprocess-cloudtrail-s3.conf`` +
``40-filter-aws-cloudtrail.conf``):

* S3 input sets ``[labels][type] = aws``.
* JSON is parsed from ``message``; the pipeline expects either a CloudTrail S3
  log file (``{"Records": [ {...}, ... ]}``) or fields already under ``[raw]``.
* ``6901``-style mapping reads native trail keys under ``[raw]`` (``eventName``,
  ``eventSource``, ``userIdentity``, …) and builds ECS-style ``aws.cloudtrail.*``.

Trail mode copies native S3 objects unchanged. Lookup mode must emit the same
``Records`` wrapper, not NDJSON lines, or Logstash will not populate ``[raw]``.
"""

from __future__ import annotations

import json
from typing import Any

from .errors import EnvelopeError

RECORDS_FIELD = "Records"

# Fields SOF-ELK copies from ``[raw]`` (see 40-filter-aws-cloudtrail.conf).
REQUIRED_FOR_SOF_ELK = ("eventName", "eventTime", "eventSource")

OPTIONAL_RAW_FIELDS = (
    "eventVersion",
    "userIdentity",
    "awsRegion",
    "sourceIPAddress",
    "userAgent",
    "requestParameters",
    "responseElements",
    "additionalEventData",
    "requestID",
    "eventID",
    "readOnly",
    "resources",
    "eventType",
    "apiVersion",
    "recipientAccountId",
    "sharedEventID",
    "vpcEndpointId",
    "errorCode",
    "errorMessage",
    "sessionCredentialFromConsole",
    "edgeDeviceDetails",
    "tlsDetails",
)


def validate_cloudtrail_record(record: dict[str, Any]) -> None:
    """Ensure one record will survive SOF-ELK CloudTrail parsing."""
    if not isinstance(record, dict):
        raise EnvelopeError(f"expected a trail record dict, got {type(record).__name__}")
    missing = [f for f in REQUIRED_FOR_SOF_ELK if not record.get(f)]
    if missing:
        raise EnvelopeError(
            f"trail record missing SOF-ELK required fields {missing}; "
            f"present keys: {sorted(record)}"
        )


def cloudtrail_s3_document(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the same top-level object AWS writes to trail S3."""
    if not records:
        raise EnvelopeError("cannot build CloudTrail S3 document with zero records")
    for record in records:
        validate_cloudtrail_record(record)
    return {RECORDS_FIELD: records}


def serialize_cloudtrail_s3_object(records: list[dict[str, Any]]) -> bytes:
    """UTF-8 JSON bytes for one gzipped trail log object."""
    return json.dumps(
        cloudtrail_s3_document(records),
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def uncompressed_chunk_size(records: list[dict[str, Any]]) -> int:
    """Exact uncompressed byte size of the S3 object body for chunk rolling."""
    return len(serialize_cloudtrail_s3_object(records))
