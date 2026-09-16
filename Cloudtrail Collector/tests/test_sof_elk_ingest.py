"""SOF-ELK ingest shape for CloudTrail evidence."""

from __future__ import annotations

import json

import pytest

from collector.errors import EnvelopeError
from collector.sof_elk_ingest import (
    RECORDS_FIELD,
    cloudtrail_s3_document,
    serialize_cloudtrail_s3_object,
    validate_cloudtrail_record,
)

SAMPLE = {
    "eventVersion": "1.08",
    "eventTime": "2026-08-14T09:15:22Z",
    "eventSource": "s3.amazonaws.com",
    "eventName": "GetObject",
    "awsRegion": "us-east-1",
}


def test_validate_requires_sof_elk_fields():
    validate_cloudtrail_record(SAMPLE)
    with pytest.raises(EnvelopeError, match="eventName"):
        validate_cloudtrail_record({"eventTime": "2026-08-14T09:15:22Z"})


def test_cloudtrail_s3_document_matches_logstash_preprocess():
    doc = cloudtrail_s3_document([SAMPLE])
    assert RECORDS_FIELD in doc
    assert doc[RECORDS_FIELD][0]["eventName"] == "GetObject"
    parsed = json.loads(serialize_cloudtrail_s3_object([SAMPLE]))
    assert parsed["Records"][0]["eventSource"] == "s3.amazonaws.com"
