"""Envelope unwrapping.

This is the highest-value test in the suite. If unwrapping regresses, the
collector still runs, still uploads, still reports success — and SOF-ELK's
6901-aws.conf matches none of it, because the parser keys off native field
names that only exist inside CloudTrailEvent. The failure is invisible until
someone queries the data.
"""

from __future__ import annotations

import json

import pytest

from collector.envelope import to_ndjson_line, unwrap_event
from collector.errors import EnvelopeError

INNER_RECORD = {
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDAEXAMPLE",
        "arn": "arn:aws:iam::123456789012:user/analyst",
        "accountId": "123456789012",
        "accessKeyId": "AKIAEXAMPLE",
        "userName": "analyst",
    },
    "eventTime": "2026-08-14T09:15:22Z",
    "eventSource": "s3.amazonaws.com",
    "eventName": "GetObject",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "198.51.100.24",
    "userAgent": "aws-cli/2.15.0",
    "requestParameters": {"bucketName": "client-data", "key": "quarterly.xlsx"},
    "responseElements": None,
    "eventID": "ba5eba11-0000-4000-8000-000000000001",
    "eventType": "AwsApiCall",
}


def envelope(**overrides) -> dict:
    """A realistic LookupEvents item wrapping INNER_RECORD."""
    item = {
        "EventId": "ba5eba11-0000-4000-8000-000000000001",
        "EventName": "GetObject",
        "ReadOnly": "true",
        "EventTime": "2026-08-14T09:15:22Z",
        "EventSource": "s3.amazonaws.com",
        "Username": "analyst",
        "Resources": [{"ResourceType": "AWS::S3::Object", "ResourceName": "quarterly.xlsx"}],
        "CloudTrailEvent": json.dumps(INNER_RECORD),
    }
    item.update(overrides)
    return item


def test_returns_inner_record_not_envelope():
    result = unwrap_event(envelope())
    assert result == INNER_RECORD


def test_camelcase_envelope_metadata_is_discarded():
    """The envelope's CamelCase keys must not survive into the output.

    SOF-ELK maps `eventName`, not `EventName`. Leaking envelope keys would put
    unmapped fields into Elasticsearch and inflate the index for no benefit.
    """
    result = unwrap_event(envelope())
    for envelope_key in ("EventId", "EventName", "Username", "Resources", "CloudTrailEvent"):
        assert envelope_key not in result
    assert result["eventName"] == "GetObject"


def test_nested_structures_survive_unwrapping():
    result = unwrap_event(envelope())
    assert result["userIdentity"]["arn"] == "arn:aws:iam::123456789012:user/analyst"
    assert result["requestParameters"]["bucketName"] == "client-data"


def test_explicit_null_response_elements_preserved():
    """A JSON null is meaningful and must not be silently dropped."""
    result = unwrap_event(envelope())
    assert "responseElements" in result
    assert result["responseElements"] is None


def test_missing_field_raises_with_event_id():
    item = envelope()
    del item["CloudTrailEvent"]
    with pytest.raises(EnvelopeError) as excinfo:
        unwrap_event(item)
    assert "ba5eba11-0000-4000-8000-000000000001" in str(excinfo.value)


def test_non_string_inner_field_raises():
    """Guards against a future boto3 that pre-parses the field.

    If that ever happens, this must fail loudly rather than write a dict where
    a JSON string was expected.
    """
    with pytest.raises(EnvelopeError, match="escaped JSON string"):
        unwrap_event(envelope(CloudTrailEvent=INNER_RECORD))


def test_malformed_inner_json_raises():
    with pytest.raises(EnvelopeError, match="not valid JSON"):
        unwrap_event(envelope(CloudTrailEvent='{"eventName": "Get'))


def test_inner_json_array_raises():
    with pytest.raises(EnvelopeError, match="expected a JSON object"):
        unwrap_event(envelope(CloudTrailEvent='["not", "an", "object"]'))


def test_non_dict_item_raises():
    with pytest.raises(EnvelopeError):
        unwrap_event("not an item")  # type: ignore[arg-type]


def test_ndjson_line_is_single_line_and_round_trips():
    line = to_ndjson_line(INNER_RECORD)
    assert line.endswith(b"\n")
    assert line.count(b"\n") == 1
    assert json.loads(line) == INNER_RECORD


def test_ndjson_preserves_non_ascii():
    """Usernames and user agents carry non-ASCII; escaping them loses fidelity."""
    record = dict(INNER_RECORD, userAgent="curl/8.0 (Ünïcodé)")
    line = to_ndjson_line(record)
    assert "Ünïcodé" in line.decode("utf-8")
    assert json.loads(line)["userAgent"] == "curl/8.0 (Ünïcodé)"


def test_ndjson_embedded_newline_does_not_break_line_framing():
    """A newline inside a value must stay escaped, or one record becomes two."""
    record = dict(INNER_RECORD, errorMessage="line one\nline two")
    line = to_ndjson_line(record)
    assert line.count(b"\n") == 1
    assert json.loads(line)["errorMessage"] == "line one\nline two"


def test_ndjson_is_byte_reproducible():
    """Same record, same bytes — otherwise the manifest digest is unverifiable."""
    shuffled = dict(reversed(list(INNER_RECORD.items())))
    assert to_ndjson_line(INNER_RECORD) == to_ndjson_line(shuffled)
