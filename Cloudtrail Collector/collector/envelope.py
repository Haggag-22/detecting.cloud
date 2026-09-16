"""LookupEvents envelope unwrapping.

``LookupEvents`` does not return trail-format records. It returns a CamelCase
metadata envelope::

    {
      "EventId": "...", "EventName": "...", "EventTime": <datetime>,
      "Username": "...", "Resources": [...],
      "CloudTrailEvent": "{\\"eventVersion\\":\\"1.08\\", ...}"
    }

The real record is the ``CloudTrailEvent`` field, as an escaped JSON *string*.
SOF-ELK's ``6901-aws.conf`` keys entirely off native field names
(``eventName``, ``eventSource``, ``userIdentity``...). If the envelope is
written out instead of the inner record, the parser matches nothing and the
data lands in Elasticsearch as unparsed noise — which looks like a successful
ingest until someone tries to query it.
"""

from __future__ import annotations

import json
from typing import Any

from .errors import EnvelopeError

INNER_FIELD = "CloudTrailEvent"


def unwrap_event(item: dict[str, Any]) -> dict[str, Any]:
    """Extract the native trail record from one LookupEvents item.

    The envelope is discarded entirely; everything in it is also present in the
    inner record, so keeping it would only add fields SOF-ELK does not map.

    Raises ``EnvelopeError`` with the offending event id when the field is
    missing, is not a string, is not valid JSON, or does not decode to an
    object. Every one of those cases means the record is unusable, and silently
    skipping it would understate the event count.
    """
    if not isinstance(item, dict):
        raise EnvelopeError(f"expected a LookupEvents item dict, got {type(item).__name__}")

    event_id = item.get("EventId", "<no EventId>")

    if INNER_FIELD not in item:
        raise EnvelopeError(
            f"LookupEvents item {event_id} has no {INNER_FIELD!r} field; "
            f"present keys: {sorted(item)}"
        )

    raw = item[INNER_FIELD]
    if not isinstance(raw, str):
        raise EnvelopeError(
            f"LookupEvents item {event_id}: {INNER_FIELD} should be an escaped "
            f"JSON string, got {type(raw).__name__}"
        )

    try:
        record = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise EnvelopeError(
            f"LookupEvents item {event_id}: {INNER_FIELD} is not valid JSON "
            f"({exc.msg} at position {exc.pos})"
        ) from exc

    if not isinstance(record, dict):
        raise EnvelopeError(
            f"LookupEvents item {event_id}: {INNER_FIELD} decoded to "
            f"{type(record).__name__}, expected a JSON object"
        )

    return record


def to_ndjson_line(record: dict[str, Any]) -> bytes:
    """Serialise one record as a single NDJSON line.

    ``separators`` removes insignificant whitespace and ``ensure_ascii=False``
    keeps non-ASCII values (usernames, resource tags, user agents) intact rather
    than escaping them; the file is written as UTF-8 and Logstash reads it as
    UTF-8. ``sort_keys`` makes output byte-reproducible, which matters when a
    manifest hash is meant to be verifiable.
    """
    return (
        json.dumps(record, separators=(",", ":"), ensure_ascii=False, sort_keys=True, default=str)
        + "\n"
    ).encode("utf-8")
