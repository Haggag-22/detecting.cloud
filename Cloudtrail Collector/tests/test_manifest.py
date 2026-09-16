"""Manifest construction and hash calculation.

The manifest is the chain-of-custody document. The failure modes worth testing
are the ones that would make it *lie*: a composite multipart digest presented
as a whole-object SHA256, failures omitted from the record, or a run reporting
itself complete when it was not.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json

import pytest

from collector.manifest import (
    CollectedObject,
    FailedObject,
    FailedWindow,
    ManifestBuilder,
    s3_checksum_to_hex,
    sha256_stream,
)


def builder(**overrides) -> ManifestBuilder:
    kwargs = {
        "run_id": "20260814T090000Z-abcd1234",
        "mode": "trail",
        "engagement_id": "IR-2026-0142",
        "dest_bucket": "evidence",
        "dest_prefix": "aws",
    }
    kwargs.update(overrides)
    return ManifestBuilder(**kwargs)


def collected(**overrides) -> CollectedObject:
    kwargs = {
        "source_key": "AWSLogs/123456789012/CloudTrail/us-east-1/2026/08/14/a.json.gz",
        "dest_key": "aws/IR-2026-0142/123456789012/us-east-1/2026-08-14/a.json.gz",
        "size_bytes": 4096,
        "digest": "a" * 64,
        "digest_method": "s3-sha256",
    }
    kwargs.update(overrides)
    return CollectedObject(**kwargs)


# --- hash calculation -------------------------------------------------------


def test_sha256_stream_matches_hashlib():
    payload = b"cloudtrail evidence bytes" * 1000
    assert sha256_stream(io.BytesIO(payload)) == hashlib.sha256(payload).hexdigest()


def test_sha256_stream_chunk_size_does_not_change_digest():
    """Chunking is an implementation detail; the digest must not depend on it."""
    payload = b"x" * 100_000
    expected = hashlib.sha256(payload).hexdigest()
    for chunk in (1, 7, 4096, 1_000_000):
        assert sha256_stream(io.BytesIO(payload), chunk_size=chunk) == expected


def test_sha256_of_empty_stream():
    assert sha256_stream(io.BytesIO(b"")) == hashlib.sha256(b"").hexdigest()


def test_s3_base64_checksum_converts_to_hex():
    digest = hashlib.sha256(b"payload").digest()
    encoded = base64.b64encode(digest).decode()
    value, method = s3_checksum_to_hex(encoded)
    assert value == digest.hex()
    assert method == "s3-sha256"


def test_multipart_composite_checksum_is_labelled_as_composite():
    """A composite digest is NOT the SHA256 of the object's bytes.

    Recording one as if it were a whole-object hash would be a false claim in
    an evidence document, so the method must come back distinguishable.
    """
    encoded = base64.b64encode(hashlib.sha256(b"parts").digest()).decode()
    value, method = s3_checksum_to_hex(f"{encoded}-12")
    assert method == "s3-sha256-composite"
    assert value.endswith("-12")


def test_composite_part_count_is_preserved():
    """Without the part count, the digest cannot be re-verified."""
    encoded = base64.b64encode(hashlib.sha256(b"parts").digest()).decode()
    value, _ = s3_checksum_to_hex(f"{encoded}-347")
    assert value.rsplit("-", 1)[1] == "347"


def test_invalid_base64_checksum_raises():
    with pytest.raises(ValueError, match="not valid base64"):
        s3_checksum_to_hex("!!!not base64!!!")


def test_empty_checksum_raises():
    with pytest.raises(ValueError, match="empty checksum"):
        s3_checksum_to_hex("")


# --- manifest document ------------------------------------------------------


def test_totals_sum_objects_and_bytes():
    manifest = builder()
    manifest.add_object(collected(size_bytes=1000))
    manifest.add_object(collected(dest_key="k2", size_bytes=2500))
    totals = manifest.build()["totals"]
    assert totals["objects_collected"] == 2
    assert totals["bytes_collected"] == 3500


def test_event_counts_accumulate():
    manifest = builder(mode="lookup")
    manifest.add_object(collected(digest_method="local-sha256", event_count=1200))
    manifest.add_object(collected(dest_key="k2", digest_method="local-sha256", event_count=800))
    assert manifest.build()["totals"]["events_collected"] == 2000


def test_clean_run_is_marked_complete():
    manifest = builder()
    manifest.add_object(collected())
    assert manifest.build()["run"]["collection_complete"] is True


def test_failed_object_marks_run_incomplete():
    """A partial collection that looks complete is the worst possible outcome."""
    manifest = builder()
    manifest.add_object(collected())
    manifest.add_failed_object(
        FailedObject(source_key="k", dest_key=None, error="AccessDenied", attempts=4)
    )
    doc = manifest.build()
    assert doc["run"]["collection_complete"] is False
    assert doc["totals"]["objects_failed"] == 1


def test_failed_window_marks_run_incomplete():
    manifest = builder(mode="lookup")
    manifest.add_failed_window(
        FailedWindow(
            region="us-east-1",
            window_start="2026-08-14T00:00:00+00:00",
            window_end="2026-08-14T06:00:00+00:00",
            error="ThrottlingException",
            events_written_before_failure=430,
        )
    )
    doc = manifest.build()
    assert doc["run"]["collection_complete"] is False
    assert doc["totals"]["windows_failed"] == 1


def test_failures_are_listed_explicitly_not_just_counted():
    """A count alone does not tell an analyst what is missing."""
    manifest = builder()
    manifest.add_failed_object(
        FailedObject(source_key="missing/object.gz", dest_key=None, error="AccessDenied", attempts=4)
    )
    doc = manifest.build()
    assert doc["failed_objects"][0]["source_key"] == "missing/object.gz"
    assert doc["failed_objects"][0]["error"] == "AccessDenied"


def test_lookup_mode_records_its_fidelity_limits():
    """An analyst seeing no data events must be able to tell why."""
    fidelity = builder(mode="lookup").build()["fidelity"]
    assert fidelity["data_events"] is False
    assert fidelity["insights_events"] is False
    assert fidelity["max_history_days"] == 90
    assert "collection artifact" in fidelity["statement"]


def test_trail_mode_defers_fidelity_to_the_source_trail():
    fidelity = builder(mode="trail").build()["fidelity"]
    assert fidelity["data_events"] == "as configured on the source trail"
    assert fidelity["max_history_days"] is None


def test_digest_method_and_note_survive_into_the_document():
    manifest = builder()
    manifest.add_object(
        collected(
            digest="ab" * 32 + "-12",
            digest_method="s3-sha256-composite",
            digest_note="composite",
        )
    )
    entry = manifest.build()["objects"][0]
    assert entry["digest_method"] == "s3-sha256-composite"
    assert entry["digest_note"] == "composite"


def test_manifest_is_valid_json_and_round_trips():
    manifest = builder()
    manifest.add_object(collected())
    manifest.add_note("source identity: arn:aws:iam::123456789012:role/Collector")
    doc = json.loads(manifest.to_json())
    assert doc["manifest_version"] == 1
    assert doc["collector"]["name"] == "ventra"
    assert doc["run"]["engagement_id"] == "IR-2026-0142"
    assert doc["notes"]


def test_concurrent_adds_lose_nothing():
    """Mode A copies from a thread pool; a lost entry is an object with no custody record."""
    import threading

    manifest = builder()

    def worker(start: int) -> None:
        for i in range(start, start + 200):
            manifest.add_object(collected(dest_key=f"key-{i}", size_bytes=10))

    threads = [threading.Thread(target=worker, args=(n * 200,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    totals = manifest.build()["totals"]
    assert totals["objects_collected"] == 1600
    assert totals["bytes_collected"] == 16000
