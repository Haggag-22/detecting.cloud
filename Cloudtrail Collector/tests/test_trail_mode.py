"""Mode A orchestration: enumerate, copy, verify, record, resume.

Exercises the parts that only misbehave under concurrency and interruption —
backpressure on the future queue, failures reaching the manifest instead of
vanishing, and a resumed run skipping exactly what it already has.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone

import pytest
from botocore.exceptions import ClientError

from collector.config import RunConfig
from collector.logging_setup import setup_logging
from collector.manifest import ManifestBuilder
from collector.modes import trail as trail_mode


def checksum_for(key: str) -> str:
    return base64.b64encode(hashlib.sha256(key.encode()).digest()).decode()


class FakeSourceS3:
    """Source bucket holding objects under native CloudTrail day prefixes."""

    def __init__(self, keys: dict[str, int]) -> None:
        self.keys = keys
        self.list_calls: list[str] = []

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        outer = self

        class _Paginator:
            def paginate(self, Bucket, Prefix):
                outer.list_calls.append(Prefix)
                contents = [
                    {"Key": k, "Size": size}
                    for k, size in sorted(outer.keys.items())
                    if k.startswith(Prefix)
                ]
                # Page it, to exercise multi-page enumeration.
                for start in range(0, max(len(contents), 1), 2):
                    page = contents[start : start + 2]
                    if page or start == 0:
                        yield {"Contents": page} if page else {}

        return _Paginator()

    def head_object(self, Bucket, Key, **kwargs):
        if Key not in self.keys:
            raise ClientError({"Error": {"Code": "404"}}, "HeadObject")
        return {
            "ContentLength": self.keys[Key],
            "ETag": f'"etag-{Key}"',
            "ChecksumSHA256": checksum_for(Key),
        }


class FakeDestS3:
    """Destination bucket. Can be told to fail specific keys."""

    def __init__(self, fail_keys: set[str] | None = None, fail_times: int = 99) -> None:
        self.objects: dict[str, dict] = {}
        self.fail_keys = fail_keys or set()
        self.fail_times = fail_times
        self.attempts: dict[str, int] = {}

    def copy_object(self, Bucket, Key, CopySource, **kwargs):
        source_key = CopySource["Key"]
        self.attempts[Key] = self.attempts.get(Key, 0) + 1
        if source_key in self.fail_keys and self.attempts[Key] <= self.fail_times:
            raise ClientError({"Error": {"Code": "InternalError"}}, "CopyObject")
        self.objects[Key] = {
            "size": 1024,
            "etag": f'"etag-{source_key}"',
            "checksum": checksum_for(source_key),
        }
        return {"CopyObjectResult": {"ETag": f'"etag-{source_key}"', "ChecksumSHA256": checksum_for(source_key)}}

    def head_object(self, Bucket, Key, **kwargs):
        obj = self.objects[Key]
        return {
            "ContentLength": obj["size"],
            "ETag": obj["etag"],
            "ChecksumSHA256": obj["checksum"],
        }


class FakeSession:
    def __init__(self, client) -> None:
        self._client = client

    def client(self, name, **kwargs):
        return self._client


def source_keys(count: int) -> dict[str, int]:
    return {
        f"AWSLogs/123456789012/CloudTrail/us-east-1/2026/08/14/"
        f"123456789012_CloudTrail_us-east-1_20260814T{i:04d}Z_obj{i}.json.gz": 1024
        for i in range(count)
    }


def make_config(tmp_path, **overrides) -> RunConfig:
    kwargs = dict(
        mode="trail",
        engagement_id="IR-2026-0142",
        run_id="run-1",
        dest_bucket="evidence",
        dest_prefix="aws",
        dest_region="us-east-1",
        create_dest_bucket=False,
        source_bucket="client-trail",
        source_prefix="",
        source_account_id="123456789012",
        org_id=None,
        regions=["us-east-1"],
        start=datetime(2026, 8, 14, tzinfo=timezone.utc),
        end=datetime(2026, 8, 14, 23, 59, tzinfo=timezone.utc),
        window=None,
        concurrency=4,
        chunk_size_bytes=1024,
        in_place=False,
        dry_run=False,
        resume=False,
        state_file=tmp_path / "state.ndjson",
        log_file=tmp_path / "run.jsonl",
        manifest_out=None,
        source_profile=None,
        dest_profile=None,
        verbose=False,
    )
    kwargs.update(overrides)
    return RunConfig(**kwargs)


def make_manifest() -> ManifestBuilder:
    return ManifestBuilder(
        run_id="run-1",
        mode="trail",
        engagement_id="IR-2026-0142",
        dest_bucket="evidence",
        dest_prefix="aws",
        source_account_id="123456789012",
    )


@pytest.fixture(autouse=True)
def _logging(tmp_path):
    setup_logging(tmp_path / "test.jsonl", verbose=False)


@pytest.fixture(autouse=True)
def _no_retry_sleep(monkeypatch):
    """Skip the real exponential backoff.

    The retry *schedule* is production behaviour worth having; waiting through
    it in tests is not. Patched here rather than shortened in the collector so
    the real delays stay real.
    """
    monkeypatch.setattr(trail_mode.time, "sleep", lambda _seconds: None)


def test_copies_everything_and_records_it(tmp_path):
    source = FakeSourceS3(source_keys(10))
    dest = FakeDestS3()
    config = make_config(tmp_path)
    manifest = make_manifest()

    failures = trail_mode.run(config, FakeSession(source), FakeSession(dest), manifest)

    assert failures == 0
    assert len(dest.objects) == 10
    doc = manifest.build()
    assert doc["totals"]["objects_collected"] == 10
    assert doc["run"]["collection_complete"] is True


def test_destination_keys_use_the_engagement_layout(tmp_path):
    source = FakeSourceS3(source_keys(3))
    dest = FakeDestS3()
    trail_mode.run(make_config(tmp_path), FakeSession(source), FakeSession(dest), make_manifest())

    for key in dest.objects:
        assert key.startswith("aws/IR-2026-0142/123456789012/us-east-1/2026-08-14/")
        assert key.endswith(".json.gz")


def test_enumeration_uses_day_prefixes_not_a_bucket_wide_list(tmp_path):
    """A bucket-wide list would never finish against a real evidence set."""
    source = FakeSourceS3(source_keys(3))
    trail_mode.run(make_config(tmp_path), FakeSession(source), FakeSession(FakeDestS3()), make_manifest())

    assert source.list_calls
    for prefix in source.list_calls:
        assert prefix.startswith("AWSLogs/123456789012/")
        assert "/2026/08/14/" in prefix


def test_backpressure_does_not_grow_the_future_queue_without_bound(tmp_path):
    """More objects than the queue bound, with low concurrency."""
    source = FakeSourceS3(source_keys(200))
    dest = FakeDestS3()
    config = make_config(tmp_path, concurrency=2)

    failures = trail_mode.run(config, FakeSession(source), FakeSession(dest), make_manifest())

    assert failures == 0
    assert len(dest.objects) == 200


def test_transient_failure_is_retried_then_succeeds(tmp_path):
    keys = source_keys(5)
    flaky = sorted(keys)[0]
    source = FakeSourceS3(keys)
    dest = FakeDestS3(fail_keys={flaky}, fail_times=2)
    manifest = make_manifest()

    failures = trail_mode.run(make_config(tmp_path), FakeSession(source), FakeSession(dest), manifest)

    assert failures == 0
    assert len(dest.objects) == 5
    assert manifest.build()["run"]["collection_complete"] is True


def test_permanent_failure_is_recorded_not_swallowed(tmp_path):
    """The whole point: a failed object must not vanish from the record."""
    keys = source_keys(5)
    doomed = sorted(keys)[0]
    source = FakeSourceS3(keys)
    dest = FakeDestS3(fail_keys={doomed})
    manifest = make_manifest()

    failures = trail_mode.run(make_config(tmp_path), FakeSession(source), FakeSession(dest), manifest)

    assert failures == 1
    doc = manifest.build()
    assert doc["run"]["collection_complete"] is False
    assert doc["totals"]["objects_failed"] == 1
    assert doc["failed_objects"][0]["source_key"] == doomed
    # The other four still got collected.
    assert doc["totals"]["objects_collected"] == 4


def test_resume_skips_what_was_already_copied(tmp_path):
    keys = source_keys(10)
    source = FakeSourceS3(keys)
    dest = FakeDestS3()

    trail_mode.run(make_config(tmp_path), FakeSession(source), FakeSession(dest), make_manifest())
    assert len(dest.objects) == 10

    # Second run against a fresh destination: everything is in the state file,
    # so nothing should be copied again.
    dest2 = FakeDestS3()
    manifest2 = make_manifest()
    failures = trail_mode.run(
        make_config(tmp_path, resume=True), FakeSession(source), FakeSession(dest2), manifest2
    )

    assert failures == 0
    assert dest2.objects == {}
    assert any("skipped as already present" in note for note in manifest2.build()["notes"])


def test_resume_after_partial_failure_copies_only_the_missing_object(tmp_path):
    keys = source_keys(6)
    doomed = sorted(keys)[0]
    source = FakeSourceS3(keys)

    first = FakeDestS3(fail_keys={doomed})
    assert trail_mode.run(make_config(tmp_path), FakeSession(source), FakeSession(first), make_manifest()) == 1
    assert len(first.objects) == 5

    second = FakeDestS3()  # no longer failing
    manifest = make_manifest()
    failures = trail_mode.run(
        make_config(tmp_path, resume=True), FakeSession(source), FakeSession(second), manifest
    )

    assert failures == 0
    assert len(second.objects) == 1
    assert manifest.build()["objects"][0]["source_key"] == doomed


def test_digest_and_method_recorded_per_object(tmp_path):
    source = FakeSourceS3(source_keys(2))
    manifest = make_manifest()
    trail_mode.run(make_config(tmp_path), FakeSession(source), FakeSession(FakeDestS3()), manifest)

    for entry in manifest.build()["objects"]:
        assert entry["digest_method"] == "s3-sha256"
        assert len(entry["digest"]) == 64
        assert entry["digest"] == hashlib.sha256(entry["source_key"].encode()).hexdigest()


def test_dry_run_writes_nothing(tmp_path, capsys):
    source = FakeSourceS3(source_keys(7))
    dest = FakeDestS3()
    manifest = make_manifest()

    failures = trail_mode.run(
        make_config(tmp_path, dry_run=True), FakeSession(source), FakeSession(dest), manifest
    )

    assert failures == 0
    assert dest.objects == {}
    assert not (tmp_path / "state.ndjson").exists()
    assert "DRY RUN" in capsys.readouterr().out


def test_in_place_catalogues_without_copying(tmp_path, capsys):
    source = FakeSourceS3(source_keys(4))
    dest = FakeDestS3()
    manifest = make_manifest()

    trail_mode.run(
        make_config(tmp_path, in_place=True), FakeSession(source), FakeSession(dest), manifest
    )

    assert dest.objects == {}
    doc = manifest.build()
    assert doc["totals"]["objects_collected"] == 4
    # The custody caveat must be stated: we do not control this evidence.
    assert any("IN-PLACE" in note and "outside our control" in note for note in doc["notes"])
