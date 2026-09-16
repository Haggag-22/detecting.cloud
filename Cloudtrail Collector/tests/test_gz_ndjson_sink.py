"""Streaming gzip NDJSON sink.

Covers the failure modes that would corrupt an evidence set without raising:
records lost or reordered across a chunk boundary, a manifest digest that does
not match the stored bytes, and partial objects left behind by a failed window.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os

import pytest

from collector.envelope import to_ndjson_line
from collector.errors import UploadError
from collector.io.gz_ndjson_sink import MIN_PART_SIZE, GzipNdjsonChunkWriter

PART_SIZE = MIN_PART_SIZE


def records(count: int, pad: int = 200) -> list[dict]:
    return [
        {"eventName": f"Event{i}", "eventTime": "2026-08-14T00:00:00Z", "pad": "x" * pad}
        for i in range(count)
    ]


def incompressible(count: int) -> list[dict]:
    """Payloads gzip cannot shrink, so parts actually reach the 5 MiB minimum."""
    return [
        {"eventName": f"E{i}", "pad": base64.b64encode(os.urandom(400)).decode()}
        for i in range(count)
    ]


def write_all(writer: GzipNdjsonChunkWriter, items: list[dict]) -> None:
    with writer:
        for item in items:
            writer.write(to_ndjson_line(item))


def make_writer(fake_s3, **overrides) -> GzipNdjsonChunkWriter:
    kwargs = {
        "client": fake_s3,
        "bucket": "evidence",
        "key_factory": lambda i: f"aws/IR-1/chunk_{i:05d}.json.gz",
        "chunk_size": 200_000,
        "part_size": PART_SIZE,
    }
    kwargs.update(overrides)
    return GzipNdjsonChunkWriter(**kwargs)


def test_rolls_into_multiple_chunks(fake_s3):
    writer = make_writer(fake_s3)
    write_all(writer, records(5000))
    assert len(writer.chunks) > 1
    assert len(fake_s3.objects) == len(writer.chunks)


def test_every_chunk_is_valid_gzip_ndjson(fake_s3):
    writer = make_writer(fake_s3)
    write_all(writer, records(5000))
    for chunk in writer.chunks:
        lines = gzip.decompress(fake_s3.objects[chunk.key]).decode().splitlines()
        assert len(lines) == chunk.event_count
        for line in lines:
            json.loads(line)


def test_no_records_lost_or_reordered_across_chunk_boundaries(fake_s3):
    """The boundary is where a streaming writer silently drops a record."""
    original = records(5000)
    writer = make_writer(fake_s3)
    write_all(writer, original)

    recovered = [
        json.loads(line)
        for chunk in writer.chunks
        for line in gzip.decompress(fake_s3.objects[chunk.key]).decode().splitlines()
    ]
    assert recovered == original


def test_digest_matches_the_bytes_actually_stored(fake_s3):
    """A digest over anything else is unverifiable by whoever re-downloads it."""
    writer = make_writer(fake_s3)
    write_all(writer, records(5000))
    for chunk in writer.chunks:
        stored = fake_s3.objects[chunk.key]
        assert hashlib.sha256(stored).hexdigest() == chunk.sha256
        assert len(stored) == chunk.size_bytes


def test_event_counts_sum_to_input(fake_s3):
    writer = make_writer(fake_s3)
    write_all(writer, records(5000))
    assert sum(c.event_count for c in writer.chunks) == 5000


def test_chunk_indices_are_sequential(fake_s3):
    writer = make_writer(fake_s3)
    write_all(writer, records(5000))
    assert [c.chunk_index for c in writer.chunks] == list(range(len(writer.chunks)))


def test_small_output_uses_put_object_not_multipart(fake_s3):
    writer = make_writer(fake_s3, chunk_size=10**9)
    write_all(writer, records(10))
    assert len(writer.chunks) == 1
    assert not fake_s3.uploads
    assert gzip.decompress(fake_s3.objects[writer.chunks[0].key]).decode().count("\n") == 10


def test_multipart_path_completes_when_parts_are_reached(fake_s3):
    writer = make_writer(fake_s3, chunk_size=10**9)
    write_all(writer, incompressible(20000))
    assert not fake_s3.uploads, "upload left in flight"
    chunk = writer.chunks[0]
    assert chunk.size_bytes > PART_SIZE
    assert hashlib.sha256(fake_s3.objects[chunk.key]).hexdigest() == chunk.sha256


def test_failure_mid_window_leaves_no_completed_object(fake_s3):
    """A half-written window must not look like a successful one."""
    writer = make_writer(fake_s3, chunk_size=10**9)
    with pytest.raises(RuntimeError):
        with writer:
            for record in incompressible(20000):
                writer.write(to_ndjson_line(record))
            assert fake_s3.in_flight_parts > 0, "test needs real parts in flight"
            raise RuntimeError("simulated window failure")

    assert fake_s3.objects == {}
    assert fake_s3.aborted
    assert not fake_s3.uploads


def test_abort_does_not_start_an_upload_just_to_abort_it(fake_s3):
    """Closing the gzip stream emits a trailer; it must not create an upload."""
    writer = make_writer(fake_s3, chunk_size=10**9)
    with pytest.raises(RuntimeError):
        with writer:
            writer.write(to_ndjson_line({"eventName": "OnlyOne"}))
            raise RuntimeError("fail before any part is due")

    assert not fake_s3.uploads
    assert not fake_s3.objects


def test_writing_nothing_creates_no_object(fake_s3):
    writer = make_writer(fake_s3)
    with writer:
        pass
    assert fake_s3.objects == {}
    assert writer.chunks == []


def test_part_size_below_s3_minimum_rejected(fake_s3):
    """S3 rejects sub-5 MiB parts at completion, long after the data is gone."""
    writer = make_writer(fake_s3, part_size=1024)
    with pytest.raises(UploadError, match="minimum"):
        writer.write(to_ndjson_line({"eventName": "X"}))


def test_gzip_output_is_byte_reproducible(fake_s3):
    """Identical input must give an identical digest, so mtime must be pinned."""
    items = records(500)
    digests = []
    for _ in range(2):
        from tests.conftest import FakeS3

        s3 = FakeS3()
        writer = make_writer(s3, chunk_size=10**9)
        write_all(writer, items)
        digests.append(writer.chunks[0].sha256)
    assert digests[0] == digests[1]
