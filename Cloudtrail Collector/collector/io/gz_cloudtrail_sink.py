"""Gzip CloudTrail S3-format objects for lookup mode (SOF-ELK compatible)."""

from __future__ import annotations

import gzip
from typing import Any, Callable

from ..sof_elk_ingest import serialize_cloudtrail_s3_object, validate_cloudtrail_record
from .gz_ndjson_sink import WrittenChunk, _MultipartSink


class GzipCloudTrailChunkWriter:
    """Rolling gzip objects, each a single ``{"Records":[...]}`` JSON document."""

    def __init__(
        self,
        *,
        client: Any,
        bucket: str,
        key_factory: Callable[[int], str],
        chunk_size: int,
        part_size: int,
        on_chunk_closed: Callable[[WrittenChunk], None] | None = None,
    ) -> None:
        self._client = client
        self._bucket = bucket
        self._key_factory = key_factory
        self._chunk_size = chunk_size
        self._part_size = part_size
        self._on_chunk_closed = on_chunk_closed

        self._chunk_index = 0
        self._pending: list[dict[str, Any]] = []
        self.chunks: list[WrittenChunk] = []

    def write(self, record: dict[str, Any]) -> None:
        validate_cloudtrail_record(record)
        trial = self._pending + [record]
        if self._pending and len(serialize_cloudtrail_s3_object(trial)) > self._chunk_size:
            self.roll()
        self._pending.append(record)

    def roll(self) -> WrittenChunk | None:
        if not self._pending:
            return None

        payload = serialize_cloudtrail_s3_object(self._pending)
        key = self._key_factory(self._chunk_index)
        sink = _MultipartSink(self._client, self._bucket, key, self._part_size)
        with gzip.GzipFile(fileobj=sink, mode="wb", compresslevel=6, mtime=0) as gz:
            gz.write(payload)

        size, digest, etag = sink.finish()
        chunk = WrittenChunk(
            key=key,
            size_bytes=size,
            uncompressed_bytes=len(payload),
            event_count=len(self._pending),
            sha256=digest,
            etag=etag,
            chunk_index=self._chunk_index,
        )
        self.chunks.append(chunk)
        if self._on_chunk_closed:
            self._on_chunk_closed(chunk)

        self._chunk_index += 1
        self._pending = []
        return chunk

    def abort(self) -> None:
        self._pending = []

    def close(self) -> None:
        self.roll()

    def __enter__(self) -> "GzipCloudTrailChunkWriter":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is not None:
            self.abort()
        else:
            self.close()
