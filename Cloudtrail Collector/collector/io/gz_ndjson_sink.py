"""Streaming gzipped-NDJSON sink for Mode B.

Nothing here buffers a dataset. Records are gzip-compressed as they arrive, and
the compressed stream is handed to S3 in fixed-size parts as soon as each part
fills. Peak memory is one part (16 MiB by default) regardless of whether the
run produces 10 MB or 10 TB, and no temporary file ever touches local disk.

Chunk rolling: a chunk closes once it has absorbed roughly ``chunk_size`` bytes
of *uncompressed* JSON, which is the number that determines how long Logstash
spends on a single object. The resulting objects are typically 20-40x smaller
after gzip.

The SHA256 recorded in the manifest is computed over the compressed bytes — the
exact bytes that land in S3 and that a verifier would later re-download and
hash. Hashing the uncompressed stream instead would produce a digest that
nobody could check against the stored object.
"""

from __future__ import annotations

import gzip
import hashlib
import io
from dataclasses import dataclass
from typing import Any, Callable

from botocore.exceptions import BotoCoreError, ClientError

from ..config import DEFAULT_UPLOAD_PART_SIZE
from ..errors import UploadError

# S3 requires every part except the last to be at least 5 MiB.
MIN_PART_SIZE = 5 * 1024**2


@dataclass(slots=True)
class WrittenChunk:
    """One completed S3 object."""

    key: str
    size_bytes: int           # compressed size, i.e. what S3 stores
    uncompressed_bytes: int
    event_count: int
    sha256: str               # of the compressed bytes
    etag: str | None
    chunk_index: int


class _MultipartSink(io.RawIOBase):
    """File-like target that streams writes into an S3 multipart upload.

    ``GzipFile`` writes here; every ``MIN_PART_SIZE``-or-larger accumulation is
    uploaded and dropped from memory.
    """

    def __init__(self, client: Any, bucket: str, key: str, part_size: int) -> None:
        super().__init__()
        if part_size < MIN_PART_SIZE:
            raise UploadError(
                f"part size {part_size} is below S3's {MIN_PART_SIZE}-byte minimum"
            )
        self._client = client
        self._bucket = bucket
        self._key = key
        self._part_size = part_size
        self._buffer = bytearray()
        self._parts: list[dict[str, Any]] = []
        self._hash = hashlib.sha256()
        self._bytes_written = 0
        self._upload_id: str | None = None
        self._aborted = False
        self._discarding = False

    def _ensure_upload(self) -> None:
        if self._upload_id is None:
            response = self._client.create_multipart_upload(
                Bucket=self._bucket,
                Key=self._key,
                ContentType="application/x-ndjson",
                ContentEncoding="gzip",
            )
            self._upload_id = response["UploadId"]

    def writable(self) -> bool:
        return True

    def write(self, data) -> int:  # type: ignore[override]
        chunk = bytes(data)
        if self._discarding:
            # Aborting. Closing the gzip stream still emits a trailer; accepting
            # it here would start an upload for the sole purpose of aborting it.
            return len(chunk)
        self._buffer.extend(chunk)
        self._hash.update(chunk)
        self._bytes_written += len(chunk)
        while len(self._buffer) >= self._part_size:
            self._flush_part(self._part_size)
        return len(chunk)

    def _flush_part(self, size: int) -> None:
        self._ensure_upload()
        payload = bytes(self._buffer[:size])
        del self._buffer[:size]
        part_number = len(self._parts) + 1
        try:
            response = self._client.upload_part(
                Bucket=self._bucket,
                Key=self._key,
                UploadId=self._upload_id,
                PartNumber=part_number,
                Body=payload,
            )
        except (ClientError, BotoCoreError) as exc:
            self.abort()
            raise UploadError(
                f"failed uploading part {part_number} of s3://{self._bucket}/{self._key}: {exc}"
            ) from exc
        self._parts.append({"PartNumber": part_number, "ETag": response["ETag"]})

    def finish(self) -> tuple[int, str, str | None]:
        """Complete the upload. Returns (bytes, sha256 hex, ETag)."""
        if self._bytes_written == 0:
            return 0, self._hash.hexdigest(), None

        if self._upload_id is None:
            # Small enough that it never needed multipart at all.
            try:
                response = self._client.put_object(
                    Bucket=self._bucket,
                    Key=self._key,
                    Body=bytes(self._buffer),
                    ContentType="application/x-ndjson",
                    ContentEncoding="gzip",
                )
            except (ClientError, BotoCoreError) as exc:
                raise UploadError(
                    f"failed writing s3://{self._bucket}/{self._key}: {exc}"
                ) from exc
            self._buffer.clear()
            return self._bytes_written, self._hash.hexdigest(), response.get("ETag")

        if self._buffer:
            self._flush_part(len(self._buffer))

        try:
            response = self._client.complete_multipart_upload(
                Bucket=self._bucket,
                Key=self._key,
                UploadId=self._upload_id,
                MultipartUpload={"Parts": self._parts},
            )
        except (ClientError, BotoCoreError) as exc:
            self.abort()
            raise UploadError(
                f"failed completing upload of s3://{self._bucket}/{self._key}: {exc}"
            ) from exc
        return self._bytes_written, self._hash.hexdigest(), response.get("ETag")

    def begin_discard(self) -> None:
        """Stop accepting writes, ahead of an abort."""
        self._discarding = True

    def abort(self) -> None:
        """Abandon the upload so no orphaned parts accrue charges."""
        self._discarding = True
        if self._upload_id is None or self._aborted:
            return
        self._aborted = True
        try:
            self._client.abort_multipart_upload(
                Bucket=self._bucket, Key=self._key, UploadId=self._upload_id
            )
        except (ClientError, BotoCoreError):
            pass


class GzipNdjsonChunkWriter:
    """Writes records into rolling gzipped-NDJSON objects in S3.

    Usage::

        with GzipNdjsonChunkWriter(...) as writer:
            for record in records:
                writer.write(to_ndjson_line(record))
        chunks = writer.chunks
    """

    def __init__(
        self,
        *,
        client: Any,
        bucket: str,
        key_factory: Callable[[int], str],
        chunk_size: int,
        part_size: int = DEFAULT_UPLOAD_PART_SIZE,
        on_chunk_closed: Callable[[WrittenChunk], None] | None = None,
    ) -> None:
        self._client = client
        self._bucket = bucket
        self._key_factory = key_factory
        self._chunk_size = chunk_size
        self._part_size = part_size
        self._on_chunk_closed = on_chunk_closed

        self._chunk_index = 0
        self._sink: _MultipartSink | None = None
        self._gzip: gzip.GzipFile | None = None
        self._current_key: str | None = None
        self._uncompressed = 0
        self._events = 0
        self.chunks: list[WrittenChunk] = []

    def write(self, line: bytes) -> None:
        """Append one NDJSON line, rolling to a new object when the chunk fills."""
        if self._gzip is None:
            self._open_chunk()
        assert self._gzip is not None
        self._gzip.write(line)
        self._uncompressed += len(line)
        self._events += 1
        if self._uncompressed >= self._chunk_size:
            self.roll()

    def _open_chunk(self) -> None:
        self._current_key = self._key_factory(self._chunk_index)
        self._sink = _MultipartSink(self._client, self._bucket, self._current_key, self._part_size)
        # mtime=0 keeps the gzip header byte-identical across runs, so the same
        # input produces the same digest.
        self._gzip = gzip.GzipFile(fileobj=self._sink, mode="wb", compresslevel=6, mtime=0)
        self._uncompressed = 0
        self._events = 0

    def roll(self) -> WrittenChunk | None:
        """Close the current object and start a new one. Returns the closed chunk."""
        if self._gzip is None or self._sink is None or self._current_key is None:
            return None

        self._gzip.close()
        size, digest, etag = self._sink.finish()

        chunk = WrittenChunk(
            key=self._current_key,
            size_bytes=size,
            uncompressed_bytes=self._uncompressed,
            event_count=self._events,
            sha256=digest,
            etag=etag,
            chunk_index=self._chunk_index,
        )
        self.chunks.append(chunk)
        if self._on_chunk_closed:
            self._on_chunk_closed(chunk)

        self._chunk_index += 1
        self._gzip = None
        self._sink = None
        self._current_key = None
        return chunk

    def abort(self) -> None:
        """Abandon the in-flight object without completing it."""
        if self._sink is not None:
            self._sink.begin_discard()
        if self._gzip is not None:
            try:
                self._gzip.close()
            except Exception:
                pass
            self._gzip = None
        if self._sink is not None:
            self._sink.abort()
            self._sink = None

    def close(self) -> None:
        self.roll()

    def __enter__(self) -> "GzipNdjsonChunkWriter":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is not None:
            self.abort()
        else:
            self.close()

    @property
    def total_events(self) -> int:
        return sum(c.event_count for c in self.chunks) + self._events


