"""Server-side S3 copy.

The governing constraint: object bytes must never transit the collector host.
At terabyte scale, downloading and re-uploading would be slow, expensive, and
would make the collector's own network the single point of failure for the
evidence set. So every copy is a ``CopyObject`` (or ``UploadPartCopy`` for
objects too large for one call), where S3 moves the bytes internally.

That constraint is also why the manifest's SHA256 comes from S3 rather than
from ``hashlib`` here: asking S3 to compute the checksum during the copy is
the only way to get a cryptographic digest without egressing the data.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from ..config import DEFAULT_COPY_PART_SIZE, MULTIPART_COPY_THRESHOLD
from ..errors import CopyVerificationError
from ..manifest import (
    COMPOSITE_DIGEST_NOTE,
    NO_DIGEST_NOTE,
    DigestMethod,
    s3_checksum_to_hex,
)


@dataclass(slots=True)
class CopyResult:
    """Outcome of one object copy, as recorded in the manifest."""

    size_bytes: int
    digest: str | None
    digest_method: DigestMethod
    digest_note: str | None
    source_etag: str | None
    dest_etag: str | None
    multipart: bool


def head_source(client: Any, bucket: str, key: str) -> dict[str, Any]:
    """HEAD the source object. Raises ClientError if it is gone."""
    return client.head_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")


def copy_object(
    *,
    source_client: Any,
    dest_client: Any,
    source_bucket: str,
    source_key: str,
    dest_bucket: str,
    dest_key: str,
    source_head: dict[str, Any] | None = None,
) -> CopyResult:
    """Copy one object server-side and verify the result.

    ``ChecksumAlgorithm='SHA256'`` makes S3 compute a SHA256 of the destination
    object as it writes it. For a single-call copy that is a true whole-object
    digest. For a multipart copy S3 returns a composite digest instead, which is
    labelled as such in the result so the manifest never overstates what it has.
    """
    head = source_head or head_source(source_client, source_bucket, source_key)
    size = int(head["ContentLength"])
    source_etag = head.get("ETag")

    if size >= MULTIPART_COPY_THRESHOLD:
        response = _multipart_copy(
            dest_client=dest_client,
            source_bucket=source_bucket,
            source_key=source_key,
            dest_bucket=dest_bucket,
            dest_key=dest_key,
            size=size,
        )
        multipart = True
    else:
        response = dest_client.copy_object(
            Bucket=dest_bucket,
            Key=dest_key,
            CopySource={"Bucket": source_bucket, "Key": source_key},
            ChecksumAlgorithm="SHA256",
            MetadataDirective="COPY",
        )
        multipart = False

    digest, method, note = _extract_digest(response, multipart)

    dest_head = dest_client.head_object(Bucket=dest_bucket, Key=dest_key, ChecksumMode="ENABLED")
    dest_size = int(dest_head["ContentLength"])
    if dest_size != size:
        raise CopyVerificationError(
            f"size mismatch after copy of s3://{source_bucket}/{source_key}: "
            f"source is {size} bytes, destination s3://{dest_bucket}/{dest_key} is "
            f"{dest_size} bytes"
        )

    if digest is None:
        digest_raw = dest_head.get("ChecksumSHA256")
        if digest_raw:
            digest, method = s3_checksum_to_hex(digest_raw)
            note = COMPOSITE_DIGEST_NOTE if method == "s3-sha256-composite" else None
        else:
            method, note = "none", NO_DIGEST_NOTE

    # A single-part copy preserves the source ETag (it is the MD5 of the bytes),
    # which gives a second, independent integrity signal at no cost. A multipart
    # copy re-chunks the object, so its ETag legitimately differs and comparing
    # them would produce a false alarm.
    dest_etag = dest_head.get("ETag")
    if not multipart and source_etag and dest_etag and source_etag != dest_etag:
        raise CopyVerificationError(
            f"ETag mismatch after copy of s3://{source_bucket}/{source_key}: "
            f"source {source_etag} != destination {dest_etag}"
        )

    return CopyResult(
        size_bytes=size,
        digest=digest,
        digest_method=method,
        digest_note=note,
        source_etag=source_etag,
        dest_etag=dest_etag,
        multipart=multipart,
    )


def _extract_digest(
    response: dict[str, Any], multipart: bool
) -> tuple[str | None, DigestMethod, str | None]:
    """Pull the SHA256 out of a copy response, if S3 returned one."""
    payload = response.get("CopyObjectResult") or response
    raw = payload.get("ChecksumSHA256")
    if not raw:
        return None, "none", None
    digest, method = s3_checksum_to_hex(raw)
    note = COMPOSITE_DIGEST_NOTE if method == "s3-sha256-composite" or multipart else None
    return digest, method, note


def _multipart_copy(
    *,
    dest_client: Any,
    source_bucket: str,
    source_key: str,
    dest_bucket: str,
    dest_key: str,
    size: int,
    part_size: int = DEFAULT_COPY_PART_SIZE,
) -> dict[str, Any]:
    """Copy an object larger than 5 GiB using UploadPartCopy.

    Still entirely server-side: each part is a byte-range copy inside S3. On any
    failure the upload is aborted so the destination bucket is not left holding
    billable orphaned parts.
    """
    upload = dest_client.create_multipart_upload(
        Bucket=dest_bucket,
        Key=dest_key,
        ChecksumAlgorithm="SHA256",
    )
    upload_id = upload["UploadId"]

    try:
        parts: list[dict[str, Any]] = []
        for index, (first, last) in enumerate(_byte_ranges(size, part_size), start=1):
            response = dest_client.upload_part_copy(
                Bucket=dest_bucket,
                Key=dest_key,
                UploadId=upload_id,
                PartNumber=index,
                CopySource={"Bucket": source_bucket, "Key": source_key},
                CopySourceRange=f"bytes={first}-{last}",
            )
            result = response["CopyPartResult"]
            part: dict[str, Any] = {"PartNumber": index, "ETag": result["ETag"]}
            if "ChecksumSHA256" in result:
                part["ChecksumSHA256"] = result["ChecksumSHA256"]
            parts.append(part)

        return dest_client.complete_multipart_upload(
            Bucket=dest_bucket,
            Key=dest_key,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )
    except (ClientError, BotoCoreError):
        try:
            dest_client.abort_multipart_upload(
                Bucket=dest_bucket, Key=dest_key, UploadId=upload_id
            )
        except (ClientError, BotoCoreError):
            # The original failure is the one worth reporting; a failed abort
            # only leaves orphaned parts, which the lifecycle rule cleans up.
            pass
        raise


def _byte_ranges(size: int, part_size: int) -> list[tuple[int, int]]:
    """Inclusive byte ranges covering ``size`` bytes."""
    ranges = []
    offset = 0
    while offset < size:
        end = min(offset + part_size, size) - 1
        ranges.append((offset, end))
        offset = end + 1
    return ranges
