"""Mode A — collect from an existing trail's S3 bucket.

This is the preferred mode whenever a trail exists: it is the only one that can
carry data events and Insights, and it has no 90-day horizon.

Enumeration walks one account/region/day prefix at a time. Listing the bucket
root instead would mean paging through every object in a bucket that may hold
hundreds of millions of them, just to find a two-week window.
"""

from __future__ import annotations

import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any, Iterator

from botocore.exceptions import BotoCoreError, ClientError

from ..config import RunConfig, boto_config
from ..errors import CopyVerificationError
from ..io.s3_copy import copy_object
from ..logging_setup import get_logger
from ..manifest import CollectedObject, FailedObject, ManifestBuilder
from ..naming import TRAIL_LOG_TYPES, day_from_trail_key, dest_key, trail_day_prefix
from ..progress import Progress

MAX_COPY_ATTEMPTS = 4


@dataclass(slots=True)
class SourceObject:
    """One object found in the source trail bucket."""

    key: str
    size: int
    region: str
    day: date
    log_type: str

    @property
    def filename(self) -> str:
        return self.key.rsplit("/", 1)[-1]


def enumerate_objects(
    client: Any,
    config: RunConfig,
) -> Iterator[SourceObject]:
    """Yield every source object in scope, one day-prefix at a time."""
    logger = get_logger()
    assert config.source_bucket and config.source_account_id
    assert config.start and config.end

    paginator = client.get_paginator("list_objects_v2")

    for region in config.regions:
        for day in _days(config.start.date(), config.end.date()):
            for log_type in TRAIL_LOG_TYPES:
                prefix = trail_day_prefix(
                    source_prefix=config.source_prefix,
                    account_id=config.source_account_id,
                    region=region,
                    day=day,
                    org_id=config.org_id,
                    log_type=log_type,
                )
                found = 0
                try:
                    pages = paginator.paginate(Bucket=config.source_bucket, Prefix=prefix)
                    for page in pages:
                        for item in page.get("Contents", []):
                            key = item["Key"]
                            if key.endswith("/"):
                                continue
                            found += 1
                            yield SourceObject(
                                key=key,
                                size=int(item["Size"]),
                                region=region,
                                day=day_from_trail_key(key) or day,
                                log_type=log_type,
                            )
                except ClientError as exc:
                    # A prefix that cannot be listed is a hole in the evidence
                    # set, so it is logged as an error rather than skipped.
                    logger.error(
                        "failed listing source prefix",
                        extra={"prefix": prefix, "error": str(exc)},
                    )
                    raise

                logger.debug(
                    "enumerated prefix",
                    extra={"prefix": prefix, "objects": found},
                )


def _days(start: date, end: date) -> Iterator[date]:
    """Every calendar day from start to end inclusive.

    Inclusive of the end day because CloudTrail delivers an object under the day
    prefix matching the events inside it, and a run ending at 09:00 still wants
    that day's objects.
    """
    current = start
    while current <= end:
        yield current
        current += timedelta(days=1)


def run(
    config: RunConfig,
    source_session: Any,
    dest_session: Any,
    manifest: ManifestBuilder,
) -> int:
    """Execute a Mode A collection. Returns the number of failures."""
    logger = get_logger()
    source_client = source_session.client(
        "s3", config=boto_config(pool_size=max(config.concurrency * 2, 32))
    )

    if config.dry_run:
        return _dry_run(config, source_client, manifest)

    if config.in_place:
        return _in_place(config, source_client, manifest)

    dest_client = dest_session.client(
        "s3", config=boto_config(pool_size=max(config.concurrency * 2, 32))
    )

    from ..state import RunState  # local import keeps the module import graph flat

    state = RunState(config.state_file, config.state_identity())
    state.load(resume=config.resume)

    progress = Progress()
    failures = 0
    skipped = 0

    try:
        with ThreadPoolExecutor(max_workers=config.concurrency) as pool:
            pending: dict[Any, SourceObject] = {}

            for obj in enumerate_objects(source_client, config):
                target = dest_key(
                    root_prefix=config.dest_prefix,
                    engagement_id=config.engagement_id,
                    account_id=config.source_account_id,  # type: ignore[arg-type]
                    region=obj.region,
                    day=obj.day,
                    filename=obj.filename,
                )

                if state.is_completed(target):
                    skipped += 1
                    continue

                future = pool.submit(
                    _copy_one,
                    source_client=source_client,
                    dest_client=dest_client,
                    config=config,
                    obj=obj,
                    target=target,
                )
                pending[future] = obj

                # Bound the queue so enumerating a bucket with hundreds of
                # millions of objects does not build an unbounded list of
                # futures in memory. Blocks once the bound is hit: a purely
                # non-blocking drain would let `pending` keep growing whenever
                # no copy happened to have finished yet.
                while len(pending) >= config.concurrency * 8:
                    failures += _drain(pending, manifest, state, progress, block_all=False)

            failures += _drain(pending, manifest, state, progress, block_all=True)
    finally:
        state.close()
        progress.finish()

    if skipped:
        logger.info("skipped already-collected objects", extra={"skipped": skipped})
        manifest.add_note(f"{skipped} object(s) skipped as already present from a prior run")

    return failures


def _drain(
    pending: dict[Any, SourceObject],
    manifest: ManifestBuilder,
    state: Any,
    progress: Progress,
    *,
    block_all: bool,
) -> int:
    """Harvest completed futures, recording each outcome.

    With ``block_all`` false this waits for at least one future rather than
    polling, so the caller's backpressure loop cannot spin.
    """
    logger = get_logger()
    failures = 0

    if block_all:
        done = list(as_completed(pending))
    else:
        finished, _ = wait(list(pending), return_when=FIRST_COMPLETED)
        done = list(finished)

    for future in done:
        obj = pending.pop(future)
        try:
            collected = future.result()
        except Exception as exc:  # noqa: BLE001 - every failure must be recorded
            failures += 1
            manifest.add_failed_object(
                FailedObject(
                    source_key=obj.key,
                    dest_key=None,
                    error=f"{type(exc).__name__}: {exc}",
                    attempts=MAX_COPY_ATTEMPTS,
                )
            )
            logger.error(
                "copy failed",
                extra={"source_key": obj.key, "error": str(exc)},
            )
            progress.update(failures=1)
            continue

        manifest.add_object(collected)
        state.mark_completed(collected.dest_key)
        progress.update(objects=1, bytes_=collected.size_bytes)

    return failures


def _copy_one(
    *,
    source_client: Any,
    dest_client: Any,
    config: RunConfig,
    obj: SourceObject,
    target: str,
) -> CollectedObject:
    """Copy one object, retrying transient and verification failures."""
    logger = get_logger()
    last_error: Exception | None = None

    for attempt in range(1, MAX_COPY_ATTEMPTS + 1):
        try:
            result = copy_object(
                source_client=source_client,
                dest_client=dest_client,
                source_bucket=config.source_bucket,  # type: ignore[arg-type]
                source_key=obj.key,
                dest_bucket=config.dest_bucket,  # type: ignore[arg-type]
                dest_key=target,
            )
            return CollectedObject(
                source_key=obj.key,
                dest_key=target,
                size_bytes=result.size_bytes,
                digest=result.digest,
                digest_method=result.digest_method,
                digest_note=result.digest_note,
                source_etag=result.source_etag,
                dest_etag=result.dest_etag,
            )
        except (CopyVerificationError, ClientError, BotoCoreError) as exc:
            last_error = exc
            if attempt < MAX_COPY_ATTEMPTS:
                delay = min(2**attempt, 30)
                logger.warning(
                    "copy attempt failed, retrying",
                    extra={
                        "source_key": obj.key,
                        "attempt": attempt,
                        "delay_s": delay,
                        "error": str(exc),
                    },
                )
                time.sleep(delay)

    raise last_error if last_error else RuntimeError("copy failed with no recorded error")


def _dry_run(config: RunConfig, source_client: Any, manifest: ManifestBuilder) -> int:
    """Enumerate and report totals without writing anything."""
    logger = get_logger()
    total_objects = 0
    total_bytes = 0
    per_region: dict[str, tuple[int, int]] = {}

    for obj in enumerate_objects(source_client, config):
        total_objects += 1
        total_bytes += obj.size
        count, size = per_region.get(obj.region, (0, 0))
        per_region[obj.region] = (count + 1, size + obj.size)

    print(f"\nDRY RUN — mode=trail engagement={config.engagement_id}")
    print(f"  source     s3://{config.source_bucket}/{config.source_prefix}")
    print(f"  dest       s3://{config.dest_bucket}/{config.dest_prefix}/{config.engagement_id}/")
    print(f"  range      {config.start} .. {config.end}")
    print(f"  regions    {', '.join(config.regions)}")
    print()
    for region in sorted(per_region):
        count, size = per_region[region]
        print(f"  {region:<18} {count:>10,} objects  {_gib(size):>12}")
    print(f"  {'TOTAL':<18} {total_objects:>10,} objects  {_gib(total_bytes):>12}")
    print("\nNothing was written.\n")

    manifest.add_note(
        f"dry run: {total_objects} objects / {total_bytes} bytes would be collected"
    )
    logger.info(
        "dry run complete",
        extra={"objects": total_objects, "bytes": total_bytes},
    )
    return 0


def _in_place(config: RunConfig, source_client: Any, manifest: ManifestBuilder) -> int:
    """Catalogue the source without copying.

    Produces a manifest describing evidence that stays in the client's bucket.
    That means we do not control retention or immutability for it, which is
    recorded in the manifest because it is the kind of thing that gets asked
    about later.
    """
    logger = get_logger()
    count = 0

    for obj in enumerate_objects(source_client, config):
        head = source_client.head_object(
            Bucket=config.source_bucket, Key=obj.key, ChecksumMode="ENABLED"
        )
        raw = head.get("ChecksumSHA256")
        if raw:
            from ..manifest import s3_checksum_to_hex

            digest, method = s3_checksum_to_hex(raw)
            note = None
        else:
            digest, method = None, "none"
            note = (
                "Source object carries no SHA256 and was not copied, so no digest "
                "could be obtained without egressing the object."
            )

        manifest.add_object(
            CollectedObject(
                source_key=obj.key,
                dest_key=f"s3://{config.source_bucket}/{obj.key}",
                size_bytes=obj.size,
                digest=digest,
                digest_method=method,  # type: ignore[arg-type]
                digest_note=note,
                source_etag=head.get("ETag"),
            )
        )
        count += 1

    manifest.add_note(
        "IN-PLACE collection: evidence was NOT copied and remains in the source "
        f"bucket s3://{config.source_bucket}. Retention, immutability, and access "
        "control for this evidence are outside our control, and the objects may be "
        "modified or deleted by the source account at any time."
    )
    logger.info("in-place catalogue complete", extra={"objects": count})
    print(f"\nIN-PLACE — catalogued {count:,} objects. No data was copied.\n")
    return 0


def _gib(size: int) -> str:
    return f"{size / 1024**3:,.2f} GiB"
