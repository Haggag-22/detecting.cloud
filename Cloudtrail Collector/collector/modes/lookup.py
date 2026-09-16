"""Mode B — collect via the CloudTrail LookupEvents API.

This is the backfill path, used when no trail exists. Its limits are severe and
must be stated everywhere they could mislead an analyst:

* Management events only. Data events and Insights are not returned.
* 90 days of history, maximum.
* Roughly 2 requests/second/region at 50 events per call — about 100 events per
  second per region. A busy account generating millions of events per day
  cannot be fully collected this way in reasonable time.

The pagination token expires after roughly an hour, so the range is cut into
windows and each window paginates on its own token chain. A window that dies is
restarted from its start boundary rather than aborting the run.
"""

from __future__ import annotations

import random
import time
from typing import Any, Iterator

from botocore.exceptions import BotoCoreError, ClientError

from ..config import DEFAULT_UPLOAD_PART_SIZE, RunConfig, boto_config
from ..envelope import unwrap_event
from ..errors import EnvelopeError
from ..io.gz_cloudtrail_sink import GzipCloudTrailChunkWriter
from ..io.gz_ndjson_sink import WrittenChunk
from ..logging_setup import get_logger
from ..manifest import CollectedObject, FailedWindow, ManifestBuilder
from ..naming import dest_key, lookup_object_name
from ..progress import Progress
from ..state import Checkpoint, RunState
from ..windows import Window, slice_windows, warn_if_outside_retention

# Errors that mean "slow down", not "give up".
THROTTLE_CODES = frozenset(
    {"ThrottlingException", "Throttling", "RequestLimitExceeded", "TooManyRequestsException"}
)
# Errors that mean the token chain is dead and the window must restart.
TOKEN_CODES = frozenset({"InvalidNextTokenException", "InvalidTokenException"})

MAX_THROTTLE_RETRIES = 8
MAX_WINDOW_RESTARTS = 3
PAGE_SIZE = 50  # API maximum


def run(
    config: RunConfig,
    source_session: Any,
    dest_session: Any,
    manifest: ManifestBuilder,
) -> int:
    """Execute a Mode B collection. Returns the number of failed windows."""
    logger = get_logger()
    assert config.start and config.end and config.source_account_id

    warning = warn_if_outside_retention(config.start)
    if warning:
        logger.warning("retention horizon", extra={"detail": warning})
        manifest.add_note(warning)
        print(f"\n  WARNING: {warning}\n")

    windows = slice_windows(config.start, config.end, config.window)
    logger.info(
        "planned lookup collection",
        extra={
            "regions": config.regions,
            "windows_per_region": len(windows),
            "total_windows": len(windows) * len(config.regions),
        },
    )

    if config.dry_run:
        return _dry_run(config, windows, manifest)

    dest_client = dest_session.client("s3", config=boto_config())
    state = RunState(config.state_file, config.state_identity())
    state.load(resume=config.resume)

    progress = Progress()
    failures = 0

    try:
        for region in config.regions:
            client = source_session.client(
                "cloudtrail", region_name=region, config=boto_config()
            )
            for window in windows:
                if state.is_window_done(region, window.start.isoformat(), window.end.isoformat()):
                    logger.debug(
                        "window already complete, skipping",
                        extra={"region": region, "window": window.key()},
                    )
                    continue

                try:
                    _collect_window(
                        config=config,
                        client=client,
                        dest_client=dest_client,
                        region=region,
                        window=window,
                        state=state,
                        manifest=manifest,
                        progress=progress,
                    )
                except Exception as exc:  # noqa: BLE001 - must be recorded, not raised
                    failures += 1
                    checkpoint = state.checkpoint_for(
                        region, window.start.isoformat(), window.end.isoformat()
                    )
                    manifest.add_failed_window(
                        FailedWindow(
                            region=region,
                            window_start=window.start.isoformat(),
                            window_end=window.end.isoformat(),
                            error=f"{type(exc).__name__}: {exc}",
                            events_written_before_failure=(
                                checkpoint.events_written if checkpoint else 0
                            ),
                        )
                    )
                    logger.error(
                        "window failed",
                        extra={
                            "region": region,
                            "window": window.key(),
                            "error": str(exc),
                        },
                    )
    finally:
        state.close()
        progress.finish()

    return failures


def _collect_window(
    *,
    config: RunConfig,
    client: Any,
    dest_client: Any,
    region: str,
    window: Window,
    state: RunState,
    manifest: ManifestBuilder,
    progress: Progress,
) -> None:
    """Pull one window to completion, restarting on token expiry."""
    logger = get_logger()
    account_id = config.source_account_id
    assert account_id

    for restart in range(MAX_WINDOW_RESTARTS + 1):
        # Re-running a window rewrites the same deterministic keys. Any chunks
        # left by the abandoned attempt are removed first, because a shorter
        # retry would otherwise leave trailing objects behind and double-count
        # their events at ingest. The destination bucket is versioned, so this
        # is recoverable.
        if restart or config.resume:
            _clear_window_chunks(
                dest_client=dest_client,
                config=config,
                region=region,
                window=window,
                account_id=account_id,
            )

        def key_factory(index: int, _region: str = region, _window: Window = window) -> str:
            return dest_key(
                root_prefix=config.dest_prefix,
                engagement_id=config.engagement_id,
                account_id=account_id,
                region=_region,
                day=_window.start.date(),
                filename=lookup_object_name(account_id, _region, _window.start, index),
            )

        def on_chunk(chunk: WrittenChunk) -> None:
            manifest.add_object(
                CollectedObject(
                    source_key=(
                        f"cloudtrail:LookupEvents/{region}/"
                        f"{window.start.isoformat()}..{window.end.isoformat()}"
                    ),
                    dest_key=chunk.key,
                    size_bytes=chunk.size_bytes,
                    digest=chunk.sha256,
                    digest_method="local-sha256",
                    dest_etag=chunk.etag,
                    event_count=chunk.event_count,
                    digest_note=(
                        "SHA256 of the stored gzip bytes, computed while streaming. "
                        f"Uncompressed size {chunk.uncompressed_bytes} bytes."
                    ),
                )
            )

        writer = GzipCloudTrailChunkWriter(
            client=dest_client,
            bucket=config.dest_bucket,  # type: ignore[arg-type]
            key_factory=key_factory,
            chunk_size=config.chunk_size_bytes,
            part_size=DEFAULT_UPLOAD_PART_SIZE,
            on_chunk_closed=on_chunk,
        )

        events = 0
        try:
            with writer:
                for record, token in _iter_events(client, window):
                    writer.write(record)
                    events += 1
                    progress.update(events=1)
                    if events % PAGE_SIZE == 0:
                        state.save_checkpoint(
                            Checkpoint(
                                region=region,
                                window_start=window.start.isoformat(),
                                window_end=window.end.isoformat(),
                                last_token=token,
                                events_written=events,
                            )
                        )
        except _TokenExpired as exc:
            if restart >= MAX_WINDOW_RESTARTS:
                raise RuntimeError(
                    f"window {window.key()} in {region} exhausted "
                    f"{MAX_WINDOW_RESTARTS} restarts after token expiry. Reduce "
                    f"--window-hours so each window completes inside the ~60 minute "
                    f"token lifetime."
                ) from exc
            logger.warning(
                "pagination token expired, restarting window from its start boundary",
                extra={
                    "region": region,
                    "window": window.key(),
                    "restart": restart + 1,
                    "events_discarded": events,
                },
            )
            continue

        total = sum(c.event_count for c in writer.chunks)
        progress.update(objects=len(writer.chunks), bytes_=sum(c.size_bytes for c in writer.chunks))
        state.mark_window_done(region, window.start.isoformat(), window.end.isoformat())
        logger.info(
            "window complete",
            extra={
                "region": region,
                "window": window.key(),
                "events": total,
                "objects": len(writer.chunks),
            },
        )
        return


class _TokenExpired(Exception):
    """Internal signal: the NextToken chain died and the window must restart."""


def _iter_events(client: Any, window: Window) -> Iterator[tuple[dict[str, Any], str | None]]:
    """Yield unwrapped trail records for one window, with the current token.

    Pagination is driven by hand rather than with a boto3 paginator so that a
    token expiry can be distinguished from a genuine error and surfaced as a
    restart rather than a failure.
    """
    logger = get_logger()
    token: str | None = None

    while True:
        kwargs: dict[str, Any] = {
            "StartTime": window.start,
            "EndTime": window.end,
            "MaxResults": PAGE_SIZE,
        }
        if token:
            kwargs["NextToken"] = token

        response = _call_with_backoff(client, kwargs)

        for item in response.get("Events", []):
            try:
                yield unwrap_event(item), token
            except EnvelopeError as exc:
                # One malformed record must not abort a window, but it must not
                # vanish either — the manifest's event count would then overstate
                # what was actually written.
                logger.error("dropping unparseable event", extra={"error": str(exc)})

        token = response.get("NextToken")
        if not token:
            return


def _call_with_backoff(client: Any, kwargs: dict[str, Any]) -> dict[str, Any]:
    """Call LookupEvents, backing off on throttling.

    Full jitter on the delay: without it, parallel regions re-synchronise after
    a throttle and immediately throttle each other again.
    """
    logger = get_logger()

    for attempt in range(MAX_THROTTLE_RETRIES):
        try:
            return client.lookup_events(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in TOKEN_CODES:
                raise _TokenExpired(str(exc)) from exc
            if code not in THROTTLE_CODES:
                raise
            delay = random.uniform(0, min(2**attempt, 60))
            logger.warning(
                "throttled by LookupEvents, backing off",
                extra={"attempt": attempt + 1, "delay_s": round(delay, 2), "code": code},
            )
            time.sleep(delay)
        except BotoCoreError:
            raise

    raise RuntimeError(
        f"LookupEvents still throttling after {MAX_THROTTLE_RETRIES} attempts. "
        "The API is limited to roughly 2 requests/second/region; reduce "
        "concurrency or collect a narrower range."
    )


def _clear_window_chunks(
    *,
    dest_client: Any,
    config: RunConfig,
    region: str,
    window: Window,
    account_id: str,
) -> None:
    """Remove chunks left by an abandoned attempt at this window."""
    logger = get_logger()
    day_prefix = dest_key(
        root_prefix=config.dest_prefix,
        engagement_id=config.engagement_id,
        account_id=account_id,
        region=region,
        day=window.start.date(),
        filename="_",
    )[:-1]
    name_prefix = lookup_object_name(account_id, region, window.start, 0).rsplit("_", 1)[0] + "_"
    full_prefix = day_prefix + name_prefix

    paginator = dest_client.get_paginator("list_objects_v2")
    stale = [
        item["Key"]
        for page in paginator.paginate(Bucket=config.dest_bucket, Prefix=full_prefix)
        for item in page.get("Contents", [])
    ]
    if not stale:
        return

    logger.warning(
        "removing chunks from an incomplete prior attempt at this window",
        extra={"region": region, "window": window.key(), "keys": stale},
    )
    for batch_start in range(0, len(stale), 1000):
        dest_client.delete_objects(
            Bucket=config.dest_bucket,
            Delete={"Objects": [{"Key": k} for k in stale[batch_start : batch_start + 1000]]},
        )


def _dry_run(config: RunConfig, windows: list[Window], manifest: ManifestBuilder) -> int:
    """Report the collection plan and its throughput ceiling."""
    total_windows = len(windows) * len(config.regions)
    span = (config.end - config.start) if config.start and config.end else None

    print(f"\nDRY RUN — mode=lookup engagement={config.engagement_id}")
    print(f"  source account  {config.source_account_id}")
    print(f"  dest            s3://{config.dest_bucket}/{config.dest_prefix}/{config.engagement_id}/")
    print(f"  range           {config.start} .. {config.end}  ({span})")
    print(f"  regions         {len(config.regions)}: {', '.join(config.regions)}")
    print(f"  window size     {config.window}")
    print(f"  windows         {len(windows)} per region, {total_windows} total")
    print()
    print("  Fidelity: management events ONLY. No data events, no Insights, 90-day max.")
    print("  Throughput ceiling: ~100 events/sec/region. Event volume is not known")
    print("  until the pull runs, so no ETA can be given here.")
    print("\nNothing was written.\n")

    manifest.add_note(f"dry run: {total_windows} windows planned across {len(config.regions)} regions")
    return 0
