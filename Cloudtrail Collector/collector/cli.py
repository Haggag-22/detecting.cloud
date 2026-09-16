"""Command-line interface.

Exit codes are meaningful because this tool gets driven from engagement
runbooks and CI:

* 0 — collection completed with no failures
* 1 — configuration, credential, or startup error; nothing was collected
* 2 — collection ran but some objects or windows failed; the manifest lists them
"""

from __future__ import annotations

import argparse
import io
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from botocore.exceptions import BotoCoreError, ClientError

from . import __version__
from .config import (
    RunConfig,
    boto_config,
    build_session,
    ensure_dest_bucket,
    resolve_regions,
    verify_identity,
)
from .errors import CollectorError, ConfigError
from .logging_setup import get_logger, setup_logging
from .manifest import ManifestBuilder, sha256_stream
from .naming import manifest_key, validate_account_id, validate_engagement_id
from .modes import lookup as lookup_mode
from .modes import trail as trail_mode
from .trail_discovery import resolve_organization_id, resolve_trail_s3_source

EXIT_OK = 0
EXIT_CONFIG = 1
EXIT_PARTIAL = 2

MODE_HELP = """\
--mode is required and has no default, because the modes produce evidence sets
with materially different fidelity and choosing wrong is not recoverable after
the fact:

  --mode trail
      Copy objects from an existing CloudTrail trail S3 bucket into the
      evidence bucket (server-side). Full fidelity: management events, data
      events, and Insights. PREFER THIS whenever a trail exists.

  --mode s3
      Same as trail — collect CloudTrail log objects from S3 (alias for trail).

  --mode lookup
      CloudTrail LookupEvents API. MANAGEMENT EVENTS ONLY — no data events, no
      Insights. Maximum 90 days. Backfill when no trail exists; not a substitute.
"""

LOOKUP_BANNER = """
================================================================================
  MODE: lookup (CloudTrail LookupEvents API)

  LIMITATIONS OF THIS EVIDENCE SET -- read before relying on it:

    * MANAGEMENT EVENTS ONLY. S3 object-level access, Lambda invocations, and
      DynamoDB item operations are NOT returned by this API. Their absence is a
      collection artifact, NOT evidence that none occurred.
    * INSIGHTS EVENTS are not returned.
    * 90-DAY MAXIMUM HISTORY. Anything older cannot be retrieved this way.
    * THROUGHPUT ~100 events/sec/region. A high-volume account may take days.

  These limitations are recorded in the run manifest so an analyst reading the
  data later can tell a real gap from a collection artifact.
================================================================================
"""


def normalize_collect_mode(mode: str) -> str:
    """Map CLI mode names to internal runner modes."""
    if mode in ("trail", "s3"):
        return "trail"
    if mode == "lookup":
        return "lookup"
    raise ConfigError(f"unknown mode {mode!r}; use trail, s3, or lookup")


class _Parser(argparse.ArgumentParser):
    """Argument parser that explains the mode choice when it is omitted."""

    def error(self, message: str):
        if "--mode" in message:
            sys.stderr.write(f"\nerror: {message}\n\n{MODE_HELP}\n")
            sys.exit(EXIT_CONFIG)
        super().error(message)


def add_cloudtrail_collect_arguments(parser: argparse.ArgumentParser) -> None:
    """Flags shared by ``ventra collect cloudtrail`` and the legacy CLI."""
    parser.add_argument(
        "--mode",
        required=True,
        choices=("trail", "s3", "lookup"),
        help="collection mode (required) — see notes below",
    )
    parser.add_argument(
        "--engagement-id",
        required=True,
        help="engagement identifier; top-level prefix isolating this client's data",
    )

    dest = parser.add_argument_group("destination (evidence bucket)")
    dest.add_argument("--dest-bucket", help="evidence bucket name")
    dest.add_argument(
        "--create-dest-bucket",
        action="store_true",
        help="create the destination bucket if missing (versioned, encrypted)",
    )
    dest.add_argument("--dest-region", help="region for the destination bucket")
    dest.add_argument(
        "--dest-prefix",
        default="aws",
        help="root prefix inside the evidence bucket (default: aws)",
    )

    trail_s3 = parser.add_argument_group("trail logs (S3 read)")
    trail_s3.add_argument("--bucket", help="S3 bucket with CloudTrail logs (mode trail/s3)")
    trail_s3.add_argument(
        "--trail-name",
        help="mode trail/s3: resolve --bucket and --prefix via cloudtrail:DescribeTrails "
        "(alternative to --bucket)",
    )
    trail_s3.add_argument(
        "--trail-region",
        help="home region for --trail-name when DescribeTrails does not find the trail "
        "in the default session region",
    )
    trail_s3.add_argument(
        "--prefix",
        default="",
        help="key prefix before AWSLogs/ in the read bucket (default: none; set from "
        "trail S3KeyPrefix when using --trail-name unless overridden)",
    )
    trail_s3.add_argument(
        "--account-id",
        help="12-digit source account id; defaults to the source credentials' account",
    )
    trail_s3.add_argument(
        "--org-id",
        help="organization id, for org trails keyed AWSLogs/<org>/<account>/CloudTrail/...",
    )
    trail_s3.add_argument(
        "--regions",
        default="",
        help="comma-separated regions; default is every region enabled on the account",
    )

    timing = parser.add_argument_group("time range")
    timing.add_argument("--start", help="UTC start, ISO 8601 (e.g. 2026-08-01)")
    timing.add_argument("--end", help="UTC end, ISO 8601; defaults to now")
    timing.add_argument(
        "--last-days",
        type=int,
        help="convenience alternative to --start: collect the last N days",
    )
    timing.add_argument(
        "--window-hours",
        type=float,
        default=6.0,
        help="mode lookup: hours per pagination window (default: 6)",
    )

    behaviour = parser.add_argument_group("behaviour")
    behaviour.add_argument(
        "--concurrency", type=int, default=16, help="parallel copies in trail/s3 mode (default: 16)"
    )
    behaviour.add_argument(
        "--chunk-size-mb",
        type=int,
        default=256,
        help="mode lookup: uncompressed MB per output object (default: 256)",
    )
    behaviour.add_argument(
        "--in-place",
        action="store_true",
        help="trail/s3: do not copy; manifest + point ingest at source bucket",
    )
    behaviour.add_argument(
        "--dry-run",
        action="store_true",
        help="enumerate and report totals without writing anything",
    )
    behaviour.add_argument(
        "--resume", action="store_true", help="continue from an existing state file"
    )

    creds = parser.add_argument_group("credentials")
    creds.add_argument("--profile", help="AWS profile for the source account")
    creds.add_argument("--dest-profile", help="AWS profile for the evidence bucket account")

    output = parser.add_argument_group("output")
    output.add_argument("--state-file", type=Path, help="resume state (default: ./state/<engagement>-<mode>.ndjson)")
    output.add_argument("--log-file", type=Path, help="structured JSON log (default: ./logs/<engagement>-<run>.jsonl)")
    output.add_argument("--manifest-out", type=Path, help="also write the manifest to this local path")
    output.add_argument("-v", "--verbose", action="store_true", help="debug logging on stderr")


def build_ventra_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ventra",
        description="Ventra — cloud evidence collection for SIEM ingest.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"ventra {__version__}")

    sub = parser.add_subparsers(dest="ventra_command", required=True)

    collect = sub.add_parser(
        "collect",
        help="collect logs from a cloud source into S3 evidence layout",
    )
    collect_sub = collect.add_subparsers(dest="collect_source", required=True)

    cloudtrail = collect_sub.add_parser(
        "cloudtrail",
        help="AWS CloudTrail (trail S3 copy or LookupEvents API)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=MODE_HELP,
    )
    add_cloudtrail_collect_arguments(cloudtrail)
    return parser


def build_legacy_parser() -> argparse.ArgumentParser:
    """Flat CLI for ``cloudtrail-collector`` entry point (prefer ``ventra``)."""
    parser = _Parser(
        prog="cloudtrail-collector",
        description="Collect AWS CloudTrail logs (legacy — use: ventra collect cloudtrail).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=MODE_HELP,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    add_cloudtrail_collect_arguments(parser)
    return parser


def parse_timestamp(value: str, *, label: str) -> datetime:
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ConfigError(
            f"{label} {value!r} is not a valid ISO 8601 timestamp "
            f"(expected e.g. 2026-08-01 or 2026-08-01T13:45:00Z)"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def build_config(args: argparse.Namespace, source_account: str) -> RunConfig:
    validate_engagement_id(args.engagement_id)

    internal_mode = normalize_collect_mode(args.mode)

    account_id = args.account_id or source_account
    validate_account_id(account_id)

    end = parse_timestamp(args.end, label="--end") if args.end else datetime.now(timezone.utc)
    if args.start:
        start = parse_timestamp(args.start, label="--start")
    elif args.last_days:
        start = end - timedelta(days=args.last_days)
    else:
        raise ConfigError("one of --start or --last-days is required")

    if end <= start:
        raise ConfigError(f"--end ({end.isoformat()}) must be after --start ({start.isoformat()})")

    if internal_mode == "trail":
        if args.trail_name and args.bucket:
            raise ConfigError("use either --trail-name or --bucket, not both")
        if not args.bucket and not args.trail_name:
            raise ConfigError(
                "mode trail/s3 requires --bucket or --trail-name "
                "(DescribeTrails resolves the logging bucket)"
            )
    if internal_mode == "lookup" and args.trail_name:
        raise ConfigError("--trail-name applies to mode trail/s3 only")
    if internal_mode == "lookup" and args.in_place:
        raise ConfigError("--in-place applies to trail/s3 only")
    if not args.in_place and not args.dry_run and not args.dest_bucket:
        raise ConfigError("--dest-bucket is required unless --in-place or --dry-run is used")
    if args.concurrency < 1:
        raise ConfigError(f"--concurrency must be at least 1, got {args.concurrency}")
    if args.chunk_size_mb < 5:
        raise ConfigError(f"--chunk-size-mb must be at least 5, got {args.chunk_size_mb}")
    if args.window_hours <= 0:
        raise ConfigError(f"--window-hours must be positive, got {args.window_hours}")

    run_id = f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
    regions = [r.strip() for r in args.regions.split(",") if r.strip()]

    state_file = args.state_file or Path("state") / f"{args.engagement_id}-{internal_mode}.ndjson"
    log_file = args.log_file or Path("logs") / f"{args.engagement_id}-{run_id}.jsonl"

    return RunConfig(
        mode=internal_mode,
        engagement_id=args.engagement_id,
        run_id=run_id,
        dest_bucket=args.dest_bucket,
        dest_prefix=args.dest_prefix,
        dest_region=args.dest_region,
        create_dest_bucket=args.create_dest_bucket,
        source_bucket=args.bucket,
        source_prefix=args.prefix,
        source_account_id=account_id,
        org_id=args.org_id,
        regions=regions,
        start=start,
        end=end,
        window=timedelta(hours=args.window_hours),
        concurrency=args.concurrency,
        chunk_size_bytes=args.chunk_size_mb * 1024 * 1024,
        in_place=args.in_place,
        dry_run=args.dry_run,
        resume=args.resume,
        state_file=state_file,
        log_file=log_file,
        manifest_out=args.manifest_out,
        source_profile=args.profile,
        dest_profile=args.dest_profile,
        verbose=args.verbose,
    )


def run_collect(args: argparse.Namespace) -> int:
    try:
        source_session = build_session(args.profile, args.dest_region)
        source_identity = verify_identity(source_session, "source")
        config = build_config(args, source_identity["account"])
    except CollectorError as exc:
        sys.stderr.write(f"\nerror: {exc}\n\n")
        return EXIT_CONFIG

    logger = setup_logging(config.log_file, config.verbose)
    logger.info(
        "run starting",
        extra={
            "run_id": config.run_id,
            "mode": config.mode,
            "cli_mode": args.mode,
            "engagement_id": config.engagement_id,
            "collector_version": __version__,
            "source_identity": source_identity,
        },
    )

    if config.mode == "lookup":
        print(LOOKUP_BANNER)

    try:
        dest_session = build_session(args.dest_profile, config.dest_region)
        dest_identity = (
            verify_identity(dest_session, "dest")
            if not (config.dry_run or config.in_place)
            else None
        )

        if config.mode == "trail" and args.trail_name:
            discovered = resolve_trail_s3_source(
                source_session,
                args.trail_name,
                home_region=args.trail_region,
            )
            config.source_bucket = discovered.bucket
            if not args.prefix:
                config.source_prefix = discovered.prefix
            if discovered.is_organization_trail and not config.org_id:
                org_id = resolve_organization_id(source_session)
                if org_id:
                    config.org_id = org_id
                else:
                    raise ConfigError(
                        f"trail {discovered.trail_name!r} is an organization trail; "
                        "pass --org-id (o-xxxxxxxxxx) or grant organizations:DescribeOrganization "
                        "on the source credentials."
                    )
            logger.info(
                "trail S3 location resolved",
                extra={
                    "trail_name": discovered.trail_name,
                    "source_bucket": discovered.bucket,
                    "source_prefix": config.source_prefix,
                    "home_region": discovered.home_region,
                    "is_multiregion": discovered.is_multiregion,
                },
            )

        config.regions = resolve_regions(source_session, config.regions)
        logger.info("regions resolved", extra={"regions": config.regions})

        if config.dest_bucket and not config.in_place:
            ensure_dest_bucket(
                dest_session,
                config.dest_bucket,
                config.dest_region,
                create=config.create_dest_bucket,
                dry_run=config.dry_run,
            )
    except CollectorError as exc:
        logger.error("startup failed", extra={"error": str(exc)})
        sys.stderr.write(f"\nerror: {exc}\n\n")
        return EXIT_CONFIG

    manifest = ManifestBuilder(
        run_id=config.run_id,
        mode=config.mode,
        engagement_id=config.engagement_id,
        dest_bucket=config.dest_bucket or "",
        dest_prefix=config.dest_prefix,
        requested_start=config.start.isoformat() if config.start else None,
        requested_end=config.end.isoformat() if config.end else None,
        source_bucket=config.source_bucket,
        source_account_id=config.source_account_id,
        regions=config.regions,
        in_place=config.in_place,
        dry_run=config.dry_run,
    )
    manifest.add_note(f"source identity: {source_identity['arn']}")
    if args.trail_name and config.source_bucket:
        manifest.add_note(
            f"source resolved from trail {args.trail_name!r}: "
            f"s3://{config.source_bucket}/{config.source_prefix}"
        )
    if dest_identity:
        manifest.add_note(f"destination identity: {dest_identity['arn']}")
    if args.mode == "s3" and config.mode == "trail":
        manifest.add_note("CLI mode s3 (alias for trail S3 object collection)")

    runner = trail_mode.run if config.mode == "trail" else lookup_mode.run

    try:
        failures = runner(config, source_session, dest_session, manifest)
    except KeyboardInterrupt:
        logger.error("interrupted by operator")
        manifest.add_note(
            "RUN INTERRUPTED by operator. This collection is INCOMPLETE. "
            "Re-run with --resume to continue."
        )
        _finalise(config, manifest, dest_session, incomplete=True)
        sys.stderr.write("\ninterrupted — state saved, re-run with --resume\n\n")
        return EXIT_PARTIAL
    except (CollectorError, ClientError, BotoCoreError) as exc:
        logger.exception("run failed")
        manifest.add_note(f"RUN ABORTED: {type(exc).__name__}: {exc}")
        _finalise(config, manifest, dest_session, incomplete=True)
        sys.stderr.write(f"\nerror: {exc}\n\n")
        return EXIT_PARTIAL

    _finalise(config, manifest, dest_session, incomplete=failures > 0)
    _print_summary(config, manifest, failures)
    return EXIT_PARTIAL if failures else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_ventra_parser().parse_args(argv)
    if args.ventra_command != "collect" or args.collect_source != "cloudtrail":
        sys.stderr.write("Only 'ventra collect cloudtrail' is implemented today.\n")
        return EXIT_CONFIG
    return run_collect(args)


def legacy_main(argv: list[str] | None = None) -> int:
    args = build_legacy_parser().parse_args(argv)
    return run_collect(args)


def _finalise(config: RunConfig, manifest: ManifestBuilder, dest_session, incomplete: bool) -> None:
    logger = get_logger()
    payload = manifest.to_json()
    manifest_digest = sha256_stream(io.BytesIO(payload))

    local = config.manifest_out or Path("manifests") / f"manifest_{config.run_id}.json"
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_bytes(payload)
    logger.info(
        "manifest written",
        extra={"path": str(local), "sha256": manifest_digest, "incomplete": incomplete},
    )
    print(f"\nmanifest: {local}")
    print(f"  sha256: {manifest_digest}")

    if config.dry_run or not config.dest_bucket:
        return

    key = manifest_key(
        root_prefix=config.dest_prefix,
        engagement_id=config.engagement_id,
        run_id=config.run_id,
    )
    try:
        dest_session.client("s3", config=boto_config()).put_object(
            Bucket=config.dest_bucket,
            Key=key,
            Body=payload,
            ContentType="application/json",
        )
        logger.info("manifest uploaded", extra={"key": key})
        print(f"manifest: s3://{config.dest_bucket}/{key}")
    except (ClientError, BotoCoreError) as exc:
        logger.error("manifest upload FAILED", extra={"key": key, "error": str(exc)})
        sys.stderr.write(
            f"\nWARNING: manifest could not be uploaded to s3://{config.dest_bucket}/{key}: {exc}\n"
            f"         The local copy at {local} is currently the only manifest.\n\n"
        )


def _print_summary(config: RunConfig, manifest: ManifestBuilder, failures: int) -> None:
    doc = manifest.build()
    totals = doc["totals"]

    print("\n" + "=" * 72)
    print(f"  {'COLLECTION COMPLETE' if not failures else 'COLLECTION INCOMPLETE'}")
    print("=" * 72)
    print(f"  mode              {config.mode}")
    print(f"  engagement        {config.engagement_id}")
    print(f"  run id            {config.run_id}")
    print(f"  objects           {totals['objects_collected']:,}")
    print(f"  bytes             {totals['bytes_collected'] / 1024**3:,.2f} GiB")
    if totals["events_collected"]:
        print(f"  events            {totals['events_collected']:,}")
    if failures:
        print(f"  objects FAILED    {totals['objects_failed']:,}")
        print(f"  windows FAILED    {totals['windows_failed']:,}")
        print("\n  This evidence set is INCOMPLETE. Failures are listed in the manifest.")
        print("  Re-run with --resume to retry only what is missing.")
    print("=" * 72 + "\n")


if __name__ == "__main__":
    sys.exit(main())
