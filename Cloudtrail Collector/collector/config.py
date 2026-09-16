"""Run configuration and AWS session construction.

The source account (the client's) and the destination account (ours) are
normally different credential contexts, so sessions are built separately and
each is identity-checked at startup. Discovering at hour nine of a copy that
the destination credentials were wrong is not an acceptable failure mode.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, ProfileNotFound

from .errors import ConfigError, CredentialError

# Objects at or above this size cannot be copied with a single CopyObject call.
MULTIPART_COPY_THRESHOLD = 5 * 1024**3  # 5 GiB, the S3 CopyObject hard limit
DEFAULT_COPY_PART_SIZE = 512 * 1024**2  # 512 MiB parts keep part counts sane at TB scale
DEFAULT_UPLOAD_PART_SIZE = 16 * 1024**2  # 16 MiB parts for streamed Mode B output


@dataclass(slots=True)
class RunConfig:
    """Everything one invocation needs, already validated."""

    mode: str
    engagement_id: str
    run_id: str

    dest_bucket: str | None
    dest_prefix: str
    dest_region: str | None
    create_dest_bucket: bool

    source_bucket: str | None
    source_prefix: str
    source_account_id: str | None
    org_id: str | None

    regions: list[str]
    start: datetime | None
    end: datetime | None
    window: timedelta

    concurrency: int
    chunk_size_bytes: int
    in_place: bool
    dry_run: bool
    resume: bool

    state_file: Path
    log_file: Path
    manifest_out: Path | None
    source_profile: str | None
    dest_profile: str | None
    verbose: bool

    extra: dict[str, Any] = field(default_factory=dict)

    def state_identity(self) -> dict[str, Any]:
        """Fields that must match for a --resume to be legitimate."""
        return {
            "mode": self.mode,
            "engagement_id": self.engagement_id,
            "source_bucket": self.source_bucket,
            "dest_bucket": self.dest_bucket,
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None,
        }


def boto_config(*, max_attempts: int = 10, pool_size: int = 32) -> BotoConfig:
    """Shared botocore config.

    ``adaptive`` retries because at high concurrency against CloudTrail and S3
    the binding constraint is service-side throttling, and the adaptive mode
    backs off on the client side instead of hammering through the retry budget.
    """
    return BotoConfig(
        retries={"max_attempts": max_attempts, "mode": "adaptive"},
        max_pool_connections=pool_size,
        user_agent_extra="ventra-dfir",
    )


def build_session(profile: str | None, region: str | None = None) -> boto3.Session:
    """Build a boto3 session from a profile name, or the default chain.

    Raw access keys are deliberately not accepted anywhere in this tool: as CLI
    arguments they land in shell history and in ``ps`` output. Environment
    variables and shared credential files are the supported paths, and both are
    handled by the default chain below.
    """
    try:
        if profile:
            return boto3.Session(profile_name=profile, region_name=region)
        return boto3.Session(region_name=region)
    except ProfileNotFound as exc:
        available = ", ".join(boto3.Session().available_profiles) or "<none>"
        raise CredentialError(
            f"AWS profile {profile!r} not found. Available profiles: {available}"
        ) from exc


def verify_identity(session: boto3.Session, label: str) -> dict[str, str]:
    """Resolve and return the caller identity, failing loudly if we cannot.

    Called for both sessions before any work starts.
    """
    try:
        identity = session.client("sts", config=boto_config()).get_caller_identity()
    except NoCredentialsError as exc:
        profile_flag = "--profile" if label == "source" else f"--{label}-profile"
        raise CredentialError(
            f"no credentials resolved for the {label} session. Set a profile with "
            f"{profile_flag}, or configure the environment (AWS_PROFILE, "
            f"AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, SSO, or an instance role)."
        ) from exc
    except (ClientError, BotoCoreError) as exc:
        raise CredentialError(
            f"could not verify the {label} identity: {exc}"
        ) from exc

    return {
        "account": identity["Account"],
        "arn": identity["Arn"],
        "user_id": identity["UserId"],
    }


def resolve_regions(session: boto3.Session, requested: list[str]) -> list[str]:
    """Return the regions to collect from.

    An explicit list wins. Otherwise every region enabled for the account is
    used, because a region the analyst forgot to name is exactly where the
    interesting activity tends to be.
    """
    if requested:
        return sorted(set(requested))

    region = session.region_name or os.environ.get("AWS_REGION") or "us-east-1"
    try:
        client = session.client("ec2", region_name=region, config=boto_config())
        response = client.describe_regions(AllRegions=False)
    except (ClientError, BotoCoreError) as exc:
        raise ConfigError(
            f"could not enumerate enabled regions via ec2:DescribeRegions ({exc}). "
            "Pass --regions explicitly, or grant ec2:DescribeRegions on the source "
            "account. Guessing a region list would silently under-collect."
        ) from exc

    return sorted(r["RegionName"] for r in response["Regions"])


def ensure_dest_bucket(
    session: boto3.Session,
    bucket: str,
    region: str | None,
    *,
    create: bool,
    dry_run: bool,
) -> None:
    """Confirm the destination bucket is usable, creating it if asked.

    ``--create-dest-bucket`` provisions an evidence-grade bucket: versioned,
    encrypted, and with public access blocked. It never touches an existing
    bucket's configuration.
    """
    client = session.client("s3", config=boto_config())
    region = region or session.region_name or "us-east-1"

    try:
        client.head_bucket(Bucket=bucket)
        exists = True
    except ClientError as exc:
        status = int(exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0))
        if status == 404:
            exists = False
        elif status == 403:
            raise CredentialError(
                f"destination bucket {bucket!r} exists but the destination "
                f"credentials cannot access it (HTTP 403). Check --dest-profile and "
                f"the bucket policy."
            ) from exc
        else:
            raise CredentialError(f"could not check destination bucket {bucket!r}: {exc}") from exc

    if exists:
        return

    if not create:
        raise ConfigError(
            f"destination bucket {bucket!r} does not exist. Pass --create-dest-bucket "
            f"to create it (versioned, encrypted, public access blocked), or point "
            f"--dest-bucket at an existing bucket."
        )

    if dry_run:
        return

    kwargs: dict[str, Any] = {"Bucket": bucket}
    # us-east-1 is the one region that must NOT be given a location constraint.
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}

    client.create_bucket(**kwargs)
    client.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    client.put_bucket_versioning(
        Bucket=bucket,
        VersioningConfiguration={"Status": "Enabled"},
    )
    client.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
                    "BucketKeyEnabled": True,
                }
            ]
        },
    )
