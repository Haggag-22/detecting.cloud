"""Resolve a CloudTrail trail name to its S3 delivery location."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .config import boto_config, resolve_regions
from .errors import ConfigError, CredentialError


@dataclass(frozen=True, slots=True)
class TrailS3Source:
    """S3 location where a trail delivers log objects."""

    trail_name: str
    bucket: str
    prefix: str
    home_region: str
    is_multiregion: bool
    is_organization_trail: bool
    trail_arn: str


def resolve_trail_s3_source(
    session: boto3.Session,
    trail_name: str,
    *,
    home_region: str | None = None,
) -> TrailS3Source:
    """Look up ``trail_name`` via ``cloudtrail:DescribeTrails`` and return its S3 target.

    Organization trails must be described from the trail's home region. Pass
    ``home_region`` when auto-detection fails, or when the default session region
    is not where the trail was created.
    """
    name = trail_name.strip()
    if not name:
        raise ConfigError("--trail-name must not be empty")

    trail = _find_trail(session, name, home_region=home_region)
    bucket = (trail.get("S3BucketName") or "").strip()
    if not bucket:
        raise ConfigError(
            f"trail {name!r} has no S3BucketName in CloudTrail (is logging to S3 enabled?)"
        )

    prefix = (trail.get("S3KeyPrefix") or "").strip().strip("/")
    if prefix:
        prefix = prefix + "/"

    home = trail.get("HomeRegion") or home_region or session.region_name or "us-east-1"

    return TrailS3Source(
        trail_name=name,
        bucket=bucket,
        prefix=prefix,
        home_region=home,
        is_multiregion=bool(trail.get("IsMultiRegionTrail")),
        is_organization_trail=bool(trail.get("IsOrganizationTrail")),
        trail_arn=str(trail.get("TrailARN") or ""),
    )


def resolve_organization_id(session: boto3.Session) -> str | None:
    """Return the caller's Organizations id when the API is available."""
    try:
        client = session.client("organizations", config=boto_config())
        response = client.describe_organization()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in {"AWSOrganizationsNotInUseException", "AccessDeniedException"}:
            return None
        raise CredentialError(
            f"could not read organization id for an organization trail ({exc}). "
            "Pass --org-id explicitly."
        ) from exc
    except BotoCoreError as exc:
        raise CredentialError(f"could not read organization id: {exc}") from exc

    org = response.get("Organization") or {}
    org_id = (org.get("Id") or "").strip()
    return org_id or None


def _find_trail(
    session: boto3.Session,
    trail_name: str,
    *,
    home_region: str | None,
) -> dict[str, Any]:
    regions_to_try: list[str] = []
    if home_region:
        regions_to_try.append(home_region.strip())
    default = session.region_name or "us-east-1"
    if default not in regions_to_try:
        regions_to_try.append(default)
    if "us-east-1" not in regions_to_try:
        regions_to_try.append("us-east-1")

    for region in regions_to_try:
        trail = _describe_trail(session, region, trail_name)
        if trail:
            return trail

    # Last resort: every enabled region (org trails often require home region).
    for region in resolve_regions(session, []):
        if region in regions_to_try:
            continue
        trail = _describe_trail(session, region, trail_name)
        if trail:
            return trail

    hint = (
        f" Pass --trail-region if this trail's home region is not "
        f"{default!r}."
        if not home_region
        else ""
    )
    raise ConfigError(
        f"no CloudTrail trail named {trail_name!r} in this account "
        f"(checked multiple regions via cloudtrail:DescribeTrails).{hint} "
        "Requires cloudtrail:DescribeTrails on the source credentials, or "
        "use --bucket instead."
    )


def _describe_trail(session: boto3.Session, region: str, trail_name: str) -> dict[str, Any] | None:
    try:
        client = session.client("cloudtrail", region_name=region, config=boto_config())
        response = client.describe_trails(trailNameList=[trail_name])
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in {"TrailNotFoundException", "InvalidTrailNameException"}:
            return None
        raise ConfigError(
            f"DescribeTrails failed in {region} for trail {trail_name!r}: {exc}"
        ) from exc
    except BotoCoreError as exc:
        raise ConfigError(f"DescribeTrails failed in {region}: {exc}") from exc

    for trail in response.get("trailList") or []:
        if trail.get("Name") == trail_name:
            return trail
    return None
