"""Object naming and key layout.

Two naming concerns live here:

1. Output filenames for Mode B, which must match CloudTrail's native convention
   so an analyst reading an S3 listing cannot tell (and does not need to care)
   whether a file came from a trail or from the LookupEvents API.
2. The destination key layout, which enforces per-engagement isolation.

Both are pure functions so they can be tested without AWS.
"""

from __future__ import annotations

import re
from datetime import date, datetime, timezone

from .errors import ConfigError

# CloudTrail native object names look like:
#   123456789012_CloudTrail_us-east-1_20240115T0305Z_a1B2c3D4e5F6g7H8.json.gz
# Mode B reuses the same shape, substituting a zero-padded chunk counter for the
# random suffix so ordering within a window is lexicographically obvious.
ACCOUNT_RE = re.compile(r"^\d{12}$")
REGION_RE = re.compile(r"^[a-z]{2}(-gov|-iso[a-z]?)?-[a-z]+-\d$")
ENGAGEMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

GZIP_SUFFIX = ".json.gz"

# Trail buckets carry management/data events under CloudTrail/ and Insights
# events under a sibling CloudTrail-Insight/ prefix. Collecting only the former
# would quietly drop Insights from an evidence set that claims full fidelity.
TRAIL_LOG_TYPES = ("CloudTrail", "CloudTrail-Insight")


def validate_account_id(account_id: str) -> str:
    """Return the account id, or raise if it is not 12 digits."""
    if not ACCOUNT_RE.match(account_id):
        raise ConfigError(
            f"account id must be exactly 12 digits, got {account_id!r}. "
            "A wrong account id silently produces an empty collection."
        )
    return account_id


def validate_region(region: str) -> str:
    """Return the region, or raise if it does not look like an AWS region."""
    if not REGION_RE.match(region):
        raise ConfigError(
            f"{region!r} does not look like an AWS region name (expected e.g. "
            "'us-east-1', 'eu-west-2', 'us-gov-west-1')"
        )
    return region


def validate_engagement_id(engagement_id: str) -> str:
    """Return the engagement id, or raise if it is unsafe as a key segment.

    Rejecting slashes and traversal here is what keeps one client's evidence
    from landing under another client's prefix.
    """
    if not ENGAGEMENT_RE.match(engagement_id):
        raise ConfigError(
            f"engagement id {engagement_id!r} is invalid: use 1-64 characters of "
            "[A-Za-z0-9._-] starting with alphanumeric. Slashes and '..' are "
            "rejected because they would break per-engagement prefix isolation."
        )
    return engagement_id


def lookup_object_name(
    account_id: str,
    region: str,
    window_start: datetime,
    chunk: int,
) -> str:
    """Build a Mode B output filename.

    Format: ``<12-digit-account>_CloudTrail_<region>_<YYYYMMDD>T<HHMM>Z_<chunk>.json.gz``

    ``window_start`` must be timezone-aware; it is normalised to UTC because the
    ``Z`` in the filename is a factual claim about the timestamp.
    """
    validate_account_id(account_id)
    validate_region(region)
    if chunk < 0:
        raise ConfigError(f"chunk index must be non-negative, got {chunk}")
    stamp = _utc_stamp(window_start)
    return f"{account_id}_CloudTrail_{region}_{stamp}_{chunk:05d}{GZIP_SUFFIX}"


def _utc_stamp(when: datetime) -> str:
    """Render a tz-aware datetime as ``YYYYMMDDTHHMMZ`` in UTC."""
    if when.tzinfo is None:
        raise ConfigError(
            f"refusing to format naive datetime {when!r}: an evidence filename "
            "must not encode an ambiguous local time"
        )
    return when.astimezone(timezone.utc).strftime("%Y%m%dT%H%MZ")


def dest_key(
    *,
    root_prefix: str,
    engagement_id: str,
    account_id: str,
    region: str,
    day: date,
    filename: str,
) -> str:
    """Build a destination key.

    Layout: ``<root>/<engagement-id>/<account-id>/<region>/<YYYY-MM-DD>/<filename>``
    with ``<root>`` defaulting to ``aws``.
    """
    validate_engagement_id(engagement_id)
    validate_account_id(account_id)
    validate_region(region)
    if not filename or "/" in filename:
        raise ConfigError(f"filename {filename!r} must be a single path segment")
    root = root_prefix.strip("/")
    return f"{root}/{engagement_id}/{account_id}/{region}/{day.isoformat()}/{filename}"


def manifest_key(*, root_prefix: str, engagement_id: str, run_id: str) -> str:
    """Key for the run manifest, stored beside the engagement's data."""
    validate_engagement_id(engagement_id)
    root = root_prefix.strip("/")
    return f"{root}/{engagement_id}/_manifests/manifest_{run_id}.json"


def trail_day_prefix(
    *,
    source_prefix: str,
    account_id: str,
    region: str,
    day: date,
    org_id: str | None = None,
    log_type: str = "CloudTrail",
) -> str:
    """Build the CloudTrail source prefix for one account/region/day.

    Native layout is ``AWSLogs/<account>/CloudTrail/<region>/<YYYY>/<MM>/<DD>/``.
    Organization trails insert the org id: ``AWSLogs/<org>/<account>/CloudTrail/...``.
    Insights events live under a sibling ``CloudTrail-Insight`` prefix.

    Enumerating one day at a time is what keeps us from listing an entire
    multi-terabyte bucket to find a two-week window.
    """
    validate_account_id(account_id)
    validate_region(region)
    if log_type not in TRAIL_LOG_TYPES:
        raise ConfigError(f"unknown log type {log_type!r}; expected one of {TRAIL_LOG_TYPES}")
    parts = [source_prefix.strip("/")] if source_prefix.strip("/") else []
    parts.append("AWSLogs")
    if org_id:
        parts.append(org_id.strip("/"))
    parts.extend(
        [
            account_id,
            log_type,
            region,
            f"{day.year:04d}",
            f"{day.month:02d}",
            f"{day.day:02d}",
        ]
    )
    return "/".join(parts) + "/"


def day_from_trail_key(key: str) -> date | None:
    """Recover the log date from a native CloudTrail key.

    Returns ``None`` when the key does not carry a parseable date, which lets the
    caller fall back to the object's own timestamp rather than guessing.
    """
    match = re.search(r"/CloudTrail(?:-Insight)?/[^/]+/(\d{4})/(\d{2})/(\d{2})/", key)
    if not match:
        return None
    year, month, day = (int(group) for group in match.groups())
    try:
        return date(year, month, day)
    except ValueError:
        return None
