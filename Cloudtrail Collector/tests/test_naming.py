"""Filename and key layout.

Two silent failure modes are covered here: output filenames that drift from
CloudTrail's convention (downstream tooling stops recognising them), and key
layouts that could place one client's evidence under another's prefix.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest

from collector.errors import ConfigError
from collector.naming import (
    day_from_trail_key,
    dest_key,
    lookup_object_name,
    manifest_key,
    trail_day_prefix,
    validate_account_id,
    validate_engagement_id,
    validate_region,
)

ACCOUNT = "123456789012"
WINDOW_START = datetime(2026, 8, 14, 6, 0, tzinfo=timezone.utc)


def test_lookup_name_matches_cloudtrail_convention():
    assert (
        lookup_object_name(ACCOUNT, "us-east-1", WINDOW_START, 0)
        == "123456789012_CloudTrail_us-east-1_20260814T0600Z_00000.json.gz"
    )


def test_chunk_index_is_zero_padded_for_lexicographic_order():
    """S3 listings sort lexicographically; unpadded indices would order 10 before 2."""
    names = [lookup_object_name(ACCOUNT, "us-east-1", WINDOW_START, i) for i in (2, 10, 100)]
    assert names == sorted(names)


def test_non_utc_input_is_normalised_to_utc():
    """The Z in the filename is a factual claim and must be true."""
    tokyo = timezone(timedelta(hours=9))
    same_instant = WINDOW_START.astimezone(tokyo)
    assert lookup_object_name(ACCOUNT, "us-east-1", same_instant, 0) == lookup_object_name(
        ACCOUNT, "us-east-1", WINDOW_START, 0
    )


def test_naive_datetime_rejected():
    with pytest.raises(ConfigError, match="naive datetime"):
        lookup_object_name(ACCOUNT, "us-east-1", datetime(2026, 8, 14, 6, 0), 0)


@pytest.mark.parametrize("bad", ["12345678901", "1234567890123", "12345678901a", ""])
def test_bad_account_id_rejected(bad):
    with pytest.raises(ConfigError, match="12 digits"):
        validate_account_id(bad)


@pytest.mark.parametrize("region", ["us-east-1", "eu-west-2", "ap-southeast-4", "us-gov-west-1"])
def test_valid_regions_accepted(region):
    assert validate_region(region) == region


@pytest.mark.parametrize("bad", ["useast1", "US-EAST-1", "us-east", "notaregion"])
def test_bad_regions_rejected(bad):
    with pytest.raises(ConfigError):
        validate_region(bad)


def test_dest_key_layout():
    assert (
        dest_key(
            root_prefix="aws",
            engagement_id="IR-2026-0142",
            account_id=ACCOUNT,
            region="us-east-1",
            day=date(2026, 8, 14),
            filename="file.json.gz",
        )
        == "aws/IR-2026-0142/123456789012/us-east-1/2026-08-14/file.json.gz"
    )


def test_root_prefix_slashes_normalised():
    assert dest_key(
        root_prefix="/aws/",
        engagement_id="e1",
        account_id=ACCOUNT,
        region="us-east-1",
        day=date(2026, 8, 14),
        filename="f.gz",
    ).startswith("aws/e1/")


@pytest.mark.parametrize(
    "bad",
    ["../other-client", "a/b", "IR 2026", "", "-leading-dash", "x" * 65],
)
def test_engagement_ids_that_could_cross_client_boundaries_rejected(bad):
    """Traversal or slashes in an engagement id would break prefix isolation."""
    with pytest.raises(ConfigError):
        validate_engagement_id(bad)


@pytest.mark.parametrize("good", ["IR-2026-0142", "acme.corp_01", "a", "A1"])
def test_reasonable_engagement_ids_accepted(good):
    assert validate_engagement_id(good) == good


def test_filename_with_separator_rejected():
    with pytest.raises(ConfigError, match="single path segment"):
        dest_key(
            root_prefix="aws",
            engagement_id="e1",
            account_id=ACCOUNT,
            region="us-east-1",
            day=date(2026, 8, 14),
            filename="nested/file.gz",
        )


def test_trail_day_prefix_native_layout():
    assert (
        trail_day_prefix(
            source_prefix="",
            account_id=ACCOUNT,
            region="us-east-1",
            day=date(2026, 8, 4),
        )
        == "AWSLogs/123456789012/CloudTrail/us-east-1/2026/08/04/"
    )


def test_trail_day_prefix_zero_pads_month_and_day():
    """An unpadded 2026/8/4 prefix matches nothing and silently collects zero objects."""
    prefix = trail_day_prefix(
        source_prefix="", account_id=ACCOUNT, region="us-east-1", day=date(2026, 8, 4)
    )
    assert "/2026/08/04/" in prefix


def test_trail_day_prefix_org_trail():
    assert trail_day_prefix(
        source_prefix="",
        account_id=ACCOUNT,
        region="us-east-1",
        day=date(2026, 8, 4),
        org_id="o-abc123",
    ) == "AWSLogs/o-abc123/123456789012/CloudTrail/us-east-1/2026/08/04/"


def test_trail_day_prefix_with_source_prefix():
    assert trail_day_prefix(
        source_prefix="logs/prod/",
        account_id=ACCOUNT,
        region="us-east-1",
        day=date(2026, 8, 4),
    ).startswith("logs/prod/AWSLogs/")


def test_trail_day_prefix_insights():
    assert "/CloudTrail-Insight/" in trail_day_prefix(
        source_prefix="",
        account_id=ACCOUNT,
        region="us-east-1",
        day=date(2026, 8, 4),
        log_type="CloudTrail-Insight",
    )


def test_unknown_log_type_rejected():
    with pytest.raises(ConfigError, match="unknown log type"):
        trail_day_prefix(
            source_prefix="",
            account_id=ACCOUNT,
            region="us-east-1",
            day=date(2026, 8, 4),
            log_type="CloudTrail-Nonsense",
        )


def test_day_recovered_from_trail_key():
    key = (
        "AWSLogs/123456789012/CloudTrail/us-east-1/2026/08/04/"
        "123456789012_CloudTrail_us-east-1_20260804T0305Z_abc.json.gz"
    )
    assert day_from_trail_key(key) == date(2026, 8, 4)


def test_day_recovered_from_insight_key():
    key = "AWSLogs/123456789012/CloudTrail-Insight/eu-west-1/2026/12/31/x.json.gz"
    assert day_from_trail_key(key) == date(2026, 12, 31)


def test_day_from_unparseable_key_is_none():
    """None lets the caller fall back rather than guess a wrong date."""
    assert day_from_trail_key("some/other/path/file.json.gz") is None


def test_invalid_calendar_date_in_key_is_none():
    assert day_from_trail_key("AWSLogs/1/CloudTrail/us-east-1/2026/02/31/x.gz") is None


def test_manifest_key_layout():
    key = manifest_key(root_prefix="aws", engagement_id="IR-1", run_id="20260814T090000Z-abcd1234")
    assert key == "aws/IR-1/_manifests/manifest_20260814T090000Z-abcd1234.json"


def test_manifest_is_not_picked_up_by_the_ingest_notification_filter():
    """The manifest sits inside the notified prefix, so the suffix filter is
    what keeps Logstash from trying to parse it as CloudTrail. Terraform filters
    on '.json.gz'; a manifest must not end with that."""
    key = manifest_key(root_prefix="aws", engagement_id="IR-1", run_id="run-1")
    assert key.startswith("aws/IR-1/")
    assert not key.endswith(".json.gz")


def test_data_objects_do_match_the_ingest_notification_filter():
    data_key = dest_key(
        root_prefix="aws",
        engagement_id="IR-1",
        account_id=ACCOUNT,
        region="us-east-1",
        day=date(2026, 8, 14),
        filename=lookup_object_name(ACCOUNT, "us-east-1", WINDOW_START, 0),
    )
    assert data_key.startswith("aws/IR-1/")
    assert data_key.endswith(".json.gz")
