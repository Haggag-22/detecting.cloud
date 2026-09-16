"""CLI wiring for ventra collect cloudtrail."""

from __future__ import annotations

import pytest

from collector.cli import build_ventra_parser, normalize_collect_mode


def test_normalize_mode_s3_alias():
    assert normalize_collect_mode("s3") == "trail"
    assert normalize_collect_mode("trail") == "trail"
    assert normalize_collect_mode("lookup") == "lookup"


def test_ventra_collect_cloudtrail_requires_mode():
    parser = build_ventra_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["collect", "cloudtrail", "--engagement-id", "IR-1"])


def test_ventra_collect_cloudtrail_parses_trail():
    parser = build_ventra_parser()
    args = parser.parse_args(
        [
            "collect",
            "cloudtrail",
            "--mode",
            "trail",
            "--engagement-id",
            "IR-1",
            "--bucket",
            "src",
            "--dest-bucket",
            "dst",
            "--start",
            "2026-01-01",
            "--dry-run",
        ]
    )
    assert args.mode == "trail"
    assert args.engagement_id == "IR-1"
