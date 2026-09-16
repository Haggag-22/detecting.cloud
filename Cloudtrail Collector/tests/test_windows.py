"""Time-window slicing.

The silent failure this guards against: windows that leave gaps. A gap means
events that exist in CloudTrail but never appear in the evidence set, with
nothing anywhere reporting an error. The contiguity and coverage tests below
are the ones that matter.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from collector.errors import ConfigError
from collector.windows import LOOKUP_RETENTION, slice_windows, warn_if_outside_retention

START = datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)


def test_exact_division():
    windows = slice_windows(START, START + timedelta(hours=24), timedelta(hours=6))
    assert len(windows) == 4
    assert windows[0].start == START
    assert windows[-1].end == START + timedelta(hours=24)


def test_windows_are_contiguous_with_no_gaps():
    """Any gap here is data that is never collected and never reported missing."""
    windows = slice_windows(START, START + timedelta(hours=37), timedelta(hours=6))
    for earlier, later in zip(windows, windows[1:]):
        assert earlier.end == later.start


def test_windows_do_not_overlap():
    """Overlap duplicates events in the evidence set and inflates the count."""
    windows = slice_windows(START, START + timedelta(hours=37), timedelta(hours=5))
    for earlier, later in zip(windows, windows[1:]):
        assert earlier.end <= later.start


def test_total_duration_equals_requested_range():
    end = START + timedelta(days=3, hours=7, minutes=13)
    windows = slice_windows(START, end, timedelta(hours=6))
    assert sum((w.duration for w in windows), timedelta()) == end - START


def test_final_window_is_clipped_not_extended():
    """Over-running the range would collect events outside the engagement scope."""
    end = START + timedelta(hours=14)
    windows = slice_windows(START, end, timedelta(hours=6))
    assert len(windows) == 3
    assert windows[-1].end == end
    assert windows[-1].duration == timedelta(hours=2)


def test_range_shorter_than_window_yields_one_window():
    end = START + timedelta(minutes=17)
    windows = slice_windows(START, end, timedelta(hours=6))
    assert len(windows) == 1
    assert windows[0].start == START and windows[0].end == end


def test_ninety_day_range_at_six_hours():
    windows = slice_windows(START, START + timedelta(days=90), timedelta(hours=6))
    assert len(windows) == 360


def test_naive_bounds_rejected():
    """A naive bound makes the collected range depend on the host's timezone."""
    with pytest.raises(ConfigError, match="timezone-aware"):
        slice_windows(datetime(2026, 8, 1), datetime(2026, 8, 2), timedelta(hours=6))


def test_non_utc_input_normalised():
    tokyo = timezone(timedelta(hours=9))
    windows = slice_windows(
        START.astimezone(tokyo), (START + timedelta(hours=12)).astimezone(tokyo), timedelta(hours=6)
    )
    assert windows[0].start == START
    assert all(w.start.tzinfo == timezone.utc for w in windows)


def test_end_before_start_rejected():
    with pytest.raises(ConfigError, match="must be after"):
        slice_windows(START, START - timedelta(hours=1), timedelta(hours=6))


def test_zero_length_range_rejected():
    with pytest.raises(ConfigError, match="must be after"):
        slice_windows(START, START, timedelta(hours=6))


@pytest.mark.parametrize("bad", [timedelta(0), timedelta(hours=-1)])
def test_non_positive_window_rejected(bad):
    """A zero window would loop forever rather than fail."""
    with pytest.raises(ConfigError, match="must be positive"):
        slice_windows(START, START + timedelta(hours=1), bad)


def test_window_keys_are_unique():
    """Checkpoints are keyed on these; a collision would skip a window on resume."""
    windows = slice_windows(START, START + timedelta(days=10), timedelta(hours=6))
    assert len({w.key() for w in windows}) == len(windows)


def test_dst_transition_does_not_shift_boundaries():
    """Everything is UTC, so a US DST change must not perturb window edges."""
    march = datetime(2026, 3, 8, 0, 0, tzinfo=timezone.utc)
    windows = slice_windows(march, march + timedelta(days=1), timedelta(hours=6))
    assert [w.duration for w in windows] == [timedelta(hours=6)] * 4


def test_retention_warning_for_old_start():
    now = datetime(2026, 8, 1, tzinfo=timezone.utc)
    warning = warn_if_outside_retention(now - LOOKUP_RETENTION - timedelta(days=5), now=now)
    assert warning is not None
    assert "collection artifact" in warning


def test_no_retention_warning_inside_horizon():
    now = datetime(2026, 8, 1, tzinfo=timezone.utc)
    assert warn_if_outside_retention(now - timedelta(days=30), now=now) is None
