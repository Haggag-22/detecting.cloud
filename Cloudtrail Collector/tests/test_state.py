"""Resume state.

Resumability is a hard requirement, so the tests that matter are the ones that
prove a killed run can restart without re-copying everything, and that a state
file from a *different* collection is refused rather than silently reused.
"""

from __future__ import annotations

import pytest

from collector.errors import StateError
from collector.state import Checkpoint, RunState

IDENTITY = {
    "mode": "trail",
    "engagement_id": "IR-2026-0142",
    "source_bucket": "client-trail",
    "dest_bucket": "our-evidence",
    "start": "2026-08-01T00:00:00+00:00",
    "end": "2026-08-15T00:00:00+00:00",
}


@pytest.fixture
def state_path(tmp_path):
    return tmp_path / "state.ndjson"


def test_completed_keys_survive_a_restart(state_path):
    state = RunState(state_path, IDENTITY)
    state.load(resume=False)
    for i in range(100):
        state.mark_completed(f"aws/IR/obj-{i}.json.gz")
    state.close()

    resumed = RunState(state_path, IDENTITY)
    resumed.load(resume=True)
    assert len(resumed.completed_keys) == 100
    assert resumed.is_completed("aws/IR/obj-42.json.gz")
    assert not resumed.is_completed("aws/IR/obj-100.json.gz")
    resumed.close()


def test_checkpoints_and_finished_windows_survive_a_restart(state_path):
    state = RunState(state_path, {**IDENTITY, "mode": "lookup"})
    state.load(resume=False)
    state.save_checkpoint(Checkpoint("us-east-1", "w-start", "w-end", "token-abc", 450))
    state.mark_window_done("eu-west-1", "x-start", "x-end")
    state.close()

    resumed = RunState(state_path, {**IDENTITY, "mode": "lookup"})
    resumed.load(resume=True)
    checkpoint = resumed.checkpoint_for("us-east-1", "w-start", "w-end")
    assert checkpoint is not None
    assert checkpoint.events_written == 450
    assert checkpoint.last_token == "token-abc"
    assert resumed.is_window_done("eu-west-1", "x-start", "x-end")
    assert not resumed.is_window_done("us-east-1", "w-start", "w-end")
    resumed.close()


def test_torn_final_line_from_a_kill_is_tolerated(state_path):
    """SIGKILL mid-write must cost at most the last record, not the whole file."""
    state = RunState(state_path, IDENTITY)
    state.load(resume=False)
    for i in range(10):
        state.mark_completed(f"obj-{i}")
    state.close()

    with state_path.open("a", encoding="utf-8") as handle:
        handle.write('{"kind":"completed","dest_ke')

    resumed = RunState(state_path, IDENTITY)
    resumed.load(resume=True)
    assert len(resumed.completed_keys) == 10
    resumed.close()


def test_corruption_before_the_final_line_is_refused(state_path):
    """Mid-file corruption is not a crash artifact, so it must not be trusted."""
    state = RunState(state_path, IDENTITY)
    state.load(resume=False)
    state.mark_completed("obj-0")
    state.close()

    text = state_path.read_text()
    state_path.write_text(text.replace('{"kind":"completed"', "GARBAGE") + '{"kind":"completed","dest_key":"z"}\n')

    with pytest.raises(StateError, match="not the final"):
        RunState(state_path, IDENTITY).load(resume=True)


def test_state_from_a_different_source_is_refused(state_path):
    """Resuming across engagements would mismatch the manifest and the data."""
    state = RunState(state_path, IDENTITY)
    state.load(resume=False)
    state.mark_completed("obj-0")
    state.close()

    other = {**IDENTITY, "source_bucket": "a-different-clients-bucket"}
    with pytest.raises(StateError, match="different run"):
        RunState(state_path, other).load(resume=True)


def test_state_from_a_different_time_range_is_refused(state_path):
    state = RunState(state_path, IDENTITY)
    state.load(resume=False)
    state.close()

    with pytest.raises(StateError, match="different run"):
        RunState(state_path, {**IDENTITY, "end": "2026-09-01T00:00:00+00:00"}).load(resume=True)


def test_existing_state_is_not_overwritten_without_resume(state_path):
    """The file may be the only record of a partial collection."""
    state = RunState(state_path, IDENTITY)
    state.load(resume=False)
    state.mark_completed("obj-0")
    state.close()

    with pytest.raises(StateError, match="--resume"):
        RunState(state_path, IDENTITY).load(resume=False)


def test_headerless_file_is_refused(state_path):
    state_path.write_text('{"kind":"completed","dest_key":"x"}\n')
    with pytest.raises(StateError, match="no header"):
        RunState(state_path, IDENTITY).load(resume=True)


def test_parent_directory_is_created(tmp_path):
    nested = tmp_path / "deep" / "nested" / "state.ndjson"
    state = RunState(nested, IDENTITY)
    state.load(resume=False)
    state.mark_completed("obj-0")
    state.close()
    assert nested.exists()


def test_concurrent_marks_are_all_recorded(state_path):
    """Mode A marks completion from a thread pool."""
    import threading

    state = RunState(state_path, IDENTITY)
    state.load(resume=False)

    def worker(base: int) -> None:
        for i in range(base, base + 100):
            state.mark_completed(f"obj-{i}")

    threads = [threading.Thread(target=worker, args=(n * 100,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    state.close()

    resumed = RunState(state_path, IDENTITY)
    resumed.load(resume=True)
    assert len(resumed.completed_keys) == 800
    resumed.close()
