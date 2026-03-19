"""Tests for TBR snapshot collection in the query handler."""

from __future__ import annotations

import mock_renderdoc as rd
from conftest import make_daemon_state

import rdc.handlers.query as query_mod
from rdc.services.query_service import walk_actions


def _action(eid: int, flags: int) -> rd.ActionDescription:
    return rd.ActionDescription(
        eventId=eid,
        flags=flags,
        numIndices=3,
        numInstances=1,
        _name=f"Event {eid}",
    )


def test_collect_tbr_snapshots_tracks_attachments_and_action_flags() -> None:
    ctrl = rd.MockReplayController()
    actions = [
        _action(10, int(rd.ActionFlags.Drawcall | rd.ActionFlags.Clear)),
        _action(20, int(rd.ActionFlags.Drawcall | rd.ActionFlags.Resolve)),
        _action(30, int(rd.ActionFlags.Dispatch)),
    ]
    pipe_a = rd.MockPipeState()
    pipe_a._output_targets = [rd.Descriptor(resource=rd.ResourceId(101))]
    pipe_a._depth_target = rd.Descriptor(resource=rd.ResourceId(201))
    pipe_b = rd.MockPipeState()
    pipe_b._output_targets = [rd.Descriptor(resource=rd.ResourceId(102))]
    pipe_b._depth_target = rd.Descriptor(resource=rd.ResourceId(201))
    pipe_c = rd.MockPipeState()
    pipe_c._output_targets = []
    pipe_c._depth_target = rd.Descriptor(resource=rd.ResourceId(0))
    ctrl._actions = actions
    ctrl._pipe_states = {10: pipe_a, 20: pipe_b, 30: pipe_c}

    state = make_daemon_state(ctrl=ctrl, actions=actions, current_eid=0, rd=rd)

    snapshots = query_mod._collect_tbr_snapshots(
        state,
        walk_actions(actions, state.structured_file),
    )

    assert snapshots[10]["colors"] == [{"slot": 0, "resource_id": 101}]
    assert snapshots[10]["depth"] == {"resource_id": 201}
    assert "clear" in snapshots[10]["load_store_key"]
    assert snapshots[20]["colors"] == [{"slot": 0, "resource_id": 102}]
    assert snapshots[20]["resolve_key"] == "resolve"
    assert snapshots[30]["colors"] == []
    assert snapshots[30]["depth"] is None


def test_collect_tbr_snapshots_skips_non_productive_marker_actions() -> None:
    ctrl = rd.MockReplayController()
    actions = [
        _action(10, int(rd.ActionFlags.PushMarker)),
        _action(20, int(rd.ActionFlags.Drawcall)),
    ]
    pipe = rd.MockPipeState()
    pipe._output_targets = [rd.Descriptor(resource=rd.ResourceId(101))]
    ctrl._actions = actions
    ctrl._pipe_states = {10: pipe, 20: pipe}

    state = make_daemon_state(ctrl=ctrl, actions=actions, current_eid=0, rd=rd)

    snapshots = query_mod._collect_tbr_snapshots(
        state,
        walk_actions(actions, state.structured_file),
    )

    assert 10 not in snapshots
    assert 20 in snapshots
