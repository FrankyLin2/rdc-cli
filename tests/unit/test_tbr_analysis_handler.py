"""Tests for the daemon-side TBR analysis handler."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from conftest import make_daemon_state, rpc_request

import rdc.handlers.query as query_mod
from rdc.daemon_server import _handle_request


def _action(eid: int, name: str) -> SimpleNamespace:
    return SimpleNamespace(
        eventId=eid,
        flags=0x0002,
        children=[],
        _name=name,
        numIndices=3,
        numInstances=1,
        events=[],
    )


def test_tbr_analysis_handler_returns_expected_top_level_keys(monkeypatch) -> None:
    actions = [_action(10, "Draw")]
    state = make_daemon_state(actions=actions, current_eid=0)
    state.res_rid_map = {}

    monkeypatch.setattr(
        query_mod,
        "_collect_tbr_snapshots",
        lambda _state, _actions: {
            10: {
                "eid": 10,
                "colors": [{"slot": 0, "resource_id": 101}],
                "depth": None,
                "framebuffer_key": "fb-a",
                "load_store_key": "ls-a",
                "resolve_key": "rv-a",
            }
        },
    )

    resp, running = _handle_request(rpc_request("tbr_analysis", {"debug": True}), state)

    assert running is True
    assert set(resp["result"]) >= {
        "summary",
        "segments",
        "rt_switches",
        "resource_flows",
        "optimization_candidates",
        "prune_analysis",
    }


def test_tbr_analysis_restores_current_eid_after_scan(monkeypatch) -> None:
    actions = [
        _action(10, "Draw"),
        _action(20, "Draw2"),
    ]
    touched: list[int] = []

    def set_frame_event(eid: int, _force: bool = True) -> None:
        touched.append(eid)

    ctrl = SimpleNamespace(
        GetRootActions=lambda: actions,
        GetResources=lambda: [],
        GetAPIProperties=lambda: SimpleNamespace(pipelineType="Vulkan"),
        GetPipelineState=lambda: SimpleNamespace(),
        SetFrameEvent=set_frame_event,
        GetStructuredFile=lambda: SimpleNamespace(chunks=[]),
        GetDebugMessages=lambda: [],
        Shutdown=lambda: None,
    )
    state = make_daemon_state(ctrl=ctrl, actions=actions, current_eid=77, max_eid=100)
    state._eid_cache = 77
    state.res_rid_map = {}

    def collect(_state: Any, _actions: Any) -> dict[int, dict[str, Any]]:
        _state._eid_cache = 20
        return {
            10: {
                "eid": 10,
                "colors": [{"slot": 0, "resource_id": 101}],
                "depth": None,
                "framebuffer_key": "fb-a",
                "load_store_key": "ls-a",
                "resolve_key": "rv-a",
            },
            20: {
                "eid": 20,
                "colors": [{"slot": 0, "resource_id": 102}],
                "depth": None,
                "framebuffer_key": "fb-b",
                "load_store_key": "ls-b",
                "resolve_key": "rv-b",
            },
        }

    monkeypatch.setattr(query_mod, "_collect_tbr_snapshots", collect)

    resp, running = _handle_request(rpc_request("tbr_analysis"), state)

    assert running is True
    assert "result" in resp
    assert state.current_eid == 77
    assert touched == [77]


def test_tbr_analysis_populates_pass_name_from_effective_passes(monkeypatch) -> None:
    actions = [_action(10, "Draw")]
    state = make_daemon_state(actions=actions, current_eid=0)
    state.res_rid_map = {}

    monkeypatch.setattr(
        query_mod,
        "_collect_tbr_snapshots",
        lambda _state, _actions: {
            10: {
                "eid": 10,
                "colors": [{"slot": 0, "resource_id": 101}],
                "depth": None,
                "framebuffer_key": "fb-a",
                "load_store_key": "ls-a",
                "resolve_key": "rv-a",
            }
        },
    )
    monkeypatch.setattr(
        query_mod,
        "_effective_tbr_passes",
        lambda _state, _actions: [{"name": "RenderFunPass", "begin_eid": 1, "end_eid": 20}],
    )

    resp, running = _handle_request(rpc_request("tbr_analysis", {"debug": True}), state)

    assert running is True
    assert resp["result"]["segments"][0]["pass_name"] == "RenderFunPass"


def test_tbr_analysis_handler_default_excludes_debug_sections(monkeypatch) -> None:
    actions = [_action(10, "Draw")]
    state = make_daemon_state(actions=actions, current_eid=0)
    state.res_rid_map = {}

    monkeypatch.setattr(
        query_mod,
        "_collect_tbr_snapshots",
        lambda _state, _actions: {
            10: {
                "eid": 10,
                "colors": [{"slot": 0, "resource_id": 101}],
                "depth": None,
                "framebuffer_key": "fb-a",
                "load_store_key": "ls-a",
                "resolve_key": "rv-a",
            }
        },
    )
    monkeypatch.setattr(
        query_mod,
        "_effective_tbr_passes",
        lambda _state, _actions: [{"name": "RenderFunPass", "begin_eid": 1, "end_eid": 20}],
    )

    resp, running = _handle_request(rpc_request("tbr_analysis"), state)

    assert running is True
    assert set(resp["result"]) == {"summary", "optimization_candidates", "prune_analysis"}


def test_tbr_analysis_handler_debug_includes_intermediate_sections(monkeypatch) -> None:
    actions = [_action(10, "Draw")]
    state = make_daemon_state(actions=actions, current_eid=0)
    state.res_rid_map = {}

    monkeypatch.setattr(
        query_mod,
        "_collect_tbr_snapshots",
        lambda _state, _actions: {
            10: {
                "eid": 10,
                "colors": [{"slot": 0, "resource_id": 101}],
                "depth": None,
                "framebuffer_key": "fb-a",
                "load_store_key": "ls-a",
                "resolve_key": "rv-a",
            }
        },
    )
    monkeypatch.setattr(
        query_mod,
        "_effective_tbr_passes",
        lambda _state, _actions: [{"name": "RenderFunPass", "begin_eid": 1, "end_eid": 20}],
    )

    resp, running = _handle_request(rpc_request("tbr_analysis", {"debug": True}), state)

    assert running is True
    assert set(resp["result"]) >= {
        "summary",
        "segments",
        "rt_switches",
        "resource_flows",
        "optimization_candidates",
        "prune_analysis",
    }
