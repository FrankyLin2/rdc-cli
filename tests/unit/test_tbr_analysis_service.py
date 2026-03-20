"""Tests for TBR analysis service helpers."""

from __future__ import annotations

from types import SimpleNamespace

from rdc.services.tbr_analysis import build_tbr_analysis


def _action(
    eid: int,
    *,
    pass_name: str = "MainPass",
    flags: int = 0x0002,
) -> SimpleNamespace:
    return SimpleNamespace(
        eid=eid,
        eventId=eid,
        pass_name=pass_name,
        flags=flags,
    )


def _segment_snapshot(
    eid: int,
    *,
    colors: list[tuple[int, int]],
    depth: int | None = None,
    framebuffer_key: str | None = None,
    load_store_key: str = "load-store-a",
    resolve_key: str = "resolve-a",
) -> dict[str, object]:
    return {
        "eid": eid,
        "colors": [{"slot": slot, "resource_id": rid} for slot, rid in colors],
        "depth": None if depth is None else {"resource_id": depth},
        "framebuffer_key": framebuffer_key or repr(colors),
        "load_store_key": load_store_key,
        "resolve_key": resolve_key,
    }


def _usage(event_id: int, usage: int) -> SimpleNamespace:
    return SimpleNamespace(eventId=event_id, usage=usage)


def test_segments_split_when_attachment_signature_changes_inside_single_pass() -> None:
    actions = [_action(10), _action(20)]
    snapshots = {
        10: _segment_snapshot(10, colors=[(0, 101)], depth=201, framebuffer_key="fb-a"),
        20: _segment_snapshot(20, colors=[(0, 102)], depth=201, framebuffer_key="fb-b"),
    }

    result = build_tbr_analysis(actions, snapshots, {}, capture="demo.rdc", current_eid=0)

    assert [segment["begin_eid"] for segment in result["segments"]] == [10, 20]
    assert "framebuffer_key_changed" in result["rt_switches"][0]["reasons"]


def test_state_only_segment_boundary_is_not_flush_risk() -> None:
    actions = [
        _action(10, pass_name="RenderFunPass"),
        _action(20, pass_name="UberPostProcess"),
    ]
    snapshots = {
        10: _segment_snapshot(10, colors=[(0, 101)], depth=201, framebuffer_key="fb-a"),
        20: _segment_snapshot(20, colors=[(0, 101)], depth=201, framebuffer_key="fb-a"),
    }

    result = build_tbr_analysis(actions, snapshots, {}, capture="demo.rdc", current_eid=0)

    assert len(result["segments"]) == 2
    assert result["rt_switches"][0]["reasons"] == ["state_changed"]
    kinds = [item["kind"] for item in result["optimization_candidates"]]
    assert "flush_risk_on_rt_switch" not in kinds


def test_resource_flow_marks_sampled_read_consumer() -> None:
    actions = [_action(10), _action(20)]
    snapshots = {
        10: _segment_snapshot(10, colors=[(0, 101)], depth=201, framebuffer_key="fb-a"),
        20: _segment_snapshot(20, colors=[(0, 102)], depth=201, framebuffer_key="fb-b"),
    }
    usage_map = {
        101: [
            _usage(10, 32),  # ColorTarget
            _usage(20, 17),  # PS_Resource
        ]
    }

    result = build_tbr_analysis(actions, snapshots, usage_map, capture="demo.rdc", current_eid=0)

    consumer = result["resource_flows"][0]["consumers"][0]
    assert consumer["kind"] == "sampled_read"
    candidate = result["optimization_candidates"][1]
    assert candidate["kind"] == "cross_pass_sampling_candidate"
    assert candidate["consumer_count"] == 1
    assert candidate["consumer_segments"] == ["seg-0002"]
    assert candidate["first_consumer_eid"] == 20
    assert candidate["last_consumer_eid"] == 20


def test_resource_flow_marks_compute_read_consumer() -> None:
    actions = [_action(10), _action(20, flags=0x0004)]
    snapshots = {
        10: _segment_snapshot(10, colors=[(0, 101)], depth=201, framebuffer_key="fb-a"),
        20: _segment_snapshot(20, colors=[], depth=None, framebuffer_key="compute"),
    }
    usage_map = {
        101: [
            _usage(10, 32),  # ColorTarget
            _usage(20, 18),  # CS_Resource
        ]
    }

    result = build_tbr_analysis(actions, snapshots, usage_map, capture="demo.rdc", current_eid=0)

    consumer = result["resource_flows"][0]["consumers"][0]
    assert consumer["kind"] == "compute_read"
    kinds = [item["kind"] for item in result["optimization_candidates"]]
    assert "compute_after_rt_production" in kinds


def test_resource_flow_marks_input_attachment_candidate() -> None:
    actions = [_action(10), _action(20)]
    snapshots = {
        10: _segment_snapshot(10, colors=[(0, 101)], depth=201, framebuffer_key="fb-a"),
        20: _segment_snapshot(20, colors=[(0, 102)], depth=201, framebuffer_key="fb-b"),
    }
    usage_map = {
        101: [
            _usage(10, 32),  # ColorTarget
            _usage(20, 31),  # InputTarget
        ]
    }

    result = build_tbr_analysis(actions, snapshots, usage_map, capture="demo.rdc", current_eid=0)

    consumer = result["resource_flows"][0]["consumers"][0]
    assert consumer["kind"] == "input_attachment_candidate"
    kinds = [item["kind"] for item in result["optimization_candidates"]]
    assert "input_attachment_candidate" in kinds


def test_resource_flow_uses_latest_writer_as_producer() -> None:
    actions = [_action(10), _action(20), _action(30)]
    snapshots = {
        10: _segment_snapshot(10, colors=[(0, 101)], framebuffer_key="fb-a"),
        20: _segment_snapshot(20, colors=[(0, 101)], framebuffer_key="fb-b"),
        30: _segment_snapshot(30, colors=[(0, 102)], framebuffer_key="fb-c"),
    }
    usage_map = {
        101: [
            _usage(10, 32),  # first ColorTarget write
            _usage(20, 32),  # later ColorTarget write
            _usage(30, 17),  # PS_Resource
        ]
    }

    result = build_tbr_analysis(actions, snapshots, usage_map, capture="demo.rdc", current_eid=0)

    flows = [flow for flow in result["resource_flows"] if flow["resource_id"] == 101]
    assert len(flows) == 2
    assert flows[0]["producer_segment"] == "seg-0001"
    assert flows[0]["consumers"] == []
    assert flows[1]["producer_segment"] == "seg-0002"
    assert flows[1]["consumers"][0]["segment_id"] == "seg-0003"


def test_resource_flow_marks_copy_and_resolve_consumers() -> None:
    actions = [_action(10), _action(20), _action(30)]
    snapshots = {
        10: _segment_snapshot(10, colors=[(0, 101)], framebuffer_key="fb-a"),
        20: _segment_snapshot(20, colors=[(0, 102)], framebuffer_key="fb-b"),
        30: _segment_snapshot(30, colors=[(0, 103)], framebuffer_key="fb-c"),
    }
    usage_map = {
        101: [
            _usage(10, 32),  # ColorTarget
            _usage(20, 42),  # CopySrc
            _usage(30, 39),  # ResolveSrc
        ]
    }

    result = build_tbr_analysis(actions, snapshots, usage_map, capture="demo.rdc", current_eid=0)

    flow = [item for item in result["resource_flows"] if item["resource_id"] == 101][0]
    consumer_kinds = [consumer["kind"] for consumer in flow["consumers"]]
    assert consumer_kinds == ["copy_read", "resolve_read"]


def test_segments_include_event_count_and_compute_context() -> None:
    actions = [_action(10), _action(20, flags=0x0004)]
    snapshots = {
        10: _segment_snapshot(10, colors=[(0, 101)], framebuffer_key="fb-a"),
        20: _segment_snapshot(20, colors=[], framebuffer_key="compute"),
    }

    result = build_tbr_analysis(actions, snapshots, {}, capture="demo.rdc", current_eid=0)

    assert result["segments"][0]["event_count"] == 1
    assert result["segments"][0]["has_compute"] is False
    assert result["segments"][1]["event_count"] == 1
    assert result["segments"][1]["has_compute"] is True


def test_resource_flows_include_producer_kind_for_copy_and_resolve_writes() -> None:
    actions = [_action(10), _action(20)]
    snapshots = {
        10: _segment_snapshot(10, colors=[(0, 101)], framebuffer_key="fb-a"),
        20: _segment_snapshot(20, colors=[(0, 102)], framebuffer_key="fb-b"),
    }
    usage_map = {
        301: [_usage(10, 43)],  # CopyDst
        302: [_usage(20, 40)],  # ResolveDst
    }

    result = build_tbr_analysis(actions, snapshots, usage_map, capture="demo.rdc", current_eid=0)

    flows = {flow["resource_id"]: flow for flow in result["resource_flows"]}
    assert flows[301]["producer_kind"] == "copy_write"
    assert flows[302]["producer_kind"] == "resolve_write"


def test_candidates_distinguish_copy_and_resolve_producers() -> None:
    actions = [_action(10), _action(20), _action(30), _action(40)]
    snapshots = {
        10: _segment_snapshot(10, colors=[(0, 401)], framebuffer_key="fb-a"),
        20: _segment_snapshot(20, colors=[(0, 402)], framebuffer_key="fb-b"),
        30: _segment_snapshot(30, colors=[(0, 403)], framebuffer_key="fb-c"),
        40: _segment_snapshot(40, colors=[(0, 404)], framebuffer_key="fb-d"),
    }
    usage_map = {
        501: [
            _usage(10, 43),  # CopyDst
            _usage(20, 17),  # PS_Resource
        ],
        502: [
            _usage(30, 40),  # ResolveDst
            _usage(40, 17),  # PS_Resource
        ],
    }

    result = build_tbr_analysis(actions, snapshots, usage_map, capture="demo.rdc", current_eid=0)

    by_resource = {
        candidate["resource_id"]: candidate["kind"]
        for candidate in result["optimization_candidates"]
        if candidate.get("resource_id") in {501, 502}
    }
    assert by_resource[501] == "copy_chain_candidate"
    assert by_resource[502] == "resolve_chain_candidate"


def test_candidates_distinguish_clear_and_genmips_producers() -> None:
    actions = [_action(10), _action(20), _action(30), _action(40)]
    snapshots = {
        10: _segment_snapshot(10, colors=[(0, 601)], framebuffer_key="fb-a"),
        20: _segment_snapshot(20, colors=[(0, 602)], framebuffer_key="fb-b"),
        30: _segment_snapshot(30, colors=[(0, 603)], framebuffer_key="fb-c"),
        40: _segment_snapshot(40, colors=[(0, 604)], framebuffer_key="fb-d"),
    }
    usage_map = {
        701: [
            _usage(10, 35),  # Clear
            _usage(20, 17),  # PS_Resource
        ],
        702: [
            _usage(30, 37),  # GenMips
            _usage(40, 17),  # PS_Resource
        ],
    }

    result = build_tbr_analysis(actions, snapshots, usage_map, capture="demo.rdc", current_eid=0)

    by_resource = {
        candidate["resource_id"]: candidate["kind"]
        for candidate in result["optimization_candidates"]
        if candidate.get("resource_id") in {701, 702}
    }
    assert by_resource[701] == "clear_chain_candidate"
    assert by_resource[702] == "genmips_chain_candidate"


def test_candidates_aggregate_multiple_consumers_for_same_flow() -> None:
    actions = [_action(10), _action(20), _action(30)]
    snapshots = {
        10: _segment_snapshot(10, colors=[(0, 101)], framebuffer_key="fb-a"),
        20: _segment_snapshot(20, colors=[(0, 102)], framebuffer_key="fb-b"),
        30: _segment_snapshot(30, colors=[(0, 103)], framebuffer_key="fb-c"),
    }
    usage_map = {
        101: [
            _usage(10, 32),  # ColorTarget
            _usage(20, 17),  # PS_Resource
            _usage(30, 17),  # PS_Resource
        ]
    }

    result = build_tbr_analysis(actions, snapshots, usage_map, capture="demo.rdc", current_eid=0)

    candidates = [
        candidate
        for candidate in result["optimization_candidates"]
        if candidate.get("flow_id") == "flow-0001"
    ]
    assert len(candidates) == 1
    assert candidates[0]["consumer_count"] == 2
    assert candidates[0]["consumer_segments"] == ["seg-0002", "seg-0003"]
    assert candidates[0]["first_consumer_eid"] == 20
    assert candidates[0]["last_consumer_eid"] == 30


def test_prune_analysis_reports_unused_terminal_resources() -> None:
    actions = [_action(10)]
    snapshots = {
        10: _segment_snapshot(10, colors=[(0, 301)], depth=None, framebuffer_key="fb-a"),
    }

    result = build_tbr_analysis(actions, snapshots, {}, capture="demo.rdc", current_eid=0)

    assert result["prune_analysis"]["unused_terminal_resources"] == [301]


def test_prune_analysis_excludes_external_swapchain_resources() -> None:
    actions = [_action(10)]
    snapshots = {
        10: _segment_snapshot(10, colors=[(0, 951)], depth=None, framebuffer_key="fb-a"),
    }

    result = build_tbr_analysis(
        actions,
        snapshots,
        {},
        capture="demo.rdc",
        current_eid=0,
        external_resources={951},
    )

    assert result["prune_analysis"]["unused_terminal_resources"] == []


def test_prune_analysis_keeps_resource_alive_when_consumer_feeds_external_output() -> None:
    actions = [_action(10), _action(20)]
    snapshots = {
        10: _segment_snapshot(10, colors=[(0, 101)], depth=None, framebuffer_key="fb-a"),
        20: _segment_snapshot(20, colors=[(0, 951)], depth=None, framebuffer_key="fb-b"),
    }
    usage_map = {
        101: [
            _usage(10, 32),  # ColorTarget
            _usage(20, 17),  # PS_Resource consumed by presented pass
        ],
        951: [
            _usage(20, 32),  # Swapchain ColorTarget
        ],
    }

    result = build_tbr_analysis(
        actions,
        snapshots,
        usage_map,
        capture="demo.rdc",
        current_eid=0,
        external_resources={951},
    )

    assert 101 not in result["prune_analysis"]["unused_terminal_resources"]


def test_prune_analysis_keeps_depth_stencil_targets_alive_without_downstream_consumers() -> None:
    actions = [_action(10)]
    snapshots = {
        10: _segment_snapshot(10, colors=[], depth=201, framebuffer_key="fb-a"),
    }
    usage_map = {
        201: [
            _usage(10, 33),  # DepthStencilTarget
        ],
    }

    result = build_tbr_analysis(actions, snapshots, usage_map, capture="demo.rdc", current_eid=0)

    assert 201 not in result["prune_analysis"]["unused_terminal_resources"]


def test_resource_flows_do_not_emit_fallback_entries_without_usage_evidence() -> None:
    actions = [_action(10)]
    snapshots = {
        10: _segment_snapshot(10, colors=[(0, 801)], depth=None, framebuffer_key="fb-a"),
    }

    result = build_tbr_analysis(actions, snapshots, {}, capture="demo.rdc", current_eid=0)

    assert result["resource_flows"] == []


def test_prune_analysis_recurses_until_no_new_dead_outputs() -> None:
    actions = [_action(10), _action(20)]
    snapshots = {
        10: _segment_snapshot(10, colors=[(0, 101)], depth=None, framebuffer_key="fb-a"),
        20: _segment_snapshot(20, colors=[(0, 201)], depth=None, framebuffer_key="fb-b"),
    }
    usage_map = {
        101: [
            _usage(10, 32),  # ColorTarget
            _usage(20, 17),  # PS_Resource
        ],
    }

    result = build_tbr_analysis(actions, snapshots, usage_map, capture="demo.rdc", current_eid=0)

    waves = result["prune_analysis"]["recursive_prune_groups"]
    assert len(waves) == 2
    assert waves[0]["resources"] == [201]
    assert waves[1]["resources"] == [101]
