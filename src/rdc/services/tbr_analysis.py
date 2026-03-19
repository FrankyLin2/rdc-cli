"""Conservative event-level TBR analysis helpers."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

_DRAW_FLAGS = 0x0002 | 0x0008
_DISPATCH_FLAG = 0x0004

_WRITE_USAGES: frozenset[int] = frozenset(
    {22, 23, 24, 25, 26, 27, 28, 29, 30, 32, 33, 35, 37, 40, 43}
)
_SAMPLED_READ_USAGES: frozenset[int] = frozenset({13, 14, 15, 16, 17})
_COMPUTE_READ_USAGES: frozenset[int] = frozenset({18})
_COMPUTE_WRITE_USAGES: frozenset[int] = frozenset({30})
_INPUT_ATTACHMENT_USAGES: frozenset[int] = frozenset({31})
_COPY_READ_USAGES: frozenset[int] = frozenset({42})
_RESOLVE_READ_USAGES: frozenset[int] = frozenset({39})
_WRITE_KIND_MAP: dict[int, str] = {
    22: "rw_write",
    23: "rw_write",
    24: "rw_write",
    25: "rw_write",
    26: "rw_write",
    27: "rw_write",
    28: "rw_write",
    29: "rw_write",
    30: "rw_write",
    32: "color_target_write",
    33: "depth_stencil_write",
    35: "clear_write",
    37: "genmips_write",
    40: "resolve_write",
    43: "copy_write",
}


def build_tbr_analysis(
    actions: Iterable[Any],
    snapshots: Mapping[int, Mapping[str, Any]],
    usage_map: Mapping[int, Iterable[Any]],
    *,
    capture: str,
    current_eid: int,
    external_resources: set[int] | None = None,
) -> dict[str, Any]:
    """Build conservative TBR analysis output from event snapshots and usage."""
    del current_eid
    segments = _build_segments(actions, snapshots)
    segment_by_eid = _segment_by_eid(segments)
    rt_switches = _build_rt_switches(segments)
    external = set() if external_resources is None else set(external_resources)
    resource_flows = _build_resource_flows(usage_map, segment_by_eid)
    optimization_candidates = _build_candidates(rt_switches, resource_flows)
    prune_analysis = _build_prune_analysis(segments, resource_flows, external)
    return {
        "capture": capture,
        "mode": "conservative",
        "segments": segments,
        "rt_switches": rt_switches,
        "resource_flows": resource_flows,
        "optimization_candidates": optimization_candidates,
        "prune_analysis": prune_analysis,
    }


def _build_segments(
    actions: Iterable[Any],
    snapshots: Mapping[int, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    ordered = sorted(
        (
            action
            for action in actions
            if getattr(action, "eid", getattr(action, "eventId", 0)) in snapshots
        ),
        key=lambda action: getattr(action, "eid", getattr(action, "eventId", 0)),
    )
    segments: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    current_signature: dict[str, Any] | None = None
    current_action_signature: tuple[str | None, bool] | None = None

    for index, action in enumerate(ordered):
        eid = getattr(action, "eid", getattr(action, "eventId", 0))
        snapshot = snapshots[eid]
        signature = _signature_from_snapshot(snapshot)
        action_signature = (
            getattr(action, "pass_name", "-"),
            bool(int(getattr(action, "flags", 0)) & _DISPATCH_FLAG),
        )
        if (
            current is None
            or signature != current_signature
            or action_signature != current_action_signature
        ):
            current = {
                "segment_id": f"seg-{len(segments) + 1:04d}",
                "begin_eid": eid,
                "end_eid": eid,
                "pass_name": getattr(action, "pass_name", "-"),
                "synthetic_pass": False,
                "draw_count": 0,
                "dispatch_count": 0,
                "event_count": 0,
                "has_compute": False,
                "attachments": {
                    "colors": list(snapshot.get("colors", [])),
                    "depth": snapshot.get("depth"),
                },
                "state_signature": dict(signature),
                "switch_reason": (
                    [] if index == 0 else _diff_signature(current_signature or {}, signature)
                ),
                "produced_resources": _produced_resources(snapshot),
            }
            segments.append(current)
            current_signature = signature
            current_action_signature = action_signature
        else:
            current["end_eid"] = eid

        flags = int(getattr(action, "flags", 0))
        if flags & _DRAW_FLAGS:
            current["draw_count"] += 1
        if flags & _DISPATCH_FLAG:
            current["dispatch_count"] += 1
            current["has_compute"] = True
        current["event_count"] += 1
        current["end_eid"] = eid
    return segments


def _signature_from_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    depth = snapshot.get("depth")
    return {
        "framebuffer_key": snapshot.get("framebuffer_key"),
        "load_store_key": snapshot.get("load_store_key"),
        "resolve_key": snapshot.get("resolve_key"),
        "colors": tuple(
            (item.get("slot"), item.get("resource_id")) for item in snapshot.get("colors", [])
        ),
        "depth": depth.get("resource_id") if isinstance(depth, dict) else None,
    }


def _diff_signature(previous: Mapping[str, Any], current: Mapping[str, Any]) -> list[str]:
    reasons: list[str] = []
    for key in ("framebuffer_key", "load_store_key", "resolve_key", "colors", "depth"):
        if previous.get(key) != current.get(key):
            reasons.append(f"{key}_changed")
    return reasons or ["state_changed"]


def _produced_resources(snapshot: Mapping[str, Any]) -> list[int]:
    colors = [
        int(item["resource_id"])
        for item in snapshot.get("colors", [])
        if int(item["resource_id"]) != 0
    ]
    depth = snapshot.get("depth")
    if isinstance(depth, dict):
        depth_id = int(depth.get("resource_id", 0))
        if depth_id != 0:
            colors.append(depth_id)
    return colors


def _segment_by_eid(segments: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    for segment in segments:
        for eid in range(int(segment["begin_eid"]), int(segment["end_eid"]) + 1):
            out[eid] = segment
    return out


def _build_rt_switches(segments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    switches: list[dict[str, Any]] = []
    for previous, current in zip(segments, segments[1:], strict=False):
        switches.append(
            {
                "from_segment": previous["segment_id"],
                "to_segment": current["segment_id"],
                "at_eid": current["begin_eid"],
                "reasons": current["switch_reason"],
                "previous_resources": previous["produced_resources"],
                "next_resources": current["produced_resources"],
            }
        )
    return switches


def _build_resource_flows(
    usage_map: Mapping[int, Iterable[Any]],
    segment_by_eid: Mapping[int, dict[str, Any]],
) -> list[dict[str, Any]]:
    flows: list[dict[str, Any]] = []
    for resource_id in sorted(usage_map):
        current_flow = _latest_flow_for_resource(flows, int(resource_id))
        events = sorted(
            usage_map[resource_id],
            key=lambda item: int(getattr(item, "eventId", 0)),
        )
        for event in events:
            usage = int(getattr(event, "usage", -1))
            eid = int(getattr(event, "eventId", 0))
            segment = segment_by_eid.get(eid)
            if segment is None:
                continue
            if usage in _WRITE_USAGES:
                current_flow = _ensure_flow_for_write(flows, int(resource_id), segment, eid, usage)
                continue
            consumer_kind = _classify_consumer_kind(usage)
            if consumer_kind is None or current_flow is None:
                continue
            current_flow["consumers"].append(
                {
                    "segment_id": segment["segment_id"],
                    "eid": eid,
                    "kind": consumer_kind,
                }
            )
    return sorted(flows, key=lambda item: (int(item["resource_id"]), int(item["producer_eid"])))


def _classify_consumer_kind(usage: int) -> str | None:
    if usage in _SAMPLED_READ_USAGES:
        return "sampled_read"
    if usage in _COMPUTE_READ_USAGES:
        return "compute_read"
    if usage in _COMPUTE_WRITE_USAGES:
        return "compute_write"
    if usage in _INPUT_ATTACHMENT_USAGES:
        return "input_attachment_candidate"
    if usage in _COPY_READ_USAGES:
        return "copy_read"
    if usage in _RESOLVE_READ_USAGES:
        return "resolve_read"
    return None


def _latest_flow_for_resource(
    flows: list[dict[str, Any]],
    resource_id: int,
) -> dict[str, Any] | None:
    matching = [flow for flow in flows if int(flow["resource_id"]) == resource_id]
    return matching[-1] if matching else None


def _ensure_flow_for_write(
    flows: list[dict[str, Any]],
    resource_id: int,
    segment: dict[str, Any],
    eid: int,
    usage: int,
) -> dict[str, Any]:
    for flow in reversed(flows):
        if int(flow["resource_id"]) != resource_id:
            continue
        if flow["producer_segment"] == segment["segment_id"] and int(flow["producer_eid"]) == eid:
            flow["producer_kind"] = _classify_write_kind(usage)
            return flow
        if flow["producer_segment"] == segment["segment_id"]:
            flow["producer_kind"] = _classify_write_kind(usage)
            return flow
        break
    flow = {
        "flow_id": f"flow-{len(flows) + 1:04d}",
        "resource_id": resource_id,
        "producer_segment": segment["segment_id"],
        "producer_eid": eid,
        "producer_kind": _classify_write_kind(usage),
        "consumers": [],
    }
    flows.append(flow)
    return flow


def _classify_write_kind(usage: int) -> str:
    return _WRITE_KIND_MAP.get(usage, "attachment_write")


def _build_candidates(
    rt_switches: list[dict[str, Any]],
    resource_flows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for switch in rt_switches:
        if _is_flush_risk_switch(switch["reasons"]):
            candidates.append(
                {
                    "kind": "flush_risk_on_rt_switch",
                    "from_segment": switch["from_segment"],
                    "to_segment": switch["to_segment"],
                    "at_eid": switch["at_eid"],
                    "reasons": switch["reasons"],
                }
            )
    for flow in resource_flows:
        producer_segment = flow.get("producer_segment")
        producer_kind = str(flow.get("producer_kind", "attachment_write"))
        for consumer in flow["consumers"]:
            kind = consumer["kind"]
            if kind == "sampled_read":
                candidate_kind = _sampled_candidate_kind(producer_kind)
            elif kind == "compute_read":
                if producer_kind == "copy_write":
                    candidate_kind = "copy_to_compute_candidate"
                elif producer_kind == "resolve_write":
                    candidate_kind = "resolve_to_compute_candidate"
                elif producer_kind == "clear_write":
                    candidate_kind = "clear_to_compute_candidate"
                elif producer_kind == "genmips_write":
                    candidate_kind = "genmips_to_compute_candidate"
                else:
                    candidate_kind = "compute_after_rt_production"
            elif kind == "input_attachment_candidate":
                candidate_kind = "input_attachment_candidate"
            elif kind == "copy_read":
                candidate_kind = "read_after_write_same_frame"
            elif kind == "resolve_read":
                candidate_kind = "read_after_write_same_frame"
            else:
                candidate_kind = "read_after_write_same_frame"
            candidates.append(
                {
                    "kind": candidate_kind,
                    "flow_id": flow.get("flow_id"),
                    "resource_id": flow["resource_id"],
                    "producer_kind": producer_kind,
                    "producer_segment": producer_segment,
                    "consumer_segment": consumer["segment_id"],
                    "eid": consumer["eid"],
                }
            )
    return candidates


def _is_flush_risk_switch(reasons: list[str]) -> bool:
    flush_reason_suffixes = {
        "framebuffer_key_changed",
        "load_store_key_changed",
        "resolve_key_changed",
        "colors_changed",
        "depth_changed",
    }
    return any(reason in flush_reason_suffixes for reason in reasons)


def _sampled_candidate_kind(producer_kind: str) -> str:
    if producer_kind == "copy_write":
        return "copy_chain_candidate"
    if producer_kind == "resolve_write":
        return "resolve_chain_candidate"
    if producer_kind == "clear_write":
        return "clear_chain_candidate"
    if producer_kind == "genmips_write":
        return "genmips_chain_candidate"
    if producer_kind == "rw_write":
        return "rw_chain_candidate"
    return "cross_pass_sampling_candidate"


def _build_prune_analysis(
    segments: list[dict[str, Any]],
    resource_flows: list[dict[str, Any]],
    external_resources: set[int],
) -> dict[str, Any]:
    dependencies: dict[int, set[int]] = {}
    externally_live: set[int] = set()
    internally_live: set[int] = set()
    all_resources: set[int] = {
        int(resource_id)
        for segment in segments
        for resource_id in segment["produced_resources"]
        if int(resource_id) not in external_resources
    }
    for flow in resource_flows:
        rid = int(flow["resource_id"])
        if rid in external_resources:
            continue
        all_resources.add(rid)
        if str(flow.get("producer_kind")) == "depth_stencil_write":
            internally_live.add(rid)
        consumed: set[int] = set()
        for consumer in flow["consumers"]:
            produced, has_external_output = _segment_outputs_by_kind(
                segments, str(consumer["segment_id"]), external_resources
            )
            if has_external_output:
                externally_live.add(rid)
            for source in produced:
                consumed.add(source)
        dependencies[rid] = consumed

    waves: list[dict[str, Any]] = []
    remaining = set(all_resources)
    while remaining:
        dead = sorted(
            rid
            for rid in remaining
            if rid not in externally_live
            and rid not in internally_live
            and not (dependencies.get(rid, set()) & remaining)
        )
        if not dead:
            break
        waves.append({"resources": dead})
        remaining -= set(dead)
    return {
        "unused_terminal_resources": waves[0]["resources"] if waves else [],
        "recursive_prune_groups": waves,
    }


def _segment_outputs_by_kind(
    segments: list[dict[str, Any]],
    segment_id: str,
    external_resources: set[int],
) -> tuple[set[int], bool]:
    for segment in segments:
        if str(segment.get("segment_id")) != segment_id:
            continue
        outputs = {int(resource_id) for resource_id in segment.get("produced_resources", [])}
        return (
            {resource_id for resource_id in outputs if resource_id not in external_resources},
            any(resource_id in external_resources for resource_id in outputs),
        )
    return set(), False
