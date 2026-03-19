"""Tests for the ``rdc tbr`` CLI command."""

from __future__ import annotations

from click.testing import CliRunner
from conftest import patch_cli_session

from rdc.cli import main


def test_help_shows_tbr() -> None:
    result = CliRunner().invoke(main, ["--help"])

    assert result.exit_code == 0
    assert "tbr" in result.output


def test_tbr_json_forwards_daemon_result(monkeypatch) -> None:
    patch_cli_session(
        monkeypatch,
        {
            "summary": {"candidate_count": 0, "prune_count": 0},
            "optimization_candidates": [],
            "prune_analysis": {
                "unused_terminal_resources": [],
                "recursive_prune_groups": [],
            },
        },
    )

    result = CliRunner().invoke(main, ["tbr", "--json"])

    assert result.exit_code == 0
    assert '"optimization_candidates": []' in result.output
    assert '"prune_analysis"' in result.output
    assert '"segments"' not in result.output


def test_tbr_json_debug_includes_intermediate_data(monkeypatch) -> None:
    patch_cli_session(
        monkeypatch,
        {
            "summary": {"candidate_count": 0, "prune_count": 0},
            "segments": [],
            "rt_switches": [],
            "resource_flows": [],
            "optimization_candidates": [],
            "prune_analysis": {
                "unused_terminal_resources": [],
                "recursive_prune_groups": [],
            },
        },
    )

    result = CliRunner().invoke(main, ["tbr", "--json", "--debug"])

    assert result.exit_code == 0
    assert '"segments": []' in result.output
    assert '"recursive_prune_groups": []' in result.output
