"""TBR analysis command."""

from __future__ import annotations

import click

from rdc.commands._helpers import call
from rdc.formatters.json_fmt import write_json


@click.command("tbr")
@click.option("--json", "use_json", is_flag=True, default=False, help="Output JSON.")
@click.option("--debug", "debug_mode", is_flag=True, default=False, help="Include debug details.")
def tbr_cmd(use_json: bool, debug_mode: bool) -> None:
    """Analyze event-level render-target switching for TBR optimization."""
    del use_json
    params = {"debug": True} if debug_mode else {}
    result = call("tbr_analysis", params)
    write_json(result)
