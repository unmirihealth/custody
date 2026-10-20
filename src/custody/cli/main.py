"""`custody` CLI entry point.

Registered in pyproject.toml as `custody = "custody.cli.main:app"`.
Subcommands are added here as each underlying module is implemented;
none are wired up yet in this v0.1 skeleton.
"""

from __future__ import annotations

import typer

app = typer.Typer(
    name="custody",
    help="A governed, auditable agent gateway for oncology data workflows.",
    no_args_is_help=True,
)


@app.command()
def init() -> None:
    """Generate the Ed25519 audit-signing key and a starter config. Not yet implemented."""
    raise NotImplementedError


@app.command()
def serve() -> None:
    """Run the MCP gateway (stdio or streamable HTTP). Not yet implemented."""
    raise NotImplementedError


@app.command()
def demo() -> None:
    """Generate the synthetic dataset and run the scripted end-to-end
    scenario. Not yet implemented."""
    raise NotImplementedError


if __name__ == "__main__":
    app()
