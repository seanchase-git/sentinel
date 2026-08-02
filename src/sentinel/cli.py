"""Sentinel CLI (Typer)."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from sentinel import __version__
from sentinel.rules.loader import load_rules

app = typer.Typer(help="Sentinel — local, rules-grounded security reviewer.", no_args_is_help=True)
rules_app = typer.Typer(help="Manage the security rules corpus.", no_args_is_help=True)
app.add_typer(rules_app, name="rules")

console = Console()

DEFAULT_RULES_DIR = Path(__file__).resolve().parents[2] / "rules"

RulesDirOption = Annotated[
    Path, typer.Option("--rules-dir", help="Rules corpus directory.")
]


@app.callback()
def _root(
    version: Annotated[bool, typer.Option("--version", help="Show version and exit.")] = False,
) -> None:
    if version:
        console.print(f"sentinel {__version__}")
        raise typer.Exit()


def _rules_table(title: str, rows: list[tuple[str, str, str, str, str]]) -> Table:
    table = Table(title=title)
    table.add_column("id", style="cyan", no_wrap=True)
    table.add_column("severity")
    table.add_column("languages")
    table.add_column("taxonomy")
    table.add_column("risk categories")
    for row in rows:
        table.add_row(*row)
    return table


@rules_app.command("list")
def rules_list(
    rules_dir: RulesDirOption = DEFAULT_RULES_DIR,
    from_yaml: Annotated[
        bool, typer.Option("--yaml", help="List corpus YAML files instead of the database.")
    ] = False,
) -> None:
    """List loaded rules grouped by taxonomy (from the database by default)."""
    if not from_yaml:
        try:
            from sentinel.retrieval.rules_store import RulesStore

            with RulesStore() as store:
                db_rows = store.list_rules()
            rows = [
                (
                    r["id"],
                    r["severity"],
                    ", ".join(r["languages"]),
                    ", ".join(f"{k}: {v}" for e in r["taxonomy"] for k, v in e.items()),
                    ", ".join(r["risk_categories"]),
                )
                for r in db_rows
            ]
            console.print(_rules_table(f"Sentinel rules corpus — database ({len(rows)})", rows))
            return
        except Exception as exc:  # DB not initialized yet — fall back to YAML view
            console.print(f"[yellow]database unavailable ({exc}); listing YAML corpus[/yellow]")

    result = load_rules(rules_dir)
    if result.errors:
        for err in result.errors:
            console.print(f"[red]invalid[/red] {err}")
        raise typer.Exit(code=1)
    rows = [
        (
            rule.id,
            rule.severity.value,
            ", ".join(rule.languages),
            ", ".join(rule.owasp_categories + rule.cwe_ids),
            ", ".join(rule.risk_categories),
        )
        for rule in sorted(result.rules, key=lambda r: (r.owasp_categories, r.id))
    ]
    console.print(_rules_table(f"Sentinel rules corpus — YAML ({len(rows)})", rows))


@rules_app.command("load")
def rules_load(rules_dir: RulesDirOption = DEFAULT_RULES_DIR) -> None:
    """Validate, embed, and (re)load the rules corpus into Postgres."""
    from sentinel.retrieval.embedder import Embedder
    from sentinel.retrieval.rules_store import RulesStore

    result = load_rules(rules_dir)
    if result.errors:
        for err in result.errors:
            console.print(f"[red]invalid[/red] {err}")
        console.print("[red]aborting load: fix invalid rules first[/red]")
        raise typer.Exit(code=1)

    with Embedder() as embedder:
        vectors = embedder.embed_documents([r.embedding_text for r in result.rules])
    embeddings = {rule.id: vec for rule, vec in zip(result.rules, vectors, strict=True)}

    with RulesStore() as store:
        upserted, deleted = store.replace_corpus(result.rules, result.yaml_bodies, embeddings)
        total = store.count()
    console.print(f"loaded {upserted} rules ({deleted} stale removed); database has {total}")


@rules_app.command("test")
def rules_test(
    rule_id: Annotated[str, typer.Argument(help="Rule id to self-retrieval-test.")],
    k: Annotated[int, typer.Option(help="Top-K to retrieve.")] = 20,
) -> None:
    """Embed the rule's own vulnerable example and verify the rule retrieves itself."""
    from sentinel.retrieval.embedder import Embedder
    from sentinel.retrieval.rules_store import RulesStore

    result = load_rules(DEFAULT_RULES_DIR)
    by_id = {r.id: r for r in result.rules}
    if rule_id not in by_id:
        console.print(f"[red]unknown rule id {rule_id!r}[/red]")
        raise typer.Exit(code=2)
    rule = by_id[rule_id]

    with Embedder() as embedder:
        query_vec = embedder.embed_query(rule.example_vulnerable)
    language = next((lang for lang in rule.languages if lang != "any"), "python")
    with RulesStore() as store:
        retrieved = store.query_similar(query_vec, language, rule.risk_categories, k=k)

    rank = next((i + 1 for i, r in enumerate(retrieved) if r.rule_id == rule_id), None)
    for i, r in enumerate(retrieved[:5], start=1):
        marker = "→" if r.rule_id == rule_id else " "
        console.print(f"{marker} {i:>2}. {r.score:.3f}  {r.rule_id}")
    if rank is None:
        console.print(f"[red]FAIL: {rule_id} not in top-{k} for its own vulnerable example[/red]")
        raise typer.Exit(code=1)
    console.print(f"[green]OK: {rule_id} self-retrieves at rank {rank}/{k}[/green]")


@rules_app.command("validate")
def rules_validate(rules_dir: RulesDirOption = DEFAULT_RULES_DIR) -> None:
    """Validate every rule file; exit nonzero on any schema error."""
    result = load_rules(rules_dir)
    for err in result.errors:
        console.print(f"[red]invalid[/red] {err}")
    console.print(f"{len(result.rules)} valid, {len(result.errors)} invalid")
    if result.errors:
        raise typer.Exit(code=1)


@app.command()
def review(
    target: Annotated[str, typer.Argument(help="Local directory or git URL to review.")],
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Report output directory.")
    ] = Path("./sentinel-report"),
    format: Annotated[
        str, typer.Option("--format", help="Report format: json, md, or both.")
    ] = "both",
    language: Annotated[
        str | None,
        typer.Option(
            "--language",
            help="Comma-separated language filter (python,javascript,typescript,csharp).",
        ),
    ] = None,
    severity: Annotated[
        str | None,
        typer.Option(
            "--severity",
            help="Severity filter: a single value means that severity and above "
            "(e.g. 'high'); a comma list selects exactly those severities.",
        ),
    ] = None,
    dashboard: Annotated[
        bool | None,
        typer.Option(
            "--dashboard/--no-dashboard",
            help="Open the live dashboard. Default: on for an interactive terminal, "
            "off when output is piped or SENTINEL_DASHBOARD=0.",
        ),
    ] = None,
) -> None:
    """Review a repository and write report.json / report.md / metrics.json."""
    import asyncio
    import logging
    import os
    import sys

    from sentinel.graph.runner import review_target
    from sentinel.ingest.walker import EXTENSION_LANGUAGES, IngestError
    from sentinel.report.builder import SEVERITY_ORDER, build_report
    from sentinel.report.json_writer import write_json_report, write_metrics
    from sentinel.report.markdown_writer import write_markdown_report

    if format not in ("json", "md", "both"):
        console.print(f"[red]invalid --format {format!r}; use json, md, or both[/red]")
        raise typer.Exit(code=2)

    languages: set[str] | None = None
    if language:
        languages = {part.strip().lower() for part in language.split(",") if part.strip()}
        known = set(EXTENSION_LANGUAGES.values())
        unknown = languages - known
        if unknown:
            console.print(
                f"[red]unknown languages {sorted(unknown)}; supported: {sorted(known)}[/red]"
            )
            raise typer.Exit(code=2)

    # C#/Razor review is beta and its known failure mode is the silent one: a
    # real finding discarded by the applicability gate, which reads as a clean
    # file. Say so before the run rather than only in docs, so nobody reads an
    # empty C# report as an all-clear. --language is the off switch.
    if languages is None or "csharp" in languages:
        console.print(
            "[yellow]note[/yellow] C#/Razor review is beta — see docs/known-issues.md. "
            "A clean C# report is not evidence of no vulnerability. "
            "Exclude it with [dim]--language python,javascript,typescript[/dim]."
        )

    severities: set[str] | None = None
    if severity:
        parts = [p.strip().lower() for p in severity.split(",") if p.strip()]
        unknown = set(parts) - set(SEVERITY_ORDER)
        if unknown:
            console.print(f"[red]unknown severities {sorted(unknown)}; use {SEVERITY_ORDER}[/red]")
            raise typer.Exit(code=2)
        if len(parts) == 1:
            # threshold semantics: this severity and above
            cutoff = SEVERITY_ORDER.index(parts[0])
            severities = set(SEVERITY_ORDER[: cutoff + 1])
        else:
            severities = set(parts)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)

    # A review is a long silence on a terminal, so show the pipeline while it
    # works. Never unasked-for, though: a piped or redirected run is a script or
    # a CI job, and spawning a browser there is a surprise, not a courtesy.
    # Explicit --dashboard overrides the sniff in both directions.
    show_dashboard = dashboard
    if show_dashboard is None:
        show_dashboard = sys.stdout.isatty() and os.environ.get(
            "SENTINEL_DASHBOARD", ""
        ).strip().lower() not in {"0", "false", "no"}
    if show_dashboard:
        from sentinel.dashboard import ensure_running, open_browser

        url = ensure_running(reports_dir=output)
        if url:
            console.print(f"[dim]dashboard[/dim] {url}")
            if dashboard is True or sys.stdout.isatty():
                open_browser(url)

    try:
        run = asyncio.run(review_target(target, languages))
    except IngestError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc

    report = build_report(run, severities)
    written: list[Path] = []
    if format in ("json", "both"):
        written.append(write_json_report(report, output))
    if format in ("md", "both"):
        written.append(write_markdown_report(report, output))
    written.append(write_metrics(run.metrics, run.wall_seconds, output))

    summary = report["summary"]
    console.print(
        f"\n[bold]{summary['findings']} finding(s)[/bold] across "
        f"{summary['files_reviewed']} file(s) in {run.wall_seconds}s — "
        f"{summary['suppressed_candidates']} suppressed, "
        f"{summary['rejected_inputs']} rejected input(s)"
    )
    unadjudicated = summary.get("judge_unavailable", 0)
    if unadjudicated:
        console.print(
            f"[bold yellow]WARNING:[/bold yellow] the judge did not answer for "
            f"{unadjudicated} candidate(s). They are quarantined in "
            f"unadjudicated_candidates, NOT judged unfounded. This run is "
            f"incomplete; real vulnerabilities may be missing."
        )
    for path in written:
        console.print(f"  wrote {path}")
    errored = summary["file_status_counts"].get("error", 0)
    if errored:
        console.print(f"[yellow]{errored} file(s) errored during review — see report[/yellow]")
        raise typer.Exit(code=3)
    # An incomplete review must not look like a clean one to automation. Exit 3
    # already means "a file errored"; this is the distinct "the review ran but
    # some candidates were never adjudicated" case.
    if unadjudicated:
        raise typer.Exit(code=4)


@app.command()
def dashboard(
    port: Annotated[
        int, typer.Option("--port", help="Loopback port to serve on.")
    ] = 8200,
    reports: Annotated[
        str | None,
        typer.Option(
            "--reports",
            help="Directory to scan for report.json (default ./sentinel-report).",
        ),
    ] = None,
) -> None:
    """Serve the local observability dashboard: pipeline, models, runs, logs.

    Read-only and loopback-only. Nothing here can start, stop, or reconfigure a
    backend, and the bind address goes through the same air-gap check the model
    clients use.
    """
    from pathlib import Path as _Path

    from sentinel.dashboard import serve

    serve(port=port, reports_dir=_Path(reports) if reports else None)


@app.command()
def status(
    backends_only: Annotated[
        bool,
        typer.Option(
            "--backends-only",
            help="Diagnostic mode: exit code ignores the gateway (pre-M4 bring-up).",
        ),
    ] = False,
) -> None:
    """Show health of the model backends and the LiteLLM gateway.

    All review traffic routes through the gateway, so a dead proxy fails
    the check by default; --backends-only is for raw backend bring-up."""
    import httpx

    from sentinel.models.registry import load_registry

    registry = load_registry()
    table = Table(title="Sentinel backends")
    table.add_column("alias", style="cyan")
    table.add_column("role")
    table.add_column("port")
    table.add_column("status")

    all_up = True
    for alias, model in registry.models.items():
        try:
            httpx.get(f"http://127.0.0.1:{model.port}/health", timeout=3).raise_for_status()
            state = "[green]healthy[/green]"
        except httpx.HTTPError:
            state = "[red]down[/red]"
            all_up = False
        table.add_row(alias, model.role, str(model.port), state)

    try:
        httpx.get("http://127.0.0.1:8100/health/liveliness", timeout=3).raise_for_status()
        gateway_state = "[green]healthy[/green]"
    except httpx.HTTPError:
        gateway_state = "[red]down[/red]"
        if not backends_only:
            all_up = False
    table.add_row("gateway", "LiteLLM proxy", "8100", gateway_state)

    console.print(table)
    if not all_up:
        raise typer.Exit(code=1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
