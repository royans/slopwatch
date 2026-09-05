"""
FlagThis Sentinel Command Line Interface (CLI).

Interactive terminal commands for syncing registry catalogs, generating
long-tail watchlists, polling real-time streams, and linting lockfiles.
"""

import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple


import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from sentinel.core.dto import Ecosystem, WatchlistState, ThreatVerdict
from sentinel.core.config import Settings
from sentinel.db.engine import DatabaseManager
from sentinel.db.repository import SentinelRepository
from sentinel.adapters import get_adapter
from sentinel.matrix.generator import generate_ecosystem_candidates, filter_unregistered_candidates
from sentinel.sentinel.monitor import InboundTripwireMonitor
from sentinel.linter.lockfile import DependencyLinter
from sentinel.assessor.scorer import ProgressiveThreatEvaluator
from sentinel.exporter.flagthis import FlagThisExporter


console = Console()


def get_db_and_repo() -> DatabaseManager:
    """
    Construct a DatabaseManager honoring config/config.yaml and the SENTINEL_DATABASE_URL
    env var override via Settings.load(). Previously every CLI command called
    DatabaseManager() directly with its hardcoded default path, silently ignoring
    Settings.load() — config/config.yaml's storage.database_url was dead configuration.
    """
    settings = Settings.load()
    return DatabaseManager(database_url=settings.storage.database_url, wal_mode=settings.storage.wal_mode)


def get_job_queue_manager():
    """
    Construct a JobQueueManager pointed at the same database as get_db_and_repo().
    JobQueueManager() with no args defaults to a hardcoded relative "data/sentinel.db"
    (it uses a raw sqlite3 connection, entirely bypassing Settings/config) — so every
    queue/reprocess CLI command silently operated on the wrong file whenever invoked
    from a working directory other than the repo root.
    """
    from sentinel.scheduler.jobs import JobQueueManager

    settings = Settings.load()
    db_url = settings.storage.database_url
    prefix = "sqlite+aiosqlite:///"
    raw_path = db_url[len(prefix):] if db_url.startswith(prefix) else "data/sentinel.db"
    return JobQueueManager(db_path=Path(raw_path))


@click.group()
def cli():
    """🛡️ FlagThis Sentinel: Multi-Ecosystem AI Package Squatting Detection."""
    pass


@cli.command("sync-index")
@click.option("--ecosystem", type=click.Choice(["pypi", "npm", "all"]), default="pypi", help="Registry ecosystem to sync")
def sync_index_cmd(ecosystem: str):
    """📥 Download and sync full registered package catalog from upstream registries."""
    async def _run():
        db = get_db_and_repo()
        await db.init_db()

        ecosystems = [Ecosystem.PYPI, Ecosystem.NPM] if ecosystem == "all" else [Ecosystem(ecosystem)]

        for eco in ecosystems:
            console.print(f"\n[cyan]Fetching full catalog for [bold]{eco.value.upper()}[/bold]...[/cyan]")
            adapter = get_adapter(eco)
            try:
                names = await adapter.fetch_full_catalog()
                console.print(f"✨ Downloaded [green]{len(names):,}[/green] package names from {eco.value.upper()}.")

                async with db.get_session() as session:
                    repo = SentinelRepository(session)
                    console.print(f"💾 Updating local SQLite catalog...")
                    synced = await repo.bulk_sync_registered_packages(eco, names)
                    console.print(f"✅ Successfully indexed [bold green]{synced:,}[/bold green] packages for {eco.value.upper()}.")
            except Exception as e:
                console.print(f"[bold red]❌ Error syncing {eco.value.upper()}: {e}[/bold red]")

        await db.close()

    asyncio.run(_run())


@cli.command("generate-matrix")
@click.option("--ecosystem", type=click.Choice(["pypi", "npm", "all"]), default="pypi", help="Ecosystem to generate")
@click.option("--limit", type=int, default=100000, help="Maximum combinations to generate per ecosystem")
def generate_matrix_cmd(ecosystem: str, limit: int):
    """⚡ Generate long-tail candidate matrix and compute unregistered watchlist."""
    async def _run():
        db = get_db_and_repo()
        await db.init_db()

        ecosystems = [Ecosystem.PYPI, Ecosystem.NPM] if ecosystem == "all" else [Ecosystem(ecosystem)]

        for eco in ecosystems:
            console.print(f"\n[cyan]Generating long-tail Cartesian candidate space for [bold]{eco.value.upper()}[/bold]...[/cyan]")
            candidates = generate_ecosystem_candidates(eco, limit=limit)
            console.print(f"Generated [bold cyan]{len(candidates):,}[/bold cyan] candidates across taxonomies.")

            async with db.get_session() as session:
                repo = SentinelRepository(session)
                registered_set = await repo.get_registered_names_set(eco)
                console.print(f"Comparing against [green]{len(registered_set):,}[/green] registered {eco.value.upper()} packages in RAM...")

                unregistered = filter_unregistered_candidates(candidates, registered_set)
                console.print(f"🎯 Isolated [bold yellow]{len(unregistered):,}[/bold yellow] high-risk UNREGISTERED candidates!")

                console.print("💾 Persisting watchlist into SQLite...")
                stored = await repo.bulk_upsert_watchlist(unregistered)
                console.print(f"✅ Successfully committed [bold green]{stored:,}[/bold green] watchlist candidates to SQLite.")

        await db.close()

    asyncio.run(_run())


@cli.command("backfill-install-hooks")
def backfill_install_hooks_cmd():
    """🔧 Recompute has_install_hook/has_network_socket for existing detections from stored AST flags (no re-crawl)."""
    async def _run():
        db = get_db_and_repo()
        await db.init_db()

        async with db.get_session() as session:
            repo = SentinelRepository(session)
            console.print("[cyan]Backfilling has_install_hook / has_network_socket from stored analysis flags...[/cyan]")
            stats = await repo.backfill_install_hook_flags()
            console.print(f"✅ Updated [bold green]{stats['updated']:,}[/bold green] of {stats['total_rows']:,} detections.")
            console.print(f"  • Packages with an install hook: [yellow]{stats['with_install_hook']:,}[/yellow]")
            console.print(f"  • Packages with an install-time network socket: [red]{stats['with_network_socket']:,}[/red]")

        await db.close()

    asyncio.run(_run())


@cli.command("backfill-findings")
@click.option("--batch-size", type=int, default=500, help="Detections per write batch")
def backfill_findings_cmd(batch_size: int):
    """🔧 Populate the sentinel_findings table from stored analysis_details (no re-crawl)."""
    async def _run():
        db = get_db_and_repo()
        await db.init_db()
        async with db.get_session() as session:
            repo = SentinelRepository(session)
            console.print("[cyan]Rebuilding sentinel_findings from stored analysis details...[/cyan]")
            stats = await repo.backfill_findings(batch_size=batch_size)
            console.print(
                f"✅ Wrote [bold green]{stats['findings_written']:,}[/bold green] findings "
                f"across {stats['detections_processed']:,} detections."
            )
        await db.close()

    asyncio.run(_run())


@cli.command("signals")
@click.option("--ecosystem", type=click.Choice(["pypi", "npm", "all"]), default="all", help="Ecosystem filter")
def signals_cmd(ecosystem: str):
    """📇 List the signal catalog with live package counts from sentinel_findings."""
    from rich.table import Table
    from sentinel.core.signals import SIGNAL_CATALOG

    async def _run():
        db = get_db_and_repo()
        await db.init_db()
        eco = None if ecosystem == "all" else Ecosystem(ecosystem)
        async with db.get_session() as session:
            repo = SentinelRepository(session)
            stats = {s["signal_code"]: s for s in await repo.get_signal_stats(ecosystem=eco)}
        await db.close()

        table = Table(title=f"Signal Catalog ({ecosystem})", show_lines=False)
        table.add_column("code", style="cyan", no_wrap=True)
        table.add_column("category")
        table.add_column("sev")
        table.add_column("pkgs", justify="right", style="yellow")
        table.add_column("exec", justify="center")
        table.add_column("gates", justify="center")
        for code, spec in sorted(SIGNAL_CATALOG.items(), key=lambda kv: (kv[1].category, kv[0])):
            st = stats.get(code, {})
            table.add_row(
                code, spec.category, spec.severity,
                f"{st.get('package_count', 0):,}",
                "✓" if spec.is_code_execution else "",
                "🚨" if spec.gates_malicious else "",
            )
        console.print(table)
        uncatalogued = sorted(set(stats) - set(SIGNAL_CATALOG))
        if uncatalogued:
            console.print(f"\n[dim]Uncatalogued signal codes seen in data: {', '.join(uncatalogued)}[/dim]")

    asyncio.run(_run())


@cli.command("mark-grammar-matches")
@click.option("--ecosystem", type=click.Choice(["pypi", "npm", "all"]), default="pypi", help="Ecosystem to flag")
@click.option("--limit", type=int, default=500000, help="Candidate matrix limit for grammar generation")
def mark_grammar_matches_cmd(ecosystem: str, limit: int):
    """🎯 Flag registered packages matching the combinatorial naming grammar (scopes the historical backfill crawl tier)."""
    async def _run():
        db = get_db_and_repo()
        await db.init_db()

        ecosystems = [Ecosystem.PYPI, Ecosystem.NPM] if ecosystem == "all" else [Ecosystem(ecosystem)]

        for eco in ecosystems:
            console.print(f"\n[cyan]Generating naming-grammar candidate space for [bold]{eco.value.upper()}[/bold]...[/cyan]")
            async with db.get_session() as session:
                repo = SentinelRepository(session)
                updated = await repo.mark_grammar_matching_packages(eco, candidate_limit=limit)
                console.print(f"✅ Flagged [bold green]{updated:,}[/bold green] registered {eco.value.upper()} packages as grammar matches.")

        await db.close()

    asyncio.run(_run())


@cli.command("taxonomy-gap-report")
@click.option("--ecosystem", type=click.Choice(["pypi", "npm"]), default="pypi", help="Ecosystem to analyze")
@click.option("--top", "top_n", type=int, default=50, help="Number of top untracked tokens to show")
def taxonomy_gap_report_cmd(ecosystem: str, top_n: int):
    """📊 Surface popular package-name keywords not yet in the naming-grammar taxonomy — run periodically to spot expansion candidates."""
    async def _run():
        db = get_db_and_repo()
        await db.init_db()
        eco = Ecosystem(ecosystem)

        async with db.get_session() as session:
            repo = SentinelRepository(session)
            console.print(f"[cyan]Scanning {eco.value.upper()} catalog for untracked naming keywords...[/cyan]")
            results = await repo.get_taxonomy_gap_report(eco, top_n=top_n)

            table = Table(title=f"Taxonomy Gap Report: {eco.value.upper()} (top {top_n} untracked tokens)")
            table.add_column("Rank", justify="center", style="bold")
            table.add_column("Token", style="cyan")
            table.add_column("Packages Containing It", justify="right", style="yellow")

            for i, (tok, count) in enumerate(results, 1):
                table.add_row(str(i), tok, f"{count:,}")
            console.print(table)
            console.print("\n[dim]Candidates worth a human review for addition to sentinel.core.taxonomies (ENTITIES/CAPABILITIES/FRAMEWORKS).[/dim]")

        await db.close()

    asyncio.run(_run())


@cli.command("audit-catalog")
@click.option("--ecosystem", type=click.Choice(["pypi", "npm", "all"]), default="pypi", help="Ecosystem to audit")
@click.option("--limit", type=int, default=100000, help="Candidate matrix limit")
def audit_catalog_cmd(ecosystem: str, limit: int):
    """🔍 Retroactively scan registered catalog for combinatorial slopsquats."""
    async def _run():
        db = get_db_and_repo()
        await db.init_db()
        evaluator = ProgressiveThreatEvaluator(concurrency_limit=10, global_timeout_seconds=300.0)

        ecosystems = [Ecosystem.PYPI, Ecosystem.NPM] if ecosystem == "all" else [Ecosystem(ecosystem)]

        for eco in ecosystems:
            console.print(f"\n[cyan]🔍 Generating candidate space for [bold]{eco.value.upper()}[/bold]...[/cyan]")
            candidates = generate_ecosystem_candidates(eco, limit=limit)

            async with db.get_session() as session:
                repo = SentinelRepository(session)
                registered_set = await repo.get_registered_names_set(eco)

                matches = [c for c in candidates if c.normalized_name in registered_set]
                console.print(f"🎯 Discovered [bold red]{len(matches)}[/bold red] existing registered packages matching combinatorial grammar!")

                if matches:
                    console.print(f"⚡ Evaluating {len(matches)} packages through Progressive 4-Tier Scorer...")
                    detections = await evaluator.evaluate_batch_with_budget(matches)

                    console.print(f"💾 Recording {len(detections)} detections in SQLite...")
                    for d in detections:
                        await repo.record_detection(d)

                    console.print("📦 Exporting dossiers & search index for FlagThis.com...")
                    exporter = FlagThisExporter(repo)
                    stats = await exporter.export_all()
                    console.print(f"✅ Generated [green]{stats['total_dossiers_generated']}[/green] dossiers and [green]{stats['unified_search_entries']}[/green] search index entries.")

        await db.close()

    asyncio.run(_run())


@cli.command("poll")

@click.option("--ecosystem", type=click.Choice(["pypi", "npm", "all"]), default="pypi", help="Ecosystem to poll")
@click.option("--limit", type=int, default=50, help="Number of recent packages to check")
@click.option("--webhook-url", type=str, default=None, help="Webhook URL for instant alert dispatch")
def poll_cmd(ecosystem: str, limit: int, webhook_url: Optional[str]):
    """📡 Poll recent package creation stream and match against watchlist."""
    async def _run():
        db = get_db_and_repo()
        await db.init_db()

        ecosystems = [Ecosystem.PYPI, Ecosystem.NPM] if ecosystem == "all" else [Ecosystem(ecosystem)]

        for eco in ecosystems:
            console.print(f"\n[cyan]Checking recent inbound package creations on [bold]{eco.value.upper()}[/bold]...[/cyan]")
            async with db.get_session() as session:
                repo = SentinelRepository(session)
                monitor = InboundTripwireMonitor(repo)
                detections = await monitor.check_inbound_stream(eco, limit=limit, webhook_url=webhook_url)

                if detections:
                    console.print(f"\n[bold red]🚨 DETECTED {len(detections)} SLOPSQUATTING PACKAGE(S) ON {eco.value.upper()}![/bold red]")
                    table = Table(title="Recent Slopsquatting Detections")
                    table.add_column("Package Name", style="cyan")
                    table.add_column("Author", style="magenta")
                    table.add_column("Version", style="green")
                    table.add_column("Threat Score", style="bold red")
                    table.add_column("Verdict", style="bold")

                    for d in detections:
                        table.add_row(
                            d.package_name,
                            d.author_username or "unknown",
                            d.release_version,
                            f"{d.threat_score}/100",
                            d.verdict.value,
                        )
                    console.print(table)
                else:
                    console.print(f"✅ No slopsquatting matches found in the last {limit} packages on {eco.value.upper()}.")

        await db.close()

    asyncio.run(_run())


@cli.command("check")
@click.argument("file_path", type=click.Path(exists=True))
def check_cmd(file_path: str):
    """🔍 Audit requirements.txt or package.json for hallucinated dependencies."""
    async def _run():
        db = get_db_and_repo()
        await db.init_db()

        async with db.get_session() as session:
            repo = SentinelRepository(session)
            linter = DependencyLinter(repo)
            result = await linter.audit_file(Path(file_path))

            console.print(Panel(f"Audit Target: [bold]{file_path}[/bold] (Ecosystem: {result['ecosystem'].upper()})", style="cyan"))
            console.print(f"Total Dependencies Scanned: [bold]{result['total_dependencies']}[/bold]")

            if result["is_clean"]:
                console.print("\n[bold green]✅ ALL DEPENDENCIES CLEAN: No hallucinated or slopsquatted packages detected.[/bold green]")
                sys.exit(0)
            else:
                console.print(f"\n[bold red]❌ AUDIT FAILED: Found {result['flagged_count']} suspicious / hallucinated package(s)![/bold red]\n")
                table = Table(title="Flagged Dependencies")
                table.add_column("Package", style="cyan")
                table.add_column("Version", style="magenta")
                table.add_column("Severity", style="bold red")
                table.add_column("Reason", style="yellow")

                for item in result["flagged_dependencies"]:
                    table.add_row(
                        item["package"],
                        item["version"],
                        item["severity"],
                        item["reason"],
                    )
                console.print(table)
                console.print("\n[bold yellow]⚠️ Do not run installation commands until flagged dependencies are verified.[/bold yellow]")
                sys.exit(1)

        await db.close()

    asyncio.run(_run())


@cli.command("inspect")
@click.argument("package_name")
@click.option("--ecosystem", type=click.Choice(["pypi", "npm"]), default="pypi", help="Package ecosystem")
def inspect_cmd(package_name: str, ecosystem: str):
    """📦 Perform deep static AST analysis on an upstream package tarball."""
    async def _run():
        eco = Ecosystem(ecosystem)
        adapter = get_adapter(eco)
        norm_name = adapter.normalize_name(package_name)

        console.print(f"[cyan]Fetching metadata for [bold]{norm_name}[/bold] on {eco.value.upper()}...[/cyan]")
        meta = await adapter.inspect_package_metadata(norm_name)
        if not meta:
            console.print(f"[bold red]❌ Package '{norm_name}' not found on {eco.value.upper()}.[/bold red]")
            return

        console.print(f"Author: [magenta]{meta.author or 'Unknown'}[/magenta] | Latest Version: [green]{meta.latest_version}[/green]")
        console.print(f"Description: {meta.description or 'None'}")

        console.print(f"\n[cyan]Downloading payload and performing AST security analysis...[/cyan]")
        report = await adapter.download_and_inspect_payload(norm_name, meta.latest_version)

        verdict_color = "red" if report.verdict == ThreatVerdict.MALICIOUS else "yellow" if report.verdict == ThreatVerdict.SUSPICIOUS else "green"
        console.print(Panel(f"Verdict: [{verdict_color}]{report.verdict.value}[/{verdict_color}] (Threat Score: {report.composite_threat_score}/100)", style=verdict_color))

        if report.flags:
            console.print("\n[bold red]🚨 Security Flags Detected:[/bold red]")
            for f in report.flags:
                console.print(f"  • {f}")
        if report.line_details:
            console.print("\n[bold yellow]Line Breakdown:[/bold yellow]")
            for ld in report.line_details:
                console.print(f"  • {ld}")

    asyncio.run(_run())


@cli.command("triage")
@click.option("--ecosystem", type=click.Choice(["pypi", "npm", "all"]), default="pypi", help="Ecosystem to triage")
@click.option("--limit", type=int, default=25, help="Number of candidate packages to evaluate")
@click.option("--min-score", type=int, default=0, help="Minimum threat score to display")
def triage_cmd(ecosystem: str, limit: int, min_score: int):
    """🎯 Run Progressive 4-Tier Investigation & Rank Suspicious Packages by Risk."""
    async def _run():
        db = get_db_and_repo()
        await db.init_db()

        ecosystems = [Ecosystem.PYPI, Ecosystem.NPM] if ecosystem == "all" else [Ecosystem(ecosystem)]
        evaluator = ProgressiveThreatEvaluator(concurrency_limit=10, global_timeout_seconds=300.0)

        for eco in ecosystems:
            console.print(f"\n[cyan]Starting Progressive Investigation for [bold]{eco.value.upper()}[/bold] (Max 5 mins)...[/cyan]")
            async with db.get_session() as session:
                repo = SentinelRepository(session)
                watchlist_names = list(await repo.get_watchlist_names_set(eco))[:limit]

                if not watchlist_names:
                    console.print(f"ℹ️ No watchlist items found for {eco.value.upper()}. Run [cyan]sentinel generate-matrix[/cyan] first.")
                    continue

                candidates = [await repo.get_candidate_by_name(eco, name) for name in watchlist_names]
                valid_candidates = [c for c in candidates if c is not None]

                console.print(f"Evaluating [bold cyan]{len(valid_candidates)}[/bold cyan] candidates across Tier 1 -> Tier 2 -> Tier 3...")
                detections = await evaluator.evaluate_batch_with_budget(valid_candidates)

                filtered_detections = [d for d in detections if d.threat_score >= min_score]

                table = Table(title=f"🎯 Ranked Triage Risk Queue: {eco.value.upper()} ({len(filtered_detections)} evaluated)")
                table.add_column("Rank", justify="center", style="bold")
                table.add_column("Package Name", style="cyan")
                table.add_column("Score", justify="right", style="bold red")
                table.add_column("Verdict", style="bold")
                table.add_column("Entity", style="magenta")
                table.add_column("Author / Org", style="green")
                table.add_column("Key Signals", style="yellow")

                for i, d in enumerate(filtered_detections, 1):
                    verdict_style = (
                        "bold red" if d.verdict == ThreatVerdict.MALICIOUS
                        else "yellow" if d.verdict == ThreatVerdict.SUSPICIOUS
                        else "bold green" if d.verdict == ThreatVerdict.VERIFIED_OFFICIAL
                        else "blue" if d.verdict == ThreatVerdict.SQUATTED_STUB
                        else "green"
                    )
                    signals = [s.get("name", "") for s in d.analysis_details.get("signals", [])][:2]
                    signal_str = ", ".join(signals) if signals else d.analysis_details.get("verdict_reason", "None")

                    table.add_row(
                        str(i),
                        d.package_name,
                        f"{d.threat_score}/100",
                        f"[{verdict_style}]{d.verdict.value}[/{verdict_style}]",
                        d.analysis_details.get("entity", "-"),
                        d.author_username or "unregistered",
                        signal_str,
                    )

                console.print(table)
                console.print(f"\n[green]✅ Progressive evaluation finished inside execution budget.[/green]")

        await db.close()

    asyncio.run(_run())


@cli.command("run-cycle")
@click.option("--timeout", type=int, default=300, help="Global cycle timeout in seconds (default: 300s)")
@click.option("--webhook-url", type=str, default=None, help="Webhook URL for alert dispatch")
@click.option("--output-dir", type=click.Path(), default="reports/flagthis_export", help="FlagThis export directory")
def run_cycle_cmd(timeout: int, webhook_url: Optional[str], output_dir: str):
    """🔄 Run Complete Automated Sentinel Cron Cycle (Stream Ingestion -> AST -> Export)."""
    async def _run():
        db = get_db_and_repo()
        await db.init_db()
        start_time = datetime.now(timezone.utc)
        console.print(f"[bold cyan]🚀 Starting Sentinel Automated Cron Cycle at {start_time.isoformat()}...[/bold cyan]")

        total_detections = 0
        async with db.get_session() as session:
            repo = SentinelRepository(session)
            monitor = InboundTripwireMonitor(repo)

            for eco in [Ecosystem.PYPI, Ecosystem.NPM]:
                try:
                    console.print(f"📡 Polling inbound stream for [bold]{eco.value.upper()}[/bold]...")
                    detections = await monitor.check_inbound_stream(eco, limit=50, webhook_url=webhook_url)
                    total_detections += len(detections)
                    if detections:
                        console.print(f"🚨 Flagged [bold red]{len(detections)}[/bold red] slopsquat package(s) on {eco.value.upper()}!")
                    else:
                        console.print(f"✅ Stream clean for {eco.value.upper()}.")
                except Exception as e:
                    console.print(f"[yellow]⚠️ Warning polling {eco.value.upper()}: {e}[/yellow]")

            # Auto-export dossiers & search index for FlagThis.com
            console.print(f"📦 Synchronizing FlagThis.com static export artifacts to {output_dir}...")
            exporter = FlagThisExporter(repo, output_dir=Path(output_dir))
            stats = await exporter.export_all()
            console.print(f"✅ FlagThis export synchronized: {stats['unified_search_entries']} search records, {stats['total_dossiers_generated']} dossiers.")


        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        console.print(f"[bold green]✨ Automated Cron Cycle Completed in {elapsed:.2f}s ({total_detections} new threats detected).[/bold green]")
        await db.close()

    asyncio.run(_run())


@cli.command("cache-stats")
def cache_stats_cmd():
    """💾 Display disk cache usage and bandwidth savings."""
    from sentinel.core.cache import DiskCacheManager
    cache = DiskCacheManager()
    stats = cache.get_cache_stats()

    console.print(Panel(f"📦 Local Disk Cache Location: [bold cyan]{stats['cache_root']}[/bold cyan]", style="green"))
    console.print(f"Total Cached Files: [bold]{stats['total_files']}[/bold]")
    console.print(f"Total Disk Space Used: [bold green]{stats['total_size_mb']} MB[/bold green]")
    console.print("[dim]Bandwidth saved: Up to 100% on repeated catalog and tarball inspections.[/dim]")


@cli.command("clean-cache")
@click.option("--all", "clean_all", is_flag=True, default=False, help="Purge all caches (catalogs, metadata, and payloads)")
def clean_cache_cmd(clean_all: bool):
    """🧹 Clean up ephemeral payload archives and free disk space."""
    from sentinel.core.cache import DiskCacheManager
    cache = DiskCacheManager()
    
    if clean_all:
        purged = cache.clean_all_cache()
        console.print(f"[bold green]✨ Purged all {purged} cached file(s) from disk.[/bold green]")
    else:
        purged = cache.clean_payload_cache()
        console.print(f"[bold green]✨ Purged {purged} ephemeral payload archive(s) from disk.[/bold green]")

    stats = cache.get_cache_stats()
    console.print(f"Current disk cache size: [bold cyan]{stats['total_size_mb']} MB[/bold cyan] ({stats['total_files']} files remaining).")



@cli.command("advisory")



@click.option("--brand", required=True, help="Brand or Entity name (e.g. Okta, Stripe, Azure)")
@click.option("--ecosystem", type=click.Choice(["pypi", "npm", "all"]), default="all", help="Ecosystem")
def advisory_cmd(brand: str, ecosystem: str):
    """🛡️ Generate Preemptive Brand Package Registration Checklist."""
    async def _run():
        db = get_db_and_repo()
        await db.init_db()

        norm_brand = brand.strip().lower()
        ecosystems = [Ecosystem.PYPI, Ecosystem.NPM] if ecosystem == "all" else [Ecosystem(ecosystem)]

        console.print(Panel(f"🛡️ Preemptive Package Claim Advisory for: [bold cyan]{brand}[/bold cyan]", style="green"))

        for eco in ecosystems:
            candidates = generate_ecosystem_candidates(eco, entities=[norm_brand], limit=100)
            async with db.get_session() as session:
                repo = SentinelRepository(session)
                registered_set = await repo.get_registered_names_set(eco)
                unregistered = filter_unregistered_candidates(candidates, registered_set)

                console.print(f"\n[bold]{eco.value.upper()}[/bold] High-Risk Unclaimed Candidates ({len(unregistered)}):")
                table = Table()
                table.add_column("Unclaimed Package Name", style="cyan")
                table.add_column("Entity", style="magenta")
                table.add_column("Capability", style="yellow")
                table.add_column("Framework", style="green")
                table.add_column("Risk Weight", style="bold red")

                for c in sorted(unregistered, key=lambda x: x.risk_weight, reverse=True)[:15]:
                    table.add_row(
                        c.normalized_name,
                        c.entity_token,
                        c.capability_token,
                        c.framework_token,
                        f"{c.risk_weight}/100",
                    )
                console.print(table)

        await db.close()

    asyncio.run(_run())


@cli.command("export-flagthis")
@click.option("--output-dir", type=click.Path(), default="reports/flagthis_export", help="Output directory")
def export_flagthis_cmd(output_dir: str):
    """🚀 Export static search index and Markdown dossiers for FlagThis.com."""
    async def _run():
        db = get_db_and_repo()
        await db.init_db()

        console.print(f"[cyan]Exporting FlagThis.com search index & Markdown dossiers to: [bold]{output_dir}[/bold]...[/cyan]")
        async with db.get_session() as session:
            repo = SentinelRepository(session)
            exporter = FlagThisExporter(repo, output_dir=Path(output_dir))
            stats = await exporter.export_all()

            console.print(f"✅ Generated [green]{stats['total_dossiers_generated']}[/green] Markdown dossiers.")
            console.print(f"✅ Generated unified search index with [green]{stats['unified_search_entries']}[/green] records.")
            console.print(f"  • PyPI index: [cyan]{stats['pypi_search_entries']}[/cyan] packages")
            console.print(f"  • npm index: [magenta]{stats['npm_search_entries']}[/magenta] packages")
            console.print(f"✅ Generated rolling JSON feed with [green]{stats['feed_entries']}[/green] entries.")
            console.print(f"  • Skipped BENIGN_COMMUNITY (no signal): [yellow]{stats['skipped_benign_count']}[/yellow]")
            if stats["cleaned_stale_dossiers_count"]:
                console.print(f"  • Cleaned up stale dossier files: [yellow]{stats['cleaned_stale_dossiers_count']}[/yellow]")


        await db.close()

    asyncio.run(_run())


@cli.command("report")
@click.option("--limit", type=int, default=50, help="Maximum detections to display")
def report_cmd(limit: int):
    """📊 View recent slopsquatting threat detections table."""
    async def _run():
        db = get_db_and_repo()
        await db.init_db()

        async with db.get_session() as session:
            repo = SentinelRepository(session)
            detections = await repo.list_detections(limit=limit)

            if not detections:
                console.print("ℹ️ No slopsquatting detections recorded yet. Run [cyan]sentinel poll[/cyan] to check feeds.")
                return

            table = Table(title=f"FlagThis Sentinel: Slopsquatting Detections ({len(detections)})")
            table.add_column("Package Name", style="cyan")
            table.add_column("Eco", style="magenta")
            table.add_column("Author", style="yellow")
            table.add_column("Threat Score", style="bold red")
            table.add_column("Verdict", style="bold")
            table.add_column("Published", style="green")

            for d in detections:
                table.add_row(
                    d.package_name,
                    d.ecosystem.value.upper(),
                    d.author_username or "unknown",
                    f"{d.threat_score}/100",
                    d.verdict.value,
                    d.published_at.strftime("%Y-%m-%d %H:%M"),
                )
            console.print(table)

        await db.close()

    asyncio.run(_run())


@cli.command("crawl-cycle")
@click.option("--limit", type=int, default=100, help="Number of packages to inspect in this cycle")
@click.option("--npm-limit", type=int, default=10, help="Number of npm packages to inspect per cycle (default: 10)")
@click.option("--brands", type=str, default=None, help="Comma-separated target brands (defaults to all top AI & high-risk brands)")
@click.option("--concurrency", type=int, default=8, help="Max concurrent package evaluations (default: 8)")
def crawl_cycle_cmd(limit: int, npm_limit: int, brands: Optional[str], concurrency: int):
    """🔄 Run a prioritized crawl and freshness re-audit cycle."""
    async def _run():
        from sentinel.scheduler.worker import ContinuousCrawlerWorker

        db = get_db_and_repo()
        await db.init_db()

        brand_list = [b.strip() for b in brands.split(",") if b.strip()] if brands else None
        brand_count_str = str(len(brand_list)) if brand_list else "all priority AI & cloud brands"
        console.print(f"[cyan]Starting priority crawl cycle (limit: [bold]{limit}[/bold], npm_limit: [bold]{npm_limit}[/bold], concurrency: [bold]{concurrency}[/bold], brands: [bold]{brand_count_str}[/bold])...[/cyan]")

        async with db.get_session() as session:
            repo = SentinelRepository(session)
            worker = ContinuousCrawlerWorker(repository=repo, concurrency_limit=concurrency)
            result = await worker.run_crawl_cycle(batch_size=limit, npm_limit=npm_limit, target_brands=brand_list)

            console.print(f"✨ Completed crawl cycle in [bold green]{result['duration_seconds']}s[/bold green]:")
            console.print(f"  • Tasks Collected: [cyan]{result['tasks_collected']}[/cyan] (PyPI: [green]{result['breakdown'].get('pypi_tasks', 0)}[/green], npm: [magenta]{result['breakdown'].get('npm_tasks', 0)}[/magenta])")
            console.print(f"  • Inbound Releases: [yellow]{result['breakdown']['inbound_new']}[/yellow]")
            console.print(f"  • Brand Targets: [red]{result['breakdown']['brand_watchlist']}[/red]")
            console.print(f"  • Freshness Re-audits: [magenta]{result['breakdown']['freshness_reaudits']}[/magenta]")
            console.print(f"  • Historical Backfill: [blue]{result['breakdown']['historical_backfill']}[/blue]")
            console.print(f"  • Detections Saved/Updated: [bold green]{result['detections_recorded']}[/bold green]")

        await db.close()

    asyncio.run(_run())


@cli.command("queue-recalc")
@click.option("--ecosystem", type=click.Choice(["pypi", "npm", "all"]), default="all", help="Ecosystem to queue")
@click.option("--job-type", type=str, default="RECALCULATE_SCORE", help="Job type (default: RECALCULATE_SCORE)")
@click.option("--priority", type=int, default=100, help="Priority (default: 100)")
def queue_recalc_cmd(ecosystem: str, job_type: str, priority: int):
    """📋 Bulk enqueue detection records into persistent job queue for incremental processing."""

    queue_mgr = get_job_queue_manager()
    eco = None if ecosystem == "all" else Ecosystem(ecosystem)
    enqueued = queue_mgr.enqueue_recalc_jobs(ecosystem=eco, job_type=job_type, priority=priority)

    console.print(Panel(
        f"✅ Successfully enqueued [bold green]{enqueued:,}[/bold green] jobs of type [bold cyan]{job_type}[/bold cyan] into persistent queue.",
        style="green"
    ))
    summary = queue_mgr.get_queue_summary()
    console.print(f"Current Queue State: [yellow]{summary['PENDING']:,}[/yellow] PENDING | [cyan]{summary['IN_PROGRESS']:,}[/cyan] IN_PROGRESS | [green]{summary['COMPLETED']:,}[/green] COMPLETED | [red]{summary['FAILED']:,}[/red] FAILED")


@cli.command("process-queue")
@click.option("--time-budget-seconds", type=float, default=60.0, help="Maximum execution time budget in seconds (default: 60s)")
@click.option("--batch-size", type=int, default=25, help="Batch size per lease (default: 25)")
@click.option("--concurrency", type=int, default=5, help="Concurrency limit (default: 5)")
@click.option("--job-type", type=str, default=None, help="Filter by job type")
def process_queue_cmd(time_budget_seconds: float, batch_size: int, concurrency: int, job_type: Optional[str]):
    """⚡ Process queued jobs within a strict time budget and auto-resume on subsequent runs."""
    async def _run():
    
        queue_mgr = get_job_queue_manager()
        console.print(Panel(
            f"⚡ Running Persistent Queue Processor\n"
            f"• Time Budget: [bold cyan]{time_budget_seconds:.1f}s[/bold cyan] | Batch Size: [bold]{batch_size}[/bold] | Concurrency: [bold]{concurrency}[/bold]",
            style="cyan"
        ))

        res = await queue_mgr.process_queue_with_budget(
            time_budget_seconds=time_budget_seconds,
            batch_size=batch_size,
            concurrency=concurrency,
            job_type=job_type,
        )

        console.print(f"\n✨ Worker Run Finished in [bold green]{res['elapsed_seconds']}s[/bold green]:")
        console.print(f"  • Processed in Run: [bold cyan]{res['processed_in_run']:,}[/bold cyan]")
        console.print(f"  • Completed in Run: [bold green]{res['completed_in_run']:,}[/bold green]")
        console.print(f"  • Failed in Run: [bold red]{res['failed_in_run']:,}[/bold red]")
        console.print(f"  • Remaining PENDING: [bold yellow]{res['PENDING']:,}[/bold yellow]")

    asyncio.run(_run())


@cli.command("queue-status")
def queue_status_cmd():
    """📊 Display real-time status and statistics of the persistent job queue."""

    queue_mgr = get_job_queue_manager()
    summary = queue_mgr.get_queue_summary()

    table = Table(title="FlagThis Sentinel: Persistent Job Queue Status")
    table.add_column("Status", style="bold")
    table.add_column("Count", justify="right", style="cyan")
    table.add_column("Description", style="dim")

    table.add_row("PENDING", f"{summary['PENDING']:,}", "Waiting to be processed")
    table.add_row("  ├─ Fresh Network Pull", f"{summary.get('PENDING_FRESH_NETWORK', 0):,}", "Bypasses disk cache to pull fresh registry metadata/tarball")
    table.add_row("  └─ Local Re-score", f"{summary.get('PENDING_LOCAL_RESCORE', 0):,}", "Fast algorithmic re-scoring using existing payload")
    table.add_row("IN_PROGRESS", f"{summary['IN_PROGRESS']:,}", "Currently leased by an active worker")
    table.add_row("COMPLETED", f"{summary['COMPLETED']:,}", "Successfully processed and saved to database")
    table.add_row("FAILED", f"{summary['FAILED']:,}", "Exceeded maximum retry attempts")
    table.add_row("TOTAL", f"[bold]{summary['TOTAL']:,}[/bold]", "Total tracked jobs across all states")

    console.print(table)


@cli.command("flag-reprocess")
@click.option("--all", "flag_all", is_flag=True, default=False, help="Flag all existing packages in squat_detections")
@click.option("--pkg", "package_name", type=str, default=None, help="Specific package name to flag")
@click.option("--ecosystem", type=click.Choice(["pypi", "npm", "all"]), default="all", help="Ecosystem filter")
@click.option("--verdict", type=str, default=None, help="Filter by verdict (MALICIOUS, SUSPICIOUS, SQUATTED_STUB, BENIGN_COMMUNITY)")
@click.option("--min-score", type=int, default=None, help="Only flag rows with threat_score >= this value (e.g. 90, 100)")
@click.option("--max-age-days", type=int, default=None, help="Only flag rows first published within the last N days")
@click.option("--keyword", "keywords", type=str, multiple=True, help="Audit rows mentioning this term (name or analysis details); repeatable, OR-matched. E.g. --keyword anthropic")
@click.option("--fresh-network", is_flag=True, default=False, help="Force fresh registry metadata & tarball pull (bypasses cache)")
@click.option("--priority", type=int, default=100, help="Reprocess priority (higher = processed first, e.g. 500)")
@click.option("--reason", type=str, default="MANUAL_REQUEST", help="Reason tag for audit log")
@click.option("--unprocessed-only", is_flag=True, default=False, help="Only flag packages that are currently unprocessed or not completed in queue")
@click.option("--dry-run", is_flag=True, default=False, help="Show how many rows would be flagged without writing anything")
def flag_reprocess_cmd(flag_all: bool, package_name: Optional[str], ecosystem: str, verdict: Optional[str], min_score: Optional[int], max_age_days: Optional[int], keywords: Tuple[str, ...], fresh_network: bool, priority: int, reason: str, unprocessed_only: bool, dry_run: bool):
    """🚩 Flag packages for prioritized reprocessing and schedule into persistent queue.

    Bulk filters (--all / --verdict / --min-score / --max-age-days / --keyword) combine with AND
    (multiple --keyword values OR together). Examples:
      sentinel flag-reprocess --min-score 90 --max-age-days 7   # recent high-risk
      sentinel flag-reprocess --min-score 100                   # whole high band
      sentinel flag-reprocess --keyword anthropic               # everything mentioning anthropic
      sentinel flag-reprocess --verdict MALICIOUS --dry-run     # preview only
    """

    queue_mgr = get_job_queue_manager()
    eco = None if ecosystem == "all" else Ecosystem(ecosystem)
    kw_list = [k for k in keywords if k and k.strip()]
    has_bulk_filter = flag_all or bool(verdict) or min_score is not None or max_age_days is not None or bool(kw_list) or unprocessed_only

    if package_name:
        if dry_run:
            console.print(f"[dim]--dry-run has no effect with --pkg; not flagging {package_name}.[/dim]")
            return
        count = queue_mgr.flag_package_for_reprocess(
            package_name=package_name,
            ecosystem=eco,
            refresh_network=fresh_network,
            priority=priority,
            reason=reason,
        )
        if count:
            console.print(f"✅ Successfully flagged [bold cyan]{package_name}[/bold cyan] for reprocessing (priority: {priority}, fresh_network: {fresh_network}).")
        else:
            console.print(f"[yellow]⚠️ Package '{package_name}' not found in squat_detections.[/yellow]")
    elif has_bulk_filter:
        count = queue_mgr.bulk_flag_for_reprocess(
            ecosystem=eco,
            verdict=verdict,
            refresh_network=fresh_network,
            priority=priority,
            reason=reason,
            min_score=min_score,
            max_age_days=max_age_days,
            keywords=kw_list or None,
            unprocessed_only=unprocessed_only,
            dry_run=dry_run,
        )
        if dry_run:
            console.print(f"[cyan]🔎 Dry run:[/cyan] [bold]{count:,}[/bold] package(s) match "
                          f"(ecosystem={ecosystem}, verdict={verdict}, min_score={min_score}, max_age_days={max_age_days}, keywords={list(kw_list) or None}). Nothing was written.")
        else:
            console.print(f"✅ Successfully flagged [bold green]{count:,}[/bold green] package(s) for reprocessing "
                          f"(priority: {priority}, fresh_network: {fresh_network}, reason: {reason}).")
    else:
        console.print("[bold red]❌ Please specify --pkg <name>, --all, --verdict <type>, --min-score <n>, --max-age-days <n>, or --keyword <term>.[/bold red]")


@cli.command("run-reprocess")
@click.option("--time-budget-seconds", type=float, default=60.0, help="Maximum execution time budget in seconds (default: 60s)")
@click.option("--batch-size", type=int, default=25, help="Batch size per lease (default: 25)")
@click.option("--concurrency", type=int, default=5, help="Concurrency limit (default: 5)")
def run_reprocess_cmd(time_budget_seconds: float, batch_size: int, concurrency: int):
    """⚡ Execute prioritized reprocessing pipeline within time budget."""
    async def _run():
    
        queue_mgr = get_job_queue_manager()
        console.print(Panel(
            f"⚡ Prioritized Reprocessing Pipeline\n"
            f"• Time Budget: [bold cyan]{time_budget_seconds:.1f}s[/bold cyan] | Batch Size: [bold]{batch_size}[/bold] | Concurrency: [bold]{concurrency}[/bold]",
            style="cyan"
        ))

        res = await queue_mgr.process_queue_with_budget(
            time_budget_seconds=time_budget_seconds,
            batch_size=batch_size,
            concurrency=concurrency,
        )

        console.print(f"\n✨ Reprocess Run Finished in [bold green]{res['elapsed_seconds']}s[/bold green]:")
        console.print(f"  • Processed in Run: [bold cyan]{res['processed_in_run']:,}[/bold cyan]")
        console.print(f"  • Completed in Run: [bold green]{res['completed_in_run']:,}[/bold green]")
        console.print(f"  • Failed in Run: [bold red]{res['failed_in_run']:,}[/bold red]")
        console.print(f"  • Remaining PENDING: [bold yellow]{res['PENDING']:,}[/bold yellow]")

    asyncio.run(_run())


@cli.command("reprocess-status")
def reprocess_status_cmd():
    """📊 View status of flagged rows and queue priority distribution."""

    queue_mgr = get_job_queue_manager()
    status = queue_mgr.get_reprocessing_status()

    table = Table(title="FlagThis Sentinel: Reprocessing Infrastructure Status")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right", style="cyan")
    table.add_column("Details", style="dim")

    table.add_row("Total Flagged in DB", f"[bold yellow]{status['total_flagged_for_reprocess']:,}[/bold yellow]", "Rows with needs_reprocess = 1")
    table.add_row("  ├─ Fresh Network Pull", f"{status['flagged_fresh_network_pull']:,}", "Requires cache invalidation & remote payload download")
    table.add_row("  └─ Local Re-score Only", f"{status['flagged_local_rescore_only']:,}", "Uses cached AST & facts for rapid heuristic re-scoring")
    table.add_row("Queue Pending", f"{status['job_queue']['PENDING']:,}", "Jobs waiting in persistent queue")
    table.add_row("Queue In Progress", f"{status['job_queue']['IN_PROGRESS']:,}", "Currently leased by worker")
    table.add_row("Queue Completed", f"[bold green]{status['job_queue']['COMPLETED']:,}[/bold green]", "Finished jobs")
    table.add_row("Queue Failed", f"[bold red]{status['job_queue']['FAILED']:,}[/bold red]", "Failed jobs")

    console.print(table)


@cli.command("audit-compliance")
@click.option("--date", "review_date", type=str, default=None, help="UTC date to check (YYYY-MM-DD), defaults to today")
def audit_compliance_cmd(review_date: Optional[str]):
    """✅ Verify the 'at most one review per package per day' rule for a given day."""
    async def _run():
        db = get_db_and_repo()
        await db.init_db()

        async with db.get_session() as session:
            repo = SentinelRepository(session)
            report = await repo.get_daily_review_compliance_report(review_date=review_date)

            status = "[bold green]✅ COMPLIANT[/bold green]" if report["rule_compliant"] else "[bold red]🚨 VIOLATION DETECTED[/bold red]"
            console.print(Panel(
                f"Daily Review Rule Compliance — {report['review_date']}\n"
                f"Status: {status}\n"
                f"Distinct packages reviewed: [bold cyan]{report['distinct_packages_reviewed']:,}[/bold cyan]\n"
                f"Duplicate attempts blocked (harmless, but worth tuning down): [yellow]{report['duplicate_attempts_blocked']:,}[/yellow]",
                style="green" if report["rule_compliant"] else "red",
            ))

            if report["rule_violations"]:
                table = Table(title="🚨 Rule Violations")
                table.add_column("Ecosystem", style="cyan")
                table.add_column("Package", style="magenta")
                table.add_column("Review Count", style="bold red")
                for v in report["rule_violations"]:
                    table.add_row(v["ecosystem"], v["package_name"], str(v["review_count"]))
                console.print(table)

        await db.close()

    asyncio.run(_run())


def main():
    cli()


if __name__ == "__main__":
    main()


