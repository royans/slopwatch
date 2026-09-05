"""
SlopGuard Command Line Interface (CLI).

Deterministic Zero-LLM Malware & Supply Chain Security Auditor for Python and JavaScript.
"""

import asyncio
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sentinel.core.dto import Ecosystem, ThreatVerdict
from sentinel.core.config import Settings, AssessorConfig
from sentinel.assessor.yara_engine import YaraPatternScanner
from sentinel.adapters import get_adapter

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="slopguard")
def cli():
    """🛡️ SlopGuard: Deterministic Zero-LLM AI Package Hallucination & Supply Chain Threat Auditor."""
    pass


@cli.command("info")
def info_cmd():
    """ℹ️ Display SlopGuard threat engine status, loaded YARA rules, and signatures."""
    console.print(Panel("🛡️ [bold cyan]SlopGuard Threat Engine[/bold cyan] (v0.1.0)", style="cyan"))
    
    scanner = YaraPatternScanner()
    rule_count = len(list(scanner._compiled_rules)) if scanner._compiled_rules else 0
    rule_status = f"[bold green]{rule_count} compiled rules active[/bold green]" if scanner.is_available else "[bold red]YARA unavailable[/bold red]"
    
    config = AssessorConfig()
    sig_path = config.signatures_path
    try:
        import json
        hashes = json.loads(Path(sig_path).read_text())
        sig_status = f"[bold green]{len(hashes):,} known parking signatures[/bold green]"
    except Exception:
        sig_status = "[bold yellow]Default signatures[/bold yellow]"

    table = Table(show_header=False, box=None)
    table.add_row("• Engine Architecture:", "[bold white]Zero-LLM Deterministic Pipeline[/bold white]")
    table.add_row("• Pattern Scanner:", rule_status)
    table.add_row("• Threat Signatures:", sig_status)
    table.add_row("• Rules Path:", f"[dim]{scanner.rules_path}[/dim]")
    table.add_row("• Signatures Path:", f"[dim]{sig_path}[/dim]")
    console.print(table)


@cli.command("scan")
@click.argument("target_path", type=click.Path(exists=True))
def scan_cmd(target_path: str):
    """🔍 Statically scan a source file or directory for weaponized patterns via YARA."""
    path = Path(target_path)
    scanner = YaraPatternScanner()

    if not scanner.is_available:
        console.print("[bold red]❌ YARA engine is unavailable. Please ensure yara-python is installed.[/bold red]")
        sys.exit(1)

    ignored_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules", "build", "dist", ".pytest_cache", ".tox", ".eggs"}
    files_to_scan = [path] if path.is_file() else [
        p for p in path.rglob("*")
        if p.is_file() and p.suffix in (".py", ".js", ".json", ".sh", ".pth")
        and not any(part in ignored_dirs or part.endswith(".egg-info") for part in p.relative_to(path).parts[:-1])
    ]

    console.print(f"[cyan]Scanning [bold]{len(files_to_scan)}[/bold] file(s) in [bold]{path}[/bold]...[/cyan]\n")

    total_violations = 0
    for f in files_to_scan:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        flags, line_details = scanner.scan_file_content(content, f.name)
        actionable_flags = [desc for tag, desc in flags if "Environment Variable Access (process.env / os.environ)" not in desc]
        actionable_lines = [ld for tag, ld in line_details if "Environment Variable Access" not in ld]

        if actionable_flags or actionable_lines:
            total_violations += len(actionable_flags) + len(actionable_lines)
            console.print(f"[bold yellow]⚠️ Flagged threat patterns in {f}:[/bold yellow]")
            for flag in actionable_flags:
                console.print(f"   • [yellow]{flag}[/yellow]")
            for ld in actionable_lines:
                console.print(f"   • [dim]{ld}[/dim]")

    if total_violations == 0:
        console.print(Panel(
            f"✅ [bold green]SCAN COMPLETE[/bold green]: Zero matched heuristic threat patterns in {path}\n"
            "[dim]Static checks passed. Review third-party dependencies as part of comprehensive security hygiene.[/dim]",
            style="green"
        ))
    else:
        console.print(Panel(
            f"⚠️ [bold red]PATTERNS FLAGGED[/bold red]: Found {total_violations} heuristic pattern match(es) for review.\n"
            "[dim]Heuristics flagged potential risk areas. Review lines above to verify intent.[/dim]",
            style="red"
        ))
        sys.exit(1)


@cli.command("check")
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--offline", is_flag=True, default=False, help="Disable live registry verification; run offline heuristics only.")
def check_cmd(file_path: str, offline: bool):
    """📋 Audit requirements.txt or package.json for hallucinated dependencies."""
    async def _run():
        path = Path(file_path)
        mode_desc = " (offline mode)" if offline else " (live upstream registry validation)"
        console.print(f"[cyan]Auditing lockfile: [bold]{path}[/bold]{mode_desc}...[/cyan]")

        from sentinel.linter.lockfile import DependencyLinter

        repo = None
        db = None
        try:
            from sentinel.db.engine import DatabaseManager
            from sentinel.db.repository import SentinelRepository
            settings = Settings.load()
            db_path = settings.storage.database_url.replace("sqlite+aiosqlite:///", "")
            if Path(db_path).exists():
                db = DatabaseManager(database_url=settings.storage.database_url, wal_mode=settings.storage.wal_mode)
                await db.init_db()
        except Exception:
            db = None

        if db:
            async with db.get_session() as session:
                repo = SentinelRepository(session)
                linter = DependencyLinter(repository=repo, offline=offline)
                result = await linter.audit_file(path)
            await db.close()
        else:
            linter = DependencyLinter(repository=None, offline=offline)
            result = await linter.audit_file(path)

        console.print(f"Total Dependencies Scanned: [bold]{result['total_dependencies']}[/bold]")

        if result["is_clean"]:
            console.print(Panel("✅ [bold green]ALL DEPENDENCIES VERIFIED[/bold green]: No flagged or suspicious packages detected.\n[dim]Automated static audit passed. Always practice defense-in-depth.[/dim]", style="green"))
        else:
            console.print(Panel(f"⚠️ [bold yellow]AUDIT NOTICE[/bold yellow]: Found {result['flagged_count']} dependency(ies) flagged for review.\n[dim]Automated heuristics suggest verification prior to installation.[/dim]", style="yellow"))
            table = Table(title="Flagged Dependencies (Heuristic Assessment)")
            table.add_column("Package", style="cyan")
            table.add_column("Version", style="magenta")
            table.add_column("Severity", style="bold yellow")
            table.add_column("Reason", style="yellow")
            for item in result["flagged_dependencies"]:
                table.add_row(item["package"], item["version"], item["severity"], item["reason"])
            console.print(table)
            console.print("\n[dim]Note: SlopGuard uses deterministic heuristics that may flag benign stubs. Please verify author and codebase before deploying.[/dim]")
            sys.exit(1)

    asyncio.run(_run())


@cli.command("inspect")
@click.argument("package_name")
@click.option("--ecosystem", type=click.Choice(["pypi", "npm"]), default="pypi", help="Package ecosystem (default: pypi)")
def inspect_cmd(package_name: str, ecosystem: str):
    """📦 Perform deep static AST analysis on an upstream package release."""
    async def _run():
        eco = Ecosystem(ecosystem)
        adapter = get_adapter(eco)
        norm_name = adapter.normalize_name(package_name)

        console.print(f"[cyan]Fetching metadata for [bold]{norm_name}[/bold] on {eco.value.upper()}...[/cyan]")
        meta = await adapter.inspect_package_metadata(norm_name)
        if not meta:
            console.print(f"[bold red]❌ Package '{norm_name}' not found on {eco.value.upper()}.[/bold red]")
            sys.exit(1)

        console.print(f"Author: [magenta]{meta.author or 'Unknown'}[/magenta] | Latest Version: [green]{meta.latest_version}[/green]")
        console.print(f"Description: {meta.description or 'None'}")

        console.print(f"\n[cyan]Downloading payload and performing AST + YARA analysis...[/cyan]")
        report = await adapter.download_and_inspect_payload(norm_name, meta.latest_version)

        verdict_color = "red" if report.verdict == ThreatVerdict.MALICIOUS else "yellow" if report.verdict == ThreatVerdict.SUSPICIOUS else "green"
        console.print(Panel(
            f"Heuristic Verdict: [{verdict_color}]{report.verdict.value}[/{verdict_color}] (Threat Score: {report.composite_threat_score}/100)\n"
            f"[dim]Static assessment based on AST code inspection and YARA threat rules. Heuristics may be imperfect; always inspect source code.[/dim]",
            style=verdict_color
        ))

        if report.flags:
            console.print("\n[bold red]🚨 Security Flags Detected:[/bold red]")
            for f in report.flags:
                console.print(f"  • {f}")
        if report.line_details:
            console.print("\n[bold yellow]Line Breakdown:[/bold yellow]")
            for ld in report.line_details:
                console.print(f"  • {ld}")

    asyncio.run(_run())


@cli.command("audit")
@click.argument("target_path", type=click.Path(exists=True), default=".")
@click.option("--strict", is_flag=True, help="Fail on any suspicious signal")
def audit_cmd(target_path: str, strict: bool):
    """🛡️ Audit local project, directory, or lockfiles for supply chain security risks."""
    path = Path(target_path)
    console.print(f"[cyan]Auditing target: [bold]{path.resolve()}[/bold]...[/cyan]\n")

    scanner = YaraPatternScanner()
    threat_count = 0

    # 1. Scan source files
    ignored_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules", "build", "dist", ".pytest_cache", ".tox", ".eggs", "tests"}
    scan_files = [path] if path.is_file() else [
        p for p in path.rglob("*")
        if p.is_file() and p.suffix in (".py", ".js", ".json", ".sh", ".pth")
        and not any(part in ignored_dirs or part.endswith(".egg-info") for part in p.relative_to(path).parts[:-1])
    ]

    for f in scan_files:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        flags, line_details = scanner.scan_file_content(content, f.name)
        actionable_flags = [desc for tag, desc in flags if "Environment Variable Access (process.env / os.environ)" not in desc]
        actionable_lines = [ld for tag, ld in line_details if "Environment Variable Access" not in ld]

        if actionable_flags or actionable_lines:
            threat_count += len(actionable_flags) + len(actionable_lines)
            console.print(f"[bold yellow]🔍 Signals in {f}:[/bold yellow]")
            for flag in actionable_flags:
                console.print(f"   • {flag}")
            for ld in actionable_lines:
                console.print(f"   • {ld}")

    if threat_count == 0:
        console.print(Panel(
            f"✅ [bold green]AUDIT COMPLETE[/bold green]: No known heuristic threat patterns detected across {len(scan_files)} file(s) in {path}.\n"
            "[dim]SlopGuard static inspection passed. Static checks cannot guarantee the absence of all vulnerabilities; review third-party code carefully.[/dim]",
            style="green"
        ))
    else:
        console.print(Panel(
            f"⚠️ [bold red]AUDIT FINDINGS[/bold red]: Identified {threat_count} heuristic signal(s) requiring review across {len(scan_files)} file(s).\n"
            "[dim]Please review the detected code locations above. False positives can occur; assess findings in context.[/dim]",
            style="red"
        ))
        sys.exit(1)


def main():
    cli()


if __name__ == "__main__":
    main()
