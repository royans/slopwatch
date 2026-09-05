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

        fail_policy = linter.config.get("fail_on", "HIGH")
        min_score = linter.config.get("min_threat_score", 50)
        severity_rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
        threshold_rank = severity_rank.get(fail_policy.upper(), 2)

        breached_items = [
            item for item in result["flagged_dependencies"]
            if severity_rank.get(item.get("severity", "MEDIUM").upper(), 1) >= threshold_rank
            or item.get("risk_weight", 0) >= min_score
        ]

        if not result["flagged_dependencies"]:
            console.print(Panel("✅ [bold green]ALL DEPENDENCIES VERIFIED[/bold green]: No flagged or suspicious packages detected.\n[dim]Automated static audit passed. Always practice defense-in-depth.[/dim]", style="green"))
        else:
            alert_style = "red" if breached_items else "yellow"
            alert_title = "AUDIT FAILURE" if breached_items else "AUDIT ADVISORY"
            console.print(Panel(
                f"⚠️ [bold {alert_style}]{alert_title}[/bold {alert_style}]: Found {result['flagged_count']} dependency(ies) flagged for review.\n"
                f"[dim]Policy: fail on {fail_policy} (score >= {min_score}). Breached: {len(breached_items)} item(s).[/dim]",
                style=alert_style
            ))
            table = Table(title="Flagged Dependencies (Heuristic Assessment)")
            table.add_column("Package", style="cyan")
            table.add_column("Version", style="magenta")
            table.add_column("Severity", style="bold yellow")
            table.add_column("Reason", style="yellow")
            for item in result["flagged_dependencies"]:
                table.add_row(item["package"], item["version"], item["severity"], item["reason"])
            console.print(table)
            console.print("\n[dim]Note: SlopGuard uses deterministic heuristics that may flag benign stubs. Configure 'allowlist' in .slopguard.yaml to permit approved packages.[/dim]")
            if breached_items:
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


@cli.command("init")
@click.option("--force", is_flag=True, help="Overwrite existing configuration and hooks.")
def init_cmd(force: bool):
    """🚀 Initialize SlopGuard in the current project (creates .slopguard.yaml, hooks, and CI)."""
    target_dir = Path.cwd().resolve()

    console.print(Panel.fit(
        "🛡️  [bold cyan]SlopGuard Project Shield Initializer[/bold cyan]\n"
        "[dim]Deterministic Zero-LLM AI Hallucination & Supply Chain Gatekeeper[/dim]",
        style="cyan"
    ))

    # 1. Environment & Workspace Discovery
    console.print(f"\n[bold]1. Inspecting Workspace Environment:[/bold] [dim]{target_dir}[/dim]")
    has_git = (target_dir / ".git").is_dir()
    if has_git:
        console.print("  [bold green]✓[/bold green] Detected Version Control: [cyan]Git repository (.git/)[/cyan]")
    else:
        console.print("  [bold yellow]![/bold yellow] Version Control: [dim]No .git/ found; skipping native git hook installation.[/dim]")

    discovered_manifests: List[Path] = []
    manifest_names = [
        "requirements.txt", "pyproject.toml", "Pipfile",
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"
    ]
    for mname in manifest_names:
        mpath = target_dir / mname
        if mpath.is_file():
            discovered_manifests.append(mpath)

    if discovered_manifests:
        console.print(f"  [bold green]✓[/bold green] Discovered Package Manifests ({len(discovered_manifests)} found):")
        for m in discovered_manifests:
            console.print(f"      • [bold]{m.name}[/bold]")
    else:
        console.print("  [dim]  • No package manifests detected yet. (Supported: requirements.txt, pyproject.toml, package.json, etc.)[/dim]")

    github_dir = target_dir / ".github"
    has_github = github_dir.is_dir()
    if has_github:
        console.print("  [bold green]✓[/bold green] Discovered CI/CD Environment: [cyan]GitHub Actions (.github/)[/cyan]")

    # 2. Configuration Setup (.slopguard.yaml)
    console.print("\n[bold]2. Configuring Project Security Baseline:[/bold]")
    config_file = target_dir / ".slopguard.yaml"
    if config_file.exists() and not force:
        console.print(f"  [dim]• Configuration file exists: {config_file.name} (use --force to overwrite)[/dim]")
    else:
        default_yaml_content = """# SlopGuard Project Configuration (.slopguard.yaml)
# Documentation: https://github.com/royans/slopguard
version: 1

# Packages to whitelist (skips hallucination and typosquat checks)
# Useful for internal private company libraries or approved VCS forks
allowlist:
  # - "my-internal-auth"
  # - "company-private-sdk"

# Failure & Alert Policy:
#   - "CRITICAL": Exit 1 only on confirmed malware, reverse shells, or malicious install hooks (score >= 80)
#   - "HIGH": Exit 1 on brand typosquats, direct unpinned URLs, or confirmed malware (score >= 50) [DEFAULT]
#   - "MEDIUM": Exit 1 on unlisted 404 dependencies, high-risk obfuscation, or higher (score >= 35)
#   - "ANY": Exit 1 on any heuristic warning
fail_on: "HIGH"

# Minimum threat score threshold (0-100) to fail CI (Default: 50)
min_threat_score: 50

# Offline mode (skip live registry queries, offline heuristics only)
offline: false

# Paths to ignore during directory audits (slopguard audit .)
ignore_paths:
  - "tests/**"
  - "fixtures/**"
  - "examples/**"
"""
        config_file.write_text(default_yaml_content, encoding="utf-8")
        console.print("  [bold green]✓[/bold green] Created configuration file: [bold cyan].slopguard.yaml[/bold cyan] (Default: fail on HIGH+, allowlist template)")

    # 3. Git Pre-Commit Hook Installation
    if has_git:
        hooks_dir = target_dir / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        pre_commit_path = hooks_dir / "pre-commit"
        if pre_commit_path.exists() and not force:
            console.print("  [dim]• Git pre-commit hook exists: .git/hooks/pre-commit (use --force to overwrite)[/dim]")
        else:
            hook_script = r"""#!/bin/sh
# SlopGuard Pre-Commit Hook: Guard against AI package hallucinations
# Auto-generated by `slopguard init`

if command -v slopguard >/dev/null 2>&1; then
    # Audit Python requirements if staged
    if git diff --cached --name-only | grep -E '(requirements.*\.txt|pyproject\.toml|Pipfile)' >/dev/null 2>&1; then
        echo "🛡️  SlopGuard auditing staged Python dependencies..."
        slopguard check requirements.txt || exit 1
    fi
    # Audit npm manifests if staged
    if git diff --cached --name-only | grep -E '(package\.json|package-lock\.json)' >/dev/null 2>&1; then
        echo "🛡️  SlopGuard auditing staged npm dependencies..."
        slopguard check package.json || exit 1
    fi
fi
"""
            pre_commit_path.write_text(hook_script, encoding="utf-8")
            pre_commit_path.chmod(0o755)
            console.print("  [bold green]✓[/bold green] Installed Native Git Pre-Commit Hook: [bold cyan].git/hooks/pre-commit[/bold cyan]")

    # 4. GitHub Actions Workflow Setup
    workflows_dir = target_dir / ".github" / "workflows"
    workflow_file = workflows_dir / "slopguard.yml"
    if workflow_file.exists() and not force:
        console.print("  [dim]• CI/CD workflow exists: .github/workflows/slopguard.yml (use --force to overwrite)[/dim]")
    else:
        try:
            workflows_dir.mkdir(parents=True, exist_ok=True)
            ci_content = """name: SlopGuard Dependency Audit

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  audit:
    name: SlopGuard Security Audit
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install SlopGuard
        run: pip install slopguard

      - name: Audit Project Dependencies & Source
        run: slopguard audit .
"""
            workflow_file.write_text(ci_content, encoding="utf-8")
            console.print("  [bold green]✓[/bold green] Installed CI/CD Workflow: [bold cyan].github/workflows/slopguard.yml[/bold cyan]")
        except Exception:
            pass

    # 5. Baseline Audit of Discovered Manifests
    if discovered_manifests:
        console.print("\n[bold]3. Running Initial Baseline Manifest Audit:[/bold]")
        from sentinel.linter.lockfile import DependencyLinter
        linter = DependencyLinter(repository=None, offline=False)

        audit_table = Table(title="Initial Manifest Baseline", show_lines=True)
        audit_table.add_column("Manifest", style="cyan")
        audit_table.add_column("Dependencies", justify="right")
        audit_table.add_column("Status", justify="center")
        audit_table.add_column("Notes", style="dim")

        async def _run_baseline():
            for m in discovered_manifests:
                try:
                    res = await linter.audit_file(m)
                    total = res.get("total_dependencies", 0)
                    flagged = res.get("flagged_count", 0)
                    if flagged == 0:
                        audit_table.add_row(m.name, str(total), "[bold green]CLEAN[/bold green]", f"All {total} dependencies verified")
                    else:
                        audit_table.add_row(m.name, str(total), f"[bold yellow]{flagged} FLAGGED[/bold yellow]", f"{flagged} item(s) need review")
                except Exception as ex:
                    audit_table.add_row(m.name, "-", "[bold red]ERROR[/bold red]", str(ex)[:30])

        asyncio.run(_run_baseline())
        console.print(audit_table)

    console.print(Panel(
        "🎉 [bold green]SlopGuard Protection Active![/bold green]\n\n"
        "  • [bold]Pre-Commit[/bold]: Future `git commit` commands will automatically audit modified manifests.\n"
        "  • [bold]CI/CD Gate[/bold]: Pull requests will be audited automatically via GitHub Actions.\n"
        "  • [bold]Customization[/bold]: Add private/internal packages to the `allowlist` in [cyan].slopguard.yaml[/cyan].",
        style="green"
    ))


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
