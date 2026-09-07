"""
SlopWatch Command Line Interface (CLI).

Deterministic Zero-LLM Malware & Supply Chain Security Auditor for Python and JavaScript.
"""

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from slopwatch import __version__
from slopwatch.core.dto import Ecosystem, ThreatVerdict
from slopwatch.core.config import Settings, AssessorConfig
from slopwatch.assessor.yara_engine import YaraPatternScanner
from slopwatch.adapters import get_adapter

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="slopwatch")
def cli():
    """🛡️ SlopWatch: Deterministic Zero-LLM AI Package Hallucination & Supply Chain Threat Auditor."""
    pass


@cli.command("info")
def info_cmd():
    """ℹ️ Display SlopWatch threat engine status, loaded YARA rules, and signatures."""
    console.print(Panel(f"🛡️ [bold cyan]SlopWatch Threat Engine[/bold cyan] (v{__version__})", style="cyan"))
    
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
    try:
        from slopwatch.core.domain_trust import get_shared_domain_trust_engine
        engine = get_shared_domain_trust_engine()
        high_trust = sum(1 for r in engine._reputations.values() if r.trust_score >= 0.7)
        table.add_row("• Domain Trust Engine:", f"[bold green]Active ({high_trust} verified high-trust domains)[/bold green]" if high_trust else "[bold green]Active (dynamic evaluation)[/bold green]")
    except Exception:
        pass
    table.add_row("• Provenance Engine:", "[bold green]PyPI OIDC / Sigstore / npm SLSA supported[/bold green]")
    console.print(table)


@cli.command("scan")
@click.argument("target_path", type=click.Path(exists=True))
@click.option("--json", "json_output", is_flag=True, help="Emit machine-readable JSON format.")
def scan_cmd(target_path: str, json_output: bool):
    """🔍 Statically scan a source file or directory for weaponized patterns via YARA."""
    path = Path(target_path)
    scanner = YaraPatternScanner()

    if not scanner.is_available:
        if json_output:
            click.echo(json.dumps({"error": "YARA engine is unavailable. Please ensure yara-python is installed."}))
        else:
            console.print("[bold red]❌ YARA engine is unavailable. Please ensure yara-python is installed.[/bold red]")
        sys.exit(1)

    ignored_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules", "build", "dist", ".pytest_cache", ".tox", ".eggs"}
    files_to_scan = [path] if path.is_file() else [
        p for p in path.rglob("*")
        if p.is_file() and p.suffix in (".py", ".js", ".json", ".sh", ".pth")
        and not any(part in ignored_dirs or part.endswith(".egg-info") for part in p.relative_to(path).parts[:-1])
    ]

    if not json_output:
        console.print(f"[cyan]Scanning [bold]{len(files_to_scan)}[/bold] file(s) in [bold]{path}[/bold]...[/cyan]\n")

    total_violations = 0
    findings = []
    for f in files_to_scan:
        try:
            fc = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        flags, line_details = scanner.scan_file_content(fc, f.name)
        actionable_flags = [desc for tag, desc in flags if "Environment Variable Access (process.env / os.environ)" not in desc]
        actionable_lines = [ld for tag, ld in line_details if "Environment Variable Access" not in ld]

        if actionable_flags or actionable_lines:
            file_v = len(actionable_flags) + len(actionable_lines)
            total_violations += file_v
            findings.append({
                "file": str(f),
                "flags": actionable_flags,
                "lines": actionable_lines,
            })
            if not json_output:
                console.print(f"[bold yellow]⚠️ Flagged threat patterns in {f}:[/bold yellow]")
                for flag in actionable_flags:
                    console.print(f"   • [yellow]{flag}[/yellow]")
                for ld in actionable_lines:
                    console.print(f"   • [dim]{ld}[/dim]")

    if json_output:
        out = {
            "target": str(path.resolve()),
            "files_scanned": len(files_to_scan),
            "total_violations": total_violations,
            "findings": findings,
        }
        click.echo(json.dumps(out, indent=2))
        if total_violations > 0:
            sys.exit(1)
        return

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


def _discover_manifests(target_path: Path) -> List[Path]:
    """Find all supported dependency manifests in a file or directory tree."""
    if target_path.is_file():
        return [target_path]

    ignored = {".git", "node_modules", ".venv", "venv", "build", "dist", ".pytest_cache", ".tox", ".eggs", "site-packages", "__pycache__"}
    manifest_patterns = (
        "requirements*.txt",
        "pyproject.toml",
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
    )

    found: List[Path] = []
    # 1. Top-level files in target directory
    try:
        for p in target_path.iterdir():
            if p.is_file():
                if any(p.match(pat) for pat in manifest_patterns):
                    found.append(p)
    except Exception:
        pass

    # 2. Check direct subdirectories (e.g. backend/requirements.txt, frontend/package.json)
    try:
        for sub in target_path.iterdir():
            if sub.is_dir() and sub.name not in ignored and not sub.name.startswith("."):
                for p in sub.iterdir():
                    if p.is_file():
                        if any(p.match(pat) for pat in manifest_patterns):
                            found.append(p)
    except Exception:
        pass

    return sorted(found, key=lambda x: str(x))


@cli.command("check")
@click.argument("target", type=click.Path(exists=True), default=".", required=False)
@click.option("--offline", is_flag=True, default=False, help="Disable live registry verification; run offline heuristics only.")
@click.option("--ignore", "ignore_tokens", multiple=True, metavar="CODE", help="Demote a finding code (e.g. SLOP-0003) from breaking to advisory. Repeatable.")
@click.option("--stats", "show_stats", is_flag=True, help="Print run statistics (manifests, registry calls, wall time).")
@click.option("--json", "json_output", is_flag=True, help="Emit machine-readable JSON format.")
def check_cmd(target: str, offline: bool, ignore_tokens: tuple, show_stats: bool, json_output: bool):
    """📋 Automatically discover and audit project manifests for hallucinated dependencies."""
    import time as _time
    from slopwatch.core.finding_catalog import resolve_ignore_token

    ignore_codes = set()
    unknown_ignores = []
    for tok in ignore_tokens:
        resolved = resolve_ignore_token(tok)
        if resolved:
            ignore_codes.add(resolved)
        else:
            unknown_ignores.append(tok)

    async def _run():
        _t0 = _time.monotonic()
        root_path = Path(target).resolve()
        manifests = _discover_manifests(root_path)

        if not manifests:
            if json_output:
                click.echo(json.dumps({
                    "target": str(root_path),
                    "manifests_discovered": 0,
                    "error": "No supported manifests found."
                }))
            else:
                console.print(Panel(
                    f"ℹ️  [bold yellow]No supported manifests found[/bold yellow] in [cyan]{root_path}[/cyan].\n"
                    "[dim]Supported: requirements*.txt, pyproject.toml, Pipfile, poetry.lock, package.json, yarn.lock, pnpm-lock.yaml[/dim]",
                    style="yellow"
                ))
            return

        mode_desc = " (offline mode)" if offline else " (live upstream registry validation)"
        if not json_output:
            if root_path.is_dir():
                console.print(f"[cyan]Discovered [bold]{len(manifests)}[/bold] manifest(s) in [bold]{root_path.name or root_path}[/bold]{mode_desc}:[/cyan]")
                for m in manifests:
                    try:
                        rel = m.relative_to(root_path)
                    except Exception:
                        rel = m.name
                    console.print(f"  • [bold]{rel}[/bold]")
                console.print()
            else:
                console.print(f"[cyan]Auditing manifest: [bold]{manifests[0].name}[/bold]{mode_desc}...[/cyan]")

        from slopwatch.linter.lockfile import DependencyLinter

        repo = None
        db = None
        try:
            from slopwatch.db.engine import DatabaseManager
            from slopwatch.db.repository import SentinelRepository
            settings = Settings.load()
            db_path = settings.storage.database_url.replace("sqlite+aiosqlite:///", "")
            if Path(db_path).exists():
                db = DatabaseManager(database_url=settings.storage.database_url, wal_mode=settings.storage.wal_mode)
                await db.init_db()
        except Exception:
            db = None

        total_scanned = 0
        all_flagged: List[Dict[str, Any]] = []
        all_suppressed: List[Dict[str, Any]] = []
        manifest_summaries: List[Tuple[str, int, int]] = []
        linter_inst: Optional[DependencyLinter] = None

        def _absorb(res, rel_name):
            nonlocal total_scanned
            total_scanned += res.get("total_dependencies", 0)
            manifest_summaries.append((rel_name, res.get("total_dependencies", 0), res.get("flagged_count", 0)))
            for item in res.get("flagged_dependencies", []):
                item["manifest"] = rel_name
                all_flagged.append(item)
            for item in res.get("suppressed_dependencies", []):
                item["manifest"] = rel_name
                all_suppressed.append(item)

        if db:
            async with db.get_session() as session:
                repo = SentinelRepository(session)
                linter_inst = DependencyLinter(repository=repo, offline=offline, ignore_codes=ignore_codes)
                for m in manifests:
                    try:
                        rel_name = str(m.relative_to(root_path))
                    except Exception:
                        rel_name = m.name
                    _absorb(await linter_inst.audit_file(m), rel_name)
            await db.close()
        else:
            linter_inst = DependencyLinter(repository=None, offline=offline, ignore_codes=ignore_codes)
            for m in manifests:
                try:
                    rel_name = str(m.relative_to(root_path))
                except Exception:
                    rel_name = m.name
                _absorb(await linter_inst.audit_file(m), rel_name)

        fail_policy = linter_inst.config.get("fail_on", "HIGH") if linter_inst else "HIGH"
        min_score = linter_inst.config.get("min_threat_score", 50) if linter_inst else 50
        severity_rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
        threshold_rank = severity_rank.get(fail_policy.upper(), 2)

        breached_items = [
            item for item in all_flagged
            if severity_rank.get(item.get("severity", "MEDIUM").upper(), 1) >= threshold_rank
            or item.get("risk_weight", 0) >= min_score
        ]

        stats = {
            "manifests_audited": getattr(linter_inst, "manifests_audited", len(manifests)),
            "dependencies_scanned": total_scanned,
            "registry_calls": getattr(linter_inst, "registry_calls", 0),
            "flagged": len(all_flagged),
            "suppressed": len(all_suppressed),
            "wall_time_seconds": round(_time.monotonic() - _t0, 3),
        }

        if unknown_ignores and not json_output:
            console.print(f"[yellow]⚠️  Ignoring unrecognized --ignore token(s): {', '.join(unknown_ignores)}[/yellow]\n")

        if json_output:
            out = {
                "target": str(root_path),
                "offline": offline,
                "manifests_count": len(manifests),
                "total_dependencies_scanned": total_scanned,
                "breached_count": len(breached_items),
                "flagged_count": len(all_flagged),
                "breached_dependencies": breached_items,
                "flagged_dependencies": all_flagged,
                "suppressed_count": len(all_suppressed),
                "suppressions": all_suppressed,
                "ignored_codes": sorted(getattr(linter_inst, "ignore_codes", ignore_codes)),
                "unknown_ignore_tokens": unknown_ignores,
                "stats": stats,
                "manifest_summaries": [
                    {"manifest": m_name, "dependencies": deps_count, "flagged": flag_count}
                    for m_name, deps_count, flag_count in manifest_summaries
                ]
            }
            click.echo(json.dumps(out, indent=2))
            if breached_items:
                sys.exit(1)
            return

        if len(manifests) > 1:
            summary_table = Table(title="Manifest Audit Summary")
            summary_table.add_column("Manifest", style="cyan")
            summary_table.add_column("Dependencies", justify="right")
            summary_table.add_column("Status", justify="center")
            for m_name, deps_count, flag_count in manifest_summaries:
                status_str = "[bold green]CLEAN[/bold green]" if flag_count == 0 else f"[bold yellow]{flag_count} FLAGGED[/bold yellow]"
                summary_table.add_row(m_name, str(deps_count), status_str)
            console.print(summary_table)
            console.print()

        console.print(f"Total Dependencies Scanned: [bold]{total_scanned}[/bold] across [bold]{len(manifests)}[/bold] manifest(s)")

        if not all_flagged:
            console.print(Panel("✅ [bold green]ALL DEPENDENCIES VERIFIED[/bold green]: No flagged or suspicious packages detected.\n[dim]Automated static audit passed. Always practice defense-in-depth.[/dim]", style="green"))
        else:
            alert_style = "red" if breached_items else "yellow"
            alert_title = "AUDIT FAILURE" if breached_items else "AUDIT ADVISORY"
            console.print(Panel(
                f"⚠️ [bold {alert_style}]{alert_title}[/bold {alert_style}]: Found {len(all_flagged)} dependency(ies) flagged for review.\n"
                f"[dim]Policy: fail on {fail_policy} (score >= {min_score}). Breached: {len(breached_items)} item(s).[/dim]",
                style=alert_style
            ))
            table = Table(title="Flagged Dependencies (Heuristic Assessment)")
            if len(manifests) > 1:
                table.add_column("Manifest", style="dim")
            table.add_column("Package", style="cyan")
            table.add_column("Version", style="magenta")
            table.add_column("Code", style="dim")
            table.add_column("Severity", style="bold yellow")
            table.add_column("Reason", style="yellow")
            for item in all_flagged:
                row = []
                if len(manifests) > 1:
                    row.append(item.get("manifest", ""))
                row.extend([item["package"], item["version"], item.get("code", "-"), item["severity"], item["reason"]])
                table.add_row(*row)
            console.print(table)
            console.print("\n[dim]Note: SlopWatch uses deterministic heuristics that may flag benign stubs. Configure 'allowlist' in .slopwatch.yaml to permit approved packages, or '--ignore <CODE>' to demote a specific finding.[/dim]")

        if all_suppressed:
            supp_table = Table(title="Suppressions (not counted against policy)")
            supp_table.add_column("Package", style="cyan")
            supp_table.add_column("Via", style="dim")
            supp_table.add_column("Why", style="dim")
            for item in all_suppressed:
                via = item.get("kind", "?")
                if item.get("code"):
                    via = f"{via} ({item['code']})"
                supp_table.add_row(str(item.get("package", "")), via, str(item.get("reason", "")))
            console.print()
            console.print(supp_table)

        if show_stats:
            stats_table = Table(title="Run Statistics", show_header=False, box=box.SIMPLE)
            stats_table.add_column("Metric", style="cyan")
            stats_table.add_column("Value", justify="right")
            stats_table.add_row("Manifests audited", str(stats["manifests_audited"]))
            stats_table.add_row("Dependencies scanned", str(stats["dependencies_scanned"]))
            stats_table.add_row("Live registry calls", str(stats["registry_calls"]))
            stats_table.add_row("Flagged", str(stats["flagged"]))
            stats_table.add_row("Suppressed", str(stats["suppressed"]))
            stats_table.add_row("Wall time (s)", f"{stats['wall_time_seconds']:.3f}")
            console.print()
            console.print(stats_table)

        if breached_items:
            sys.exit(1)

    asyncio.run(_run())


@cli.command("inspect")
@click.argument("package_name")
@click.option("--ecosystem", type=click.Choice(["pypi", "npm"]), default="pypi", help="Package ecosystem (default: pypi)")
@click.option("--json", "json_output", is_flag=True, help="Emit machine-readable JSON format.")
def inspect_cmd(package_name: str, ecosystem: str, json_output: bool):
    """📦 Perform deep static AST analysis on an upstream package release."""
    async def _run():
        eco = Ecosystem(ecosystem)
        adapter = get_adapter(eco)
        norm_name = adapter.normalize_name(package_name)

        if not json_output:
            console.print(f"[cyan]Fetching metadata for [bold]{norm_name}[/bold] on {eco.value.upper()}...[/cyan]")
        meta = await adapter.inspect_package_metadata(norm_name)
        if not meta:
            if json_output:
                click.echo(json.dumps({
                    "error": f"Package '{norm_name}' not found on {eco.value.upper()}.",
                    "package": norm_name,
                    "ecosystem": eco.value
                }))
            else:
                console.print(f"[bold red]❌ Package '{norm_name}' not found on {eco.value.upper()}.[/bold red]")
            sys.exit(1)

        # Publisher Identity & Dynamic Reputation Analysis
        from slopwatch.core.normalizers import extract_clean_email_and_domain
        from slopwatch.core.domain_trust import get_shared_domain_trust_engine
        _, author_domain = extract_clean_email_and_domain(meta.author_email)
        engine = get_shared_domain_trust_engine()
        domain_rep = engine.get_domain_reputation(author_domain) if author_domain else None

        if not json_output:
            console.print(f"Author: [magenta]{meta.author or 'Unknown'}[/magenta] | Latest Version: [green]{meta.latest_version}[/green]")
            console.print(f"Description: {meta.description or 'None'}")
            
            rep_table = Table(title="🏢 Publisher Authority & Provenance", box=box.ROUNDED, show_header=False)
            rep_table.add_column("Property", style="bold cyan", width=24)
            rep_table.add_column("Value", style="white")

            if author_domain:
                if domain_rep and domain_rep.trust_score >= 0.5:
                    rep_table.add_row("Publisher Domain:", f"[bold green]{author_domain}[/bold green] (Trust: [bold green]{int(domain_rep.trust_score * 100)}%[/bold green])")
                    rep_table.add_row("Publication History:", f"{domain_rep.package_count} package(s) over {domain_rep.span_days} days")
                elif domain_rep and domain_rep.is_generic_esp:
                    rep_table.add_row("Publisher Domain:", f"{author_domain} [yellow](Generic ESP / Public Email)[/yellow]")
                elif domain_rep:
                    rep_table.add_row("Publisher Domain:", f"{author_domain} (Trust: {int(domain_rep.trust_score * 100)}%)")
                else:
                    rep_table.add_row("Publisher Domain:", f"{author_domain} [dim](Unindexed / New domain)[/dim]")
            else:
                rep_table.add_row("Publisher Domain:", "[dim]Not declared[/dim]")

            if getattr(meta, "has_provenance", False):
                ptype = getattr(meta, "provenance_type", "SLSA / Sigstore")
                rep_table.add_row("Build Provenance:", f"[bold green]✓ Cryptographically Verified ({ptype})[/bold green]")
            else:
                rep_table.add_row("Build Provenance:", "[dim]None (unsigned release)[/dim]")

            if meta.monthly_downloads >= 100000:
                rep_table.add_row("Monthly Downloads:", f"[bold green]{meta.monthly_downloads:,}[/bold green] [dim](High Adoption)[/dim]")
            elif meta.monthly_downloads > 0:
                rep_table.add_row("Monthly Downloads:", f"{meta.monthly_downloads:,}")
            else:
                rep_table.add_row("Monthly Downloads:", "[dim]0 or unindexed[/dim]")

            console.print(rep_table)
            console.print("\n[cyan]Downloading payload and performing AST + YARA analysis...[/cyan]")

        report = await adapter.download_and_inspect_payload(norm_name, meta.latest_version)

        is_threat = report.verdict in (ThreatVerdict.MALICIOUS, ThreatVerdict.SUSPICIOUS, ThreatVerdict.UNVERIFIED_HIGH_SIGNAL)

        if json_output:
            out = {
                "package": norm_name,
                "ecosystem": eco.value,
                "version": meta.latest_version,
                "author": meta.author,
                "author_email": meta.author_email,
                "publisher_domain": author_domain,
                "domain_trust_score": domain_rep.trust_score if domain_rep else 0.0,
                "has_provenance": getattr(meta, "has_provenance", False),
                "provenance_type": getattr(meta, "provenance_type", None),
                "monthly_downloads": meta.monthly_downloads,
                "description": meta.description,
                "verdict": report.verdict.value,
                "threat_score": report.composite_threat_score,
                "flags": report.flags,
                "line_details": report.line_details,
            }
            click.echo(json.dumps(out, indent=2))
            if is_threat:
                sys.exit(1)
            return

        verdict_color = (
            "red" if report.verdict == ThreatVerdict.MALICIOUS
            else "yellow" if report.verdict == ThreatVerdict.SUSPICIOUS
            else "cyan" if report.verdict == ThreatVerdict.UNVERIFIED_HIGH_SIGNAL
            else "green"
        )
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

        if is_threat:
            sys.exit(1)

    asyncio.run(_run())


@cli.command("init")
@click.option("--force", is_flag=True, help="Overwrite existing configuration and hooks.")
def init_cmd(force: bool):
    """🚀 Initialize SlopWatch in the current project (creates .slopwatch.yaml, hooks, and CI)."""
    target_dir = Path.cwd().resolve()

    console.print(Panel.fit(
        "🛡️  [bold cyan]SlopWatch Project Shield Initializer[/bold cyan]\n"
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

    # 2. Configuration Setup (.slopwatch.yaml)
    console.print("\n[bold]2. Configuring Project Security Baseline:[/bold]")
    config_file = target_dir / ".slopwatch.yaml"
    if config_file.exists() and not force:
        console.print(f"  [dim]• Configuration file exists: {config_file.name} (use --force to overwrite)[/dim]")
    else:
        default_yaml_content = """# SlopWatch Project Configuration (.slopwatch.yaml)
# Documentation: https://github.com/royans/slopwatch
version: 1

# Packages to whitelist (skips hallucination and typosquat checks)
# Useful for internal private company libraries or approved VCS forks.
# Entries may be a bare name, or carry a justification that is echoed in
# the suppression ledger and --json output:
allowlist:
  # - "my-internal-auth"
  # - name: "company-private-sdk"
  #   reason: "internal package on Artifactory; approved 2026-09 (SEC-412)"

# Finding codes to demote from build-breaking to advisory (see docs/FINDINGS.md).
# Suppressed findings still appear in output, listed in the suppression ledger.
ignore:
  # - "SLOP-0004"   # direct VCS / raw-URL dependencies

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

# Paths to ignore during directory audits (slopwatch audit .)
ignore_paths:
  - "tests/**"
  - "fixtures/**"
  - "examples/**"
"""
        config_file.write_text(default_yaml_content, encoding="utf-8")
        console.print("  [bold green]✓[/bold green] Created configuration file: [bold cyan].slopwatch.yaml[/bold cyan] (Default: fail on HIGH+, allowlist template)")

    # 3. Git Pre-Commit Hook Installation
    if has_git:
        hooks_dir = target_dir / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        pre_commit_path = hooks_dir / "pre-commit"
        if pre_commit_path.exists() and not force:
            console.print("  [dim]• Git pre-commit hook exists: .git/hooks/pre-commit (use --force to overwrite)[/dim]")
        else:
            hook_script = r"""#!/bin/sh
# SlopWatch Pre-Commit Hook: Guard against AI package hallucinations
# Auto-generated by `slopwatch init`

if command -v slopwatch >/dev/null 2>&1; then
    # Audit Python requirements if staged
    if git diff --cached --name-only | grep -E '(requirements.*\.txt|pyproject\.toml|Pipfile)' >/dev/null 2>&1; then
        echo "🛡️  SlopWatch auditing staged Python dependencies..."
        slopwatch check requirements.txt || exit 1
    fi
    # Audit npm manifests if staged
    if git diff --cached --name-only | grep -E '(package\.json|package-lock\.json)' >/dev/null 2>&1; then
        echo "🛡️  SlopWatch auditing staged npm dependencies..."
        slopwatch check package.json || exit 1
    fi
fi
"""
            pre_commit_path.write_text(hook_script, encoding="utf-8")
            pre_commit_path.chmod(0o755)
            console.print("  [bold green]✓[/bold green] Installed Native Git Pre-Commit Hook: [bold cyan].git/hooks/pre-commit[/bold cyan]")

    # 4. GitHub Actions Workflow Setup
    workflows_dir = target_dir / ".github" / "workflows"
    workflow_file = workflows_dir / "slopwatch.yml"
    if workflow_file.exists() and not force:
        console.print("  [dim]• CI/CD workflow exists: .github/workflows/slopwatch.yml (use --force to overwrite)[/dim]")
    else:
        try:
            workflows_dir.mkdir(parents=True, exist_ok=True)
            ci_content = """name: SlopWatch Dependency Audit

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  audit:
    name: SlopWatch Security Audit
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install SlopWatch
        run: pip install slopwatch

      - name: Audit Project Dependencies & Source
        run: slopwatch audit .
"""
            workflow_file.write_text(ci_content, encoding="utf-8")
            console.print("  [bold green]✓[/bold green] Installed CI/CD Workflow: [bold cyan].github/workflows/slopwatch.yml[/bold cyan]")
        except Exception:
            pass

    # 4b. Agent Rules (AGENTS.md) — instruct autonomous coding agents to
    #     verify a dependency with SlopWatch before adding it to a manifest.
    agents_file = target_dir / "AGENTS.md"
    agent_rules_block = """## Dependency safety (SlopWatch)

Before adding, upgrading, or committing any third-party dependency
(`requirements.txt`, `pyproject.toml`, `package.json`, lockfiles):

1. Run `slopwatch check <manifest>` (or `slopwatch inspect <name> --ecosystem pypi|npm`).
2. If the package is flagged as `UNREGISTERED_OR_HALLUCINATED_PACKAGE`,
   `SUSPICIOUS_TYPOSQUAT_OF_*`, or `MATCHES_UNREGISTERED_SLOPSQUAT_WATCHLIST`,
   do **not** add it — you have likely hallucinated the name. Find the real
   package instead.
3. Only add a dependency once `slopwatch check` passes, or a human has
   explicitly approved it via the `allowlist` in `.slopwatch.yaml`.
"""
    if agents_file.exists() and not force:
        try:
            existing = agents_file.read_text(encoding="utf-8")
        except Exception:
            existing = ""
        if "SlopWatch" in existing:
            console.print("  [dim]• Agent rules present: AGENTS.md already references SlopWatch[/dim]")
        else:
            agents_file.write_text(existing.rstrip() + "\n\n" + agent_rules_block, encoding="utf-8")
            console.print("  [bold green]✓[/bold green] Appended SlopWatch dependency rule to [bold cyan]AGENTS.md[/bold cyan]")
    else:
        agents_file.write_text(
            "# Agent Instructions\n\n"
            "Machine-readable guidance for autonomous coding agents working in this repo.\n\n"
            + agent_rules_block,
            encoding="utf-8",
        )
        console.print("  [bold green]✓[/bold green] Created agent ruleset: [bold cyan]AGENTS.md[/bold cyan] (pre-dependency SlopWatch check)")

    # 5. Baseline Audit of Discovered Manifests
    if discovered_manifests:
        console.print("\n[bold]3. Running Initial Baseline Manifest Audit:[/bold]")
        from slopwatch.linter.lockfile import DependencyLinter
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
        "🎉 [bold green]SlopWatch Protection Active![/bold green]\n\n"
        "  • [bold]Pre-Commit[/bold]: Future `git commit` commands will automatically audit modified manifests.\n"
        "  • [bold]CI/CD Gate[/bold]: Pull requests will be audited automatically via GitHub Actions.\n"
        "  • [bold]Agent Rules[/bold]: [cyan]AGENTS.md[/cyan] tells coding agents to run `slopwatch check` before adding a dependency.\n"
        "  • [bold]Customization[/bold]: Add private/internal packages to the `allowlist` in [cyan].slopwatch.yaml[/cyan].",
        style="green"
    ))


@cli.command("audit")
@click.argument("target_path", type=click.Path(exists=True), default=".")
@click.option("--strict", is_flag=True, help="Fail on any suspicious signal")
@click.option("--json", "json_output", is_flag=True, help="Emit machine-readable JSON format.")
def audit_cmd(target_path: str, strict: bool, json_output: bool):
    """🛡️ Audit local project, directory, or lockfiles for supply chain security risks."""
    path = Path(target_path)
    if not json_output:
        console.print(f"[cyan]Auditing target: [bold]{path.resolve()}[/bold]...[/cyan]\n")

    scanner = YaraPatternScanner()
    threat_count = 0
    findings = []

    # 1. Scan source files
    ignored_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules", "build", "dist", ".pytest_cache", ".tox", ".eggs", "tests"}
    scan_files = [path] if path.is_file() else [
        p for p in path.rglob("*")
        if p.is_file() and p.suffix in (".py", ".js", ".json", ".sh", ".pth")
        and not any(part in ignored_dirs or part.endswith(".egg-info") for part in p.relative_to(path).parts[:-1])
    ]

    for f in scan_files:
        try:
            fc = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        flags, line_details = scanner.scan_file_content(fc, f.name)
        actionable_flags = [desc for tag, desc in flags if "Environment Variable Access (process.env / os.environ)" not in desc]
        actionable_lines = [ld for tag, ld in line_details if "Environment Variable Access" not in ld]

        if actionable_flags or actionable_lines:
            file_t = len(actionable_flags) + len(actionable_lines)
            threat_count += file_t
            findings.append({
                "file": str(f),
                "flags": actionable_flags,
                "lines": actionable_lines,
            })
            if not json_output:
                console.print(f"[bold yellow]🔍 Signals in {f}:[/bold yellow]")
                for flag in actionable_flags:
                    console.print(f"   • {flag}")
                for ld in actionable_lines:
                    console.print(f"   • {ld}")

    if json_output:
        out = {
            "target": str(path.resolve()),
            "files_scanned": len(scan_files),
            "threat_count": threat_count,
            "strict": strict,
            "findings": findings,
        }
        click.echo(json.dumps(out, indent=2))
        if threat_count > 0:
            sys.exit(1)
        return

    if threat_count == 0:
        console.print(Panel(
            f"✅ [bold green]AUDIT COMPLETE[/bold green]: No known heuristic threat patterns detected across {len(scan_files)} file(s) in {path}.\n"
            "[dim]SlopWatch static inspection passed. Static checks cannot guarantee the absence of all vulnerabilities; review third-party code carefully.[/dim]",
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
