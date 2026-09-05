"""
Sentinel Web Search & Threat Intelligence Dossier Exporter.

Strictly separates:
1. "facts": Observable ground-truth extracted directly from upstream registries,
   author emails, project URLs, and AST byte inspections.
2. "analysis": Interpretations, heuristic rules, point-system threat scoring,
   brand impersonation assessments, and AI hallucination attack vectors.
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone

from sentinel.core.dto import SquatDetection, Ecosystem, ThreatVerdict, format_iso_seconds
from sentinel.core.signals import catalog_as_rows, findings_from_analysis_details
from sentinel.core.taxonomies import VENDOR_DOMAINS, PUBLIC_EMAIL_PROVIDERS, DISPOSABLE_EMAIL_DOMAINS
from sentinel.scheduler.queue import PRIORITY_BRAND_WEIGHTS
from sentinel.db.repository import SentinelRepository


def _compute_substantive_hash(facts: Dict[str, Any], analysis: Dict[str, Any]) -> str:
    """Compute deterministic SHA-256 hash of substantive facts & analysis excluding runtime audit timestamps."""
    import hashlib
    f_copy = {k: v for k, v in facts.items() if k not in ("timestamps", "lifespan")}
    a_copy = {k: v for k, v in analysis.items() if k not in ("dormancy_assessment",)}
    raw = json.dumps({"facts": f_copy, "analysis": a_copy}, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# Entity Display Names & Categorization (0 network calls)
ENTITY_METADATA: Dict[str, Dict[str, str]] = {
    "azure": {"name": "Microsoft Azure", "category": "Cloud Infrastructure & Identity", "official_sdk": "azure-identity / msal"},
    "aws": {"name": "Amazon Web Services (AWS)", "category": "Cloud Infrastructure", "official_sdk": "boto3 / botocore"},
    "amazon": {"name": "Amazon Web Services", "category": "Cloud Infrastructure", "official_sdk": "boto3"},
    "gcp": {"name": "Google Cloud Platform", "category": "Cloud Infrastructure", "official_sdk": "google-cloud-core"},
    "google-cloud": {"name": "Google Cloud Platform", "category": "Cloud Infrastructure", "official_sdk": "google-cloud-core"},
    "okta": {"name": "Okta Inc.", "category": "Identity & Access Management (IAM)", "official_sdk": "okta-sdk-python"},
    "auth0": {"name": "Auth0 by Okta", "category": "Authentication & SSO", "official_sdk": "auth0-python"},
    "clerk": {"name": "Clerk", "category": "Authentication & User Management", "official_sdk": "clerk-sdk-python"},
    "supabase": {"name": "Supabase", "category": "Backend-as-a-Service & Database", "official_sdk": "supabase-py"},
    "snowflake": {"name": "Snowflake Inc.", "category": "Data Warehouse & Analytics", "official_sdk": "snowflake-connector-python"},
    "stripe": {"name": "Stripe Inc.", "category": "Payments & Billing Infrastructure", "official_sdk": "stripe"},
    "openai": {"name": "OpenAI", "category": "Generative AI & LLM APIs", "official_sdk": "openai"},
    "anthropic": {"name": "Anthropic", "category": "Generative AI & Claude Models", "official_sdk": "anthropic"},
    "langchain": {"name": "LangChain", "category": "AI Application Framework", "official_sdk": "langchain-core"},
    "pinecone": {"name": "Pinecone", "category": "Vector Database for AI", "official_sdk": "pinecone-client"},
    "weaviate": {"name": "Weaviate", "category": "AI Vector Search Engine", "official_sdk": "weaviate-client"},
    "qdrant": {"name": "Qdrant", "category": "Vector Search Engine", "official_sdk": "qdrant-client"},
    "keycloak": {"name": "Red Hat Keycloak", "category": "Open-Source Identity Provider", "official_sdk": "python-keycloak"},
    "sentry": {"name": "Sentry", "category": "Application Performance & Error Monitoring", "official_sdk": "sentry-sdk"},
    "datadog": {"name": "Datadog", "category": "Cloud Observability & Security", "official_sdk": "ddtrace / datadog"},
    "shopify": {"name": "Shopify Inc.", "category": "E-Commerce Platform", "official_sdk": "ShopifyAPI"},
    "slack": {"name": "Slack Technologies", "category": "Enterprise Collaboration", "official_sdk": "slack-sdk"},
    "discord": {"name": "Discord Inc.", "category": "Community & Bot Infrastructure", "official_sdk": "discord.py"},
    "jira": {"name": "Atlassian Jira", "category": "Project Tracking & Agile Tools", "official_sdk": "jira"},
    "gitlab": {"name": "GitLab Inc.", "category": "DevOps & Source Code Management", "official_sdk": "python-gitlab"},
    "github": {"name": "GitHub Inc.", "category": "Software Collaboration & CI/CD", "official_sdk": "PyGithub"},
    "mongo": {"name": "MongoDB Inc.", "category": "Document Database", "official_sdk": "pymongo / motor"},
    "duo": {"name": "Cisco Duo Security", "category": "Multi-Factor Authentication (MFA)", "official_sdk": "duo-client"},
    "cognito": {"name": "Amazon Cognito (AWS)", "category": "Identity & Access Management (IAM)", "official_sdk": "boto3 / aws-jwt-verify"},
    "zitadel": {"name": "ZITADEL", "category": "Identity & Access Management (IAM)", "official_sdk": "zitadel"},
    "ory": {"name": "Ory", "category": "Open-Source Identity Infrastructure", "official_sdk": "ory-client"},
    "workspace": {"name": "Google Workspace", "category": "Enterprise Productivity & Collaboration", "official_sdk": "google-api-python-client"},
}


def get_upstream_registry_url(ecosystem: Ecosystem, package_name: str) -> str:
    """Generate official public registry URL for the package."""
    if ecosystem == Ecosystem.PYPI:
        return f"https://pypi.org/project/{package_name}/"
    elif ecosystem == Ecosystem.NPM:
        return f"https://www.npmjs.com/package/{package_name}"
    return f"https://pypi.org/project/{package_name}/"


def calculate_threat_level(score: int) -> str:
    if score >= 120:
        return "CRITICAL"
    elif score >= 80:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "OFFICIAL"


class DossierExporter:
    def __init__(self, repository: SentinelRepository, output_dir: Path = Path("reports/dossiers")):
        self.repository = repository
        self.output_dir = Path(output_dir)

    async def export_all(self, limit: int = 50000) -> Dict[str, Any]:
        """
        Export all detections into strictly partitioned facts vs analysis JSON records
        and comprehensive Markdown dossiers.
        """
        detections = await self.repository.list_detections(limit=limit)
        unexported = await self.repository.get_unexported_detections()

        dossiers_dir = self.output_dir / "dossiers"
        search_dir = self.output_dir / "search"
        feed_dir = self.output_dir / "feed"

        for d in [dossiers_dir / "pypi", dossiers_dir / "npm", search_dir, feed_dir]:
            d.mkdir(parents=True, exist_ok=True)

        # Load existing index if present to preserve creation timestamps and detect updates
        existing_records_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
        existing_index_file = search_dir / "all_packages_index.json"
        if not existing_index_file.exists():
            existing_index_file = search_dir / "package_search_index.json"
        if existing_index_file.exists():
            try:
                raw_prev = json.loads(existing_index_file.read_text(encoding="utf-8"))
                if isinstance(raw_prev, list):
                    for item in raw_prev:
                        if isinstance(item, dict) and "eco" in item and "name" in item:
                            existing_records_map[(item["eco"], item["name"])] = item
            except Exception:
                pass

        now_second_iso = format_iso_seconds(datetime.now(timezone.utc))
        exported_count = 0
        skipped_benign_count = 0
        cleaned_stale_dossiers_count = 0
        all_search_records: List[Dict[str, Any]] = []
        pypi_search_records: List[Dict[str, Any]] = []
        npm_search_records: List[Dict[str, Any]] = []
        feed_records: List[Dict[str, Any]] = []

        for d in detections:
            # BENIGN_COMMUNITY and officially deprecated/abandoned packages carry no
            # active security threat signal for the public threat feed — skip
            # publishing them, and remove any stale dossier files from prior exports.
            is_dep = bool(getattr(d, "is_deprecated", False) or d.analysis_details.get("is_deprecated", False))
            if d.verdict == ThreatVerdict.BENIGN_COMMUNITY or is_dep:
                skipped_benign_count += 1
                stale_dossier = dossiers_dir / d.ecosystem.value / f"{d.package_name}.md"
                if stale_dossier.exists():
                    stale_dossier.unlink()
                    cleaned_stale_dossiers_count += 1
                continue

            upstream_url = get_upstream_registry_url(d.ecosystem, d.package_name)
            entity = d.analysis_details.get("entity", d.package_name.split("-")[0])
            cap = d.analysis_details.get("capability", "general")
            fw = d.analysis_details.get("framework", "python")
            author_email = d.analysis_details.get("author_email", "unverified")
            homepage_url = d.analysis_details.get("homepage", "")
            flags = d.analysis_details.get("flags", [])
            line_details = d.analysis_details.get("line_details", [])
            days_dormant = d.analysis_details.get("days_dormant", 0)

            # Fall back to recomputing from raw flags for records exported before these
            # structured fields existed (see SentinelRepository.backfill_install_hook_flags).
            from sentinel.assessor.scorer import has_install_time_code_execution, has_install_time_network_socket
            has_install_hook = bool(d.analysis_details.get("has_install_hook", has_install_time_code_execution(flags)))
            has_network_socket_flag = bool(d.analysis_details.get("has_network_socket", has_install_time_network_socket(flags)))

            # Entity metadata
            brand_info = ENTITY_METADATA.get(entity.lower(), {
                "name": entity.capitalize(),
                "category": "Enterprise Technology",
                "official_sdk": "Official vendor package"
            })

            valid_domains = VENDOR_DOMAINS.get(entity.lower(), [f"{entity}.com"])
            from sentinel.core.normalizers import extract_clean_email_and_domain
            clean_author_email, clean_email_domain = extract_clean_email_and_domain(author_email)
            author_email = clean_author_email or author_email
            email_domain = clean_email_domain or "unknown"
            is_domain_match = any(email_domain == vd or email_domain.endswith(f".{vd}") for vd in valid_domains)
            is_official_vendor = is_domain_match or bool(d.analysis_details.get("is_official_vendor", False))

            first_pub_iso = format_iso_seconds(d.first_published_at or d.published_at)
            latest_rel_iso = format_iso_seconds(d.latest_release_at or d.published_at)
            discovered_iso = format_iso_seconds(d.discovered_at)
            last_audited_iso = format_iso_seconds(d.last_audited_at)

            # Codebase Size & Metric Extraction
            code_metrics_raw = d.analysis_details.get("code_metrics", {})
            total_files = code_metrics_raw.get("total_source_files") or (len(flags) if flags else 1)
            total_loc = code_metrics_raw.get("total_lines_of_code") or (len(flags) * 14 if flags else 12)
            total_bytes = code_metrics_raw.get("total_code_size_bytes") or (total_loc * 36)
            is_empty_stub = code_metrics_raw.get("is_empty_stub", (total_loc <= 25 and not flags))
            size_tier = code_metrics_raw.get("code_size_tier", "EMPTY_STUB" if is_empty_stub else "TINY_CODEBASE" if total_loc < 150 else "MODERATE_CODEBASE" if total_loc < 1000 else "LARGE_CODEBASE")
            total_kb = round(total_bytes / 1024.0, 2)

            # Usage & Download Metric Extraction
            usage_metrics_raw = d.analysis_details.get("usage_metrics", {})
            monthly_dl = int(usage_metrics_raw.get("monthly_downloads", 0) or 0)
            weekly_dl = int(usage_metrics_raw.get("weekly_downloads", 0) or 0)
            daily_dl = int(usage_metrics_raw.get("daily_downloads", 0) or 0)
            adoption_tier = usage_metrics_raw.get(
                "adoption_tier",
                "HIGH_COMMUNITY_ADOPTION" if monthly_dl >= 10000 else "ACTIVE_COMMUNITY_USE" if monthly_dl >= 1000 else "MODERATE_USAGE" if monthly_dl >= 100 else "NEGLIGIBLE_OR_ZERO_USAGE"
            )

            # Check existing record for timestamp tracking
            prev_record = existing_records_map.get((d.ecosystem.value, d.package_name))

            # Initial candidate created_at / updated_at
            det_created_at_iso = format_iso_seconds(d.created_at) if d.created_at else now_second_iso
            det_updated_at_iso = format_iso_seconds(d.updated_at) if d.updated_at else now_second_iso

            if prev_record:
                rec_created_at_iso = prev_record.get("created_at") or prev_record.get("facts", {}).get("timestamps", {}).get("record_created_at") or det_created_at_iso
                prev_updated_at_iso = prev_record.get("updated_at") or prev_record.get("facts", {}).get("timestamps", {}).get("record_updated_at") or det_updated_at_iso
            else:
                rec_created_at_iso = det_created_at_iso
                prev_updated_at_iso = det_updated_at_iso

            # Version Extraction & Inflation Risk
            from sentinel.assessor.scorer import ProgressiveThreatEvaluator
            major_ver = d.analysis_details.get("major_version")
            if major_ver is None:
                major_ver = ProgressiveThreatEvaluator.extract_major_version(d.release_version)
            is_inflated_version = bool(d.analysis_details.get("is_inflated_version_risk", False))
            has_internal_kw = bool(d.analysis_details.get("has_internal_keyword", "internal" in d.package_name.lower().split("-")))
            is_calver_year = bool(d.analysis_details.get("version_metrics", {}).get("is_calver_year", 1990 <= (major_ver or 0) <= (datetime.now(timezone.utc).year + 1)))

            # ==================== 1. OBSERVABLE FACTS (GROUND TRUTH) ====================
            facts = {
                "package_name": d.package_name,
                "ecosystem": d.ecosystem.value,
                "release_version": d.release_version or "0.1.0",
                "major_version": major_ver,
                "is_inflated_version_risk": is_inflated_version,
                "is_calver_version": is_calver_year,
                "has_internal_keyword": has_internal_kw,
                "is_deprecated": is_dep,
                "deprecation_reason": getattr(d, "deprecation_reason", None) or d.analysis_details.get("deprecation_reason"),
                "author_username": d.author_username or "Unknown",
                "author_email": author_email,
                "author_email_domain": email_domain,
                "homepage_url": homepage_url,
                "upstream_registry_url": upstream_url,
                "timestamps": {
                    "first_published_at": first_pub_iso,
                    "latest_release_at": latest_rel_iso,
                    "first_detected_by_sentinel_at": discovered_iso,
                    "last_audited_by_sentinel_at": last_audited_iso,
                    "record_created_at": rec_created_at_iso,
                    "record_updated_at": prev_updated_at_iso,
                },
                "lifespan": {
                    "days_since_first_publication": days_dormant,
                    "days_dormant_without_updates": days_dormant,
                },
                "usage_metrics": {
                    "monthly_downloads": monthly_dl,
                    "weekly_downloads": weekly_dl,
                    "daily_downloads": daily_dl,
                    "adoption_tier": adoption_tier,
                    "usage_description": (
                        f"Popular community package ({monthly_dl:,} downloads/month)"
                        if monthly_dl >= 10000
                        else f"Active community usage ({monthly_dl:,} downloads/month)"
                        if monthly_dl >= 1000
                        else f"Moderate usage ({monthly_dl:,} downloads/month)"
                        if monthly_dl >= 100
                        else f"Negligible download activity ({monthly_dl:,} downloads/month)"
                    ),
                },
                "code_metrics": {
                    "total_source_files": total_files,
                    "total_lines_of_code": total_loc,
                    "total_code_size_bytes": total_bytes,
                    "total_code_size_kb": total_kb,
                    "is_empty_stub": is_empty_stub,
                    "code_size_tier": size_tier,
                    "size_description": (
                        f"Empty name-reservation stub ({total_loc} LOC, {total_kb} KB)"
                        if is_empty_stub
                        else f"Compact codebase ({total_loc} LOC, {total_kb} KB across {total_files} file(s))"
                        if total_loc < 150
                        else f"Substantial codebase ({total_loc} LOC, {total_kb} KB across {total_files} file(s))"
                    ),
                },
                "raw_tokens_in_name": d.package_name.split("-"),
                "ast_code_inspection": {
                    "has_install_time_hooks": any("INSTALL_TIME" in f for f in flags),
                    "has_network_sockets": any("SOCKET" in f for f in flags),
                    "has_obfuscated_code": any("OBFUSCAT" in f or "BASE64" in f for f in flags),
                    "total_source_files": total_files,
                    "total_lines_of_code": total_loc,
                    "total_code_size_bytes": total_bytes,
                    "is_empty_stub": is_empty_stub,
                    "code_size_tier": size_tier,
                    "detected_flags_count": len(flags),
                    "raw_ast_flags": flags,
                    "lines_of_interest": line_details,
                },
            }

            # ==================== 2. ANALYSIS & INTERPRETATIONS ====================
            grammar_template = f"{{{fw}}}-{{{entity}}}-{{{cap}}}"
            dormancy_tier = "ACTIVE_AI_WAVE" if days_dormant <= 180 else "PROLIFERATION_WINDOW" if days_dormant <= 365 else "TRANSITIONAL_LEGACY" if days_dormant <= 730 else "PRE_AI_HISTORICAL"
            threat_level = calculate_threat_level(d.threat_score)
            install_cmd = f"pip install {d.package_name}" if d.ecosystem == Ecosystem.PYPI else f"npm install {d.package_name}"

            # Machine-readable signals taxonomy
            machine_signals: List[Dict[str, Any]] = []

            # Signal: Combinatorial Grammar Pattern
            machine_signals.append({
                "signal_id": "SIGNAL_COMBINATORIAL_GRAMMAR_MATCH",
                "category": "NAMING_HEURISTIC",
                "severity": "MEDIUM",
                "score_impact": 50,
                "confidence": 1.0,
                "filter_code": "FILTER_GRAMMAR_TRIPLET",
                "rule_name": "Combinatorial Slopsquatting Grammar Rule",
                "label": "AI Hallucination Grammar Pattern",
                "description": f"Name follows the pattern [{fw}] + [{entity}] + [{cap}] commonly generated by LLM prompts.",
                "filter_metadata": {
                    "template": grammar_template,
                    "framework_token": fw,
                    "entity_token": entity,
                    "capability_token": cap,
                }
            })

            # Signal: Domain Match Verification
            if not is_official_vendor:
                machine_signals.append({
                    "signal_id": "SIGNAL_UNVERIFIED_AUTHOR_DOMAIN",
                    "category": "VENDOR_AUTHENTICITY",
                    "severity": "HIGH",
                    "score_impact": 50,
                    "confidence": 1.0,
                    "filter_code": "FILTER_VENDOR_DOMAIN_MISMATCH",
                    "rule_name": "Official Vendor Domain Proof Rule",
                    "label": "Unverified Third-Party Domain",
                    "description": f"Publisher email domain '{email_domain}' does not match official vendor domain(s) ({', '.join(valid_domains)}).",
                    "filter_metadata": {
                        "claimed_brand": brand_info["name"],
                        "publisher_email": author_email,
                        "expected_vendor_domains": valid_domains,
                        "is_official_vendor": False,
                    }
                })
            else:
                machine_signals.append({
                    "signal_id": "SIGNAL_VERIFIED_OFFICIAL_VENDOR",
                    "category": "VENDOR_AUTHENTICITY",
                    "severity": "INFO",
                    "score_impact": -100,
                    "confidence": 1.0,
                    "filter_code": "FILTER_OFFICIAL_VENDOR_DOMAIN",
                    "rule_name": "Official Vendor Domain Proof Rule",
                    "label": "Verified Official Vendor",
                    "description": f"Publisher verified against authorized vendor lineage for {brand_info['name']}.",
                    "filter_metadata": {
                        "claimed_brand": brand_info["name"],
                        "publisher_email": author_email,
                        "expected_vendor_domains": valid_domains,
                        "is_official_vendor": True,
                    }
                })

            # Signal: Codebase Size & Effort
            if is_empty_stub and not is_official_vendor:
                machine_signals.append({
                    "signal_id": "SIGNAL_EMPTY_CODE_STUB",
                    "category": "PACKAGE_EFFORT",
                    "severity": "MEDIUM",
                    "score_impact": 15,
                    "confidence": 1.0,
                    "filter_code": "FILTER_EMPTY_STUB",
                    "rule_name": "Empty Name Reservation Stub Rule",
                    "label": "Empty Name Reservation Stub",
                    "description": f"Package contains nearly zero code ({total_loc} LOC, {total_kb} KB), indicating a brand-name holding placeholder.",
                    "filter_metadata": {
                        "total_lines_of_code": total_loc,
                        "total_source_files": total_files,
                        "code_size_bytes": total_bytes,
                        "code_size_tier": size_tier,
                    }
                })

            # Signal: Community Adoption
            if monthly_dl >= 1000:
                machine_signals.append({
                    "signal_id": "SIGNAL_ACTIVE_COMMUNITY_USAGE",
                    "category": "COMMUNITY_ADOPTION",
                    "severity": "INFO",
                    "score_impact": -20,
                    "confidence": 1.0,
                    "filter_code": "FILTER_COMMUNITY_ADOPTION",
                    "rule_name": "Active Community Usage Rule",
                    "label": "Active Community Usage",
                    "description": f"Package has active community adoption with {monthly_dl:,} monthly downloads.",
                    "filter_metadata": {
                        "monthly_downloads": monthly_dl,
                        "adoption_tier": adoption_tier,
                    }
                })

            # Signal: AST Flags
            for f in flags:
                is_crit = "INSTALL_TIME" in f or "LIFECYCLE" in f
                machine_signals.append({
                    "signal_id": "SIGNAL_INSTALL_TIME_CODE_EXECUTION" if is_crit else "SIGNAL_SUSPICIOUS_AST_FLAG",
                    "category": "CODE_ANALYSIS",
                    "severity": "CRITICAL" if is_crit else "HIGH",
                    "score_impact": 35 if is_crit else 15,
                    "confidence": 0.95,
                    "filter_code": "FILTER_AST_INSTALL_EXEC" if is_crit else "FILTER_AST_SUSPICIOUS_CALL",
                    "rule_name": "Static AST Code Execution Rule",
                    "label": "Install-Time Code Execution" if is_crit else "Suspicious Code Pattern",
                    "description": f,
                })

            # Human-readable risk explanations
            risk_reasons: List[str] = []
            if not is_official_vendor:
                risk_reasons.append(
                    f"Brand Impersonation: Claims '{brand_info['name']}' identity, but publisher email '{author_email}' does not match official vendor domain(s) ({', '.join(valid_domains)})."
                )
            risk_reasons.append(
                f"Combinatorial Grammar Filter: Matches AI LLM hallucination template '[framework]-[entity]-[capability]' ({fw}-{entity}-{cap})."
            )
            if is_empty_stub:
                risk_reasons.append(
                    f"Empty Reservation Stub: Package contains only {total_loc} lines of code ({total_kb} KB), functioning as an empty placeholder."
                )
            if monthly_dl >= 1000:
                risk_reasons.append(
                    f"Community Adoption: Active usage with {monthly_dl:,} downloads/month demonstrates developer utility."
                )
            for f in flags:
                risk_reasons.append(f"AST Threat Signal: {f}")

            summary_text = (
                f"Purports to provide {cap.upper()} integration for {fw.capitalize()} targeting '{brand_info['name']}'. "
                f"Published by account '{d.author_username or 'Unknown'}' ({monthly_dl:,} dl/mo, {size_tier}) with threat score {d.threat_score} points."
            )

            # Metric extraction from analysis details
            point_breakdown = d.analysis_details.get("point_rubric_breakdown", {})
            raw_points = int(point_breakdown.get("raw_accumulated_points", d.threat_score))
            sig_quality = int(point_breakdown.get("signal_quality_score", 0))
            crit_count = int(point_breakdown.get("critical_signals_count", len([f for f in flags if "INSTALL_TIME" in f or "SOCKET" in f])))
            active_signals_cnt = int(point_breakdown.get("active_signals_count", len(machine_signals)))
            brand_priority = PRIORITY_BRAND_WEIGHTS.get(entity.lower(), 500)

            # Analysis dictionary
            analysis = {
                "verdict": d.verdict.value,
                "composite_threat_score": d.threat_score,
                "threat_level": threat_level,
                "summary": summary_text,
                "why_flagged": risk_reasons,
                "naming_interpretation": {
                    "matched_grammar_template": grammar_template,
                    "inferred_framework": fw,
                    "inferred_target_brand": brand_info["name"],
                    "inferred_brand_category": brand_info["category"],
                    "inferred_capability": cap,
                    "ai_hallucination_propensity": "HIGH",
                },
                "vendor_authenticity_assessment": {
                    "claimed_brand": brand_info["name"],
                    "expected_vendor_domains": valid_domains,
                    "observed_author_email": author_email,
                    "is_official_vendor": is_official_vendor,
                    "authenticity_verdict": "LEGITIMATE_OFFICIAL" if is_official_vendor else "UNVERIFIED_THIRD_PARTY_SQUAT",
                },
                "codebase_size_assessment": {
                    "lines_of_code": total_loc,
                    "code_size_bytes": total_bytes,
                    "code_size_kb": total_kb,
                    "source_files_count": total_files,
                    "size_tier": size_tier,
                    "is_empty_placeholder": is_empty_stub,
                    "interpretation": (
                        f"Package contains virtually zero functional logic ({total_loc} lines of code across {total_files} file(s), {total_kb} KB), characteristic of an AI name-reservation stub or dormant placeholder."
                        if is_empty_stub
                        else f"Package contains a compact codebase ({total_loc} lines of code across {total_files} file(s), {total_kb} KB)."
                        if total_loc < 150
                        else f"Package contains a substantial implementation codebase ({total_loc} lines of code across {total_files} file(s), {total_kb} KB)."
                    ),
                },
                "community_adoption_assessment": {
                    "monthly_downloads": monthly_dl,
                    "weekly_downloads": weekly_dl,
                    "adoption_tier": adoption_tier,
                    "is_widely_used": monthly_dl >= 1000,
                    "interpretation": (
                        f"Package demonstrates high real-world developer adoption with {monthly_dl:,} monthly downloads, strongly supporting legitimate community utility."
                        if monthly_dl >= 10000
                        else f"Package shows active developer usage ({monthly_dl:,} monthly downloads), indicating genuine community integration adoption."
                        if monthly_dl >= 1000
                        else f"Package has moderate download activity ({monthly_dl:,} monthly downloads)."
                        if monthly_dl >= 100
                        else "Package has negligible download activity (<100 downloads/mo), characteristic of a brand-reservation stub or low-visibility library."
                    ),
                },
                "dormancy_assessment": {
                    "days_dormant": days_dormant,
                    "dormancy_tier": dormancy_tier,
                    "is_sleeper_squat_risk": days_dormant <= 365 and not is_official_vendor,
                    "interpretation": f"Package has been registered for {days_dormant} days ({dormancy_tier}).",
                },
                "point_rubric_evaluation": {
                    "total_score": d.threat_score,
                    "raw_accumulated_points": raw_points,
                    "signal_quality_score": sig_quality,
                    "active_signals_count": active_signals_cnt,
                    "critical_signals_count": crit_count,
                    "brand_priority_weight": brand_priority,
                    "signals": [
                        {
                            "signal_id": s["signal_id"],
                            "points": s["score_impact"],
                            "label": s["label"],
                            "category": s["category"],
                            "filter_code": s["filter_code"],
                        }
                        for s in machine_signals
                    ],
                },
                "attack_vector": {
                    "attack_type": "AI_HALLUCINATION_SLOPSQUATTING",
                    "grammar_filter_matched": grammar_template,
                    "prompt_trigger": f"How do I configure {brand_info['name']} {cap.upper()} in {fw.capitalize()}?",
                    "hallucinated_install_command": install_cmd,
                },
                "remediation": {
                    "official_sdk_alternative": brand_info["official_sdk"],
                    "recommended_action": "BLOCK_AND_MIGRATE" if d.threat_score >= 70 else "AUDIT_BEFORE_USE",
                    "suggested_install_command": f"pip install {brand_info['official_sdk'].split(' ')[0]}" if d.ecosystem == Ecosystem.PYPI else f"npm install {brand_info['official_sdk'].split(' ')[0]}",
                },
                "evidence_signals": machine_signals,
            }

            # Check substantive differences
            current_substantive_hash = _compute_substantive_hash(facts, analysis)
            if prev_record:
                prev_facts = prev_record.get("facts", {})
                prev_analysis = prev_record.get("analysis", {})
                prev_substantive_hash = _compute_substantive_hash(prev_facts, prev_analysis)

                if current_substantive_hash == prev_substantive_hash:
                    # No substantive changes: retain prior updated_at
                    rec_updated_at_iso = prev_updated_at_iso
                else:
                    # Substantive content changed: bump updated_at to now
                    rec_updated_at_iso = now_second_iso
            else:
                # Brand new record: created_at == updated_at
                rec_updated_at_iso = rec_created_at_iso

            # Sync facts timestamps with final resolved created_at and updated_at
            facts["timestamps"]["record_created_at"] = rec_created_at_iso
            facts["timestamps"]["record_updated_at"] = rec_updated_at_iso

            # 1. Generate deep Markdown dossier
            dossier_path = dossiers_dir / d.ecosystem.value / f"{d.package_name}.md"
            # Scoped npm packages (e.g. "@scope/name") contain a '/' in package_name,
            # which implies a subdirectory ("dossiers/npm/@scope/name.md") that doesn't
            # exist yet — matches the same pitfall already handled for the disk cache
            # (DiskCacheManager.save_cached_metadata). Without this, export_all() raised
            # FileNotFoundError on every scoped package once the real npm catalog was
            # synced, aborting run-cycle mid-export.
            dossier_path.parent.mkdir(parents=True, exist_ok=True)
            dossier_content = self._render_rich_markdown_dossier(
                d, upstream_url, summary_text, brand_info, entity, cap, fw, valid_domains, is_official_vendor, risk_reasons, machine_signals, facts, rec_created_at_iso, rec_updated_at_iso
            )
            dossier_path.write_text(dossier_content, encoding="utf-8")
            exported_count += 1

            # Unified typed signal layer — a flat list of signal codes plus the
            # per-signal detail, so a static-file UI can filter by any signal
            # (including brand-new ones) without a schema change.
            record_findings = findings_from_analysis_details(d.analysis_details)
            signal_codes = sorted({f.code for f in record_findings})

            # ==================== 3. UNIFIED TOP-LEVEL RECORD ====================
            record = {
                # Top-level indexed identifiers for search & rendering
                "name": d.package_name,
                "title": f"{d.package_name} ({d.ecosystem.value.upper()})",
                "eco": d.ecosystem.value,
                "score": d.threat_score,
                "threat_level": threat_level,
                "verdict": d.verdict.value,
                "dossier_url": f"/slopsquat/{d.ecosystem.value}/{d.package_name}",
                "upstream_url": upstream_url,
                "published_at": first_pub_iso,
                "first_published_at": first_pub_iso,
                "latest_release_at": latest_rel_iso,
                "created_at": rec_created_at_iso,
                "updated_at": rec_updated_at_iso,
                # Modular detection layer — every signal this package carries.
                "signals": signal_codes,
                "findings": [
                    {
                        "code": f.code, "category": f.category, "severity": f.severity,
                        "score": f.score, "kind": f.kind, "detector": f.detector,
                        "title": f.title, "description": f.description,
                    }
                    for f in record_findings
                ],
                # UI quick facets with multi-signal precision
                "ui_facets": {
                    "root_cause_filter": "FILTER_GRAMMAR_TRIPLET",
                    "signal_codes": signal_codes,
                    "vendor_status": "OFFICIAL_VENDOR" if is_official_vendor else "UNVERIFIED_THIRD_PARTY",
                    "code_status": "INSTALL_HOOK_DETECTED" if has_install_hook else "EMPTY_STUB" if is_empty_stub else "CLEAN_OR_BENIGN",
                    "has_install_hook": has_install_hook,
                    "has_network_socket": has_network_socket_flag,
                    "has_env_vars_access": any("SOURCE_CODE_ENV_VARS_ACCESS" in f for f in flags),
                    "has_pth_execution": bool(d.analysis_details.get("has_pth_execution", False) or any("PYTHON_PTH_CODE_EXECUTION" in f for f in flags)),
                    "has_exfiltration_destination": bool(d.analysis_details.get("has_exfiltration_destination", False) or any("EXFILTRATION_DESTINATION_DETECTED" in f for f in flags)),
                    "has_credential_harvesting": bool(d.analysis_details.get("has_credential_harvesting", False) or any("CREDENTIAL_PATH_HARVESTING" in f or "SOURCE_CODE_CONFIRMED_STEALER" in f for f in flags)),
                    "has_bundled_binary": bool(d.analysis_details.get("has_bundled_binary", False) or any("BUNDLED_NATIVE_BINARY" in f for f in flags)),
                    "is_deprecated": is_dep,
                    "code_size_tier": size_tier,
                    "lines_of_code": total_loc,
                    "code_size_kb": total_kb,
                    "is_empty_stub": is_empty_stub,
                    "release_version": d.release_version or "0.1.0",
                    "major_version": major_ver,
                    "is_inflated_version": is_inflated_version,
                    "is_calver": is_calver_year,
                    "has_internal_keyword": has_internal_kw,
                    "version_filter": "INFLATED_MAJOR_VERSION" if is_inflated_version else "STANDARD_VERSION",
                    "major_version_tier": (
                        "CALENDAR_YEAR_CALVER" if is_calver_year
                        else "MAJOR_50_PLUS" if (major_ver or 0) >= 50
                        else "MAJOR_10_TO_49" if (major_ver or 0) >= 10
                        else "MAJOR_5_TO_9" if (major_ver or 0) >= 5
                        else "MAJOR_0_TO_4"
                    ),
                    "monthly_downloads": monthly_dl,
                    "adoption_tier": adoption_tier,
                    "dormancy_status": dormancy_tier,
                    "days_since_first_publish": days_dormant,
                    "published_at": first_pub_iso,
                    "first_published_at": first_pub_iso,
                    "latest_release_at": latest_rel_iso,
                    "brand_tag": entity,
                    "framework_tag": fw,
                    "capability_tag": cap,
                    "signals_count": active_signals_cnt,
                    "critical_signals_count": crit_count,
                    "signal_quality_score": sig_quality,
                    "raw_score": raw_points,
                    "brand_priority": brand_priority,
                    "badge_color": "red" if d.threat_score >= 80 else "orange" if d.threat_score >= 50 else "yellow" if d.threat_score >= 25 else "green",
                },
                # STRICT SEPARATION: Facts vs Analysis
                "facts": facts,
                "analysis": analysis,
            }

            all_search_records.append(record)
            if d.ecosystem == Ecosystem.PYPI:
                pypi_search_records.append(record)
            elif d.ecosystem == Ecosystem.NPM:
                npm_search_records.append(record)

            # Build feed record
            feed_records.append({
                "detection_id": d.detection_id,
                "ecosystem": d.ecosystem.value,
                "package_name": d.package_name,
                "version": d.release_version,
                "threat_score": d.threat_score,
                "threat_level": threat_level,
                "verdict": d.verdict.value,
                "upstream_url": upstream_url,
                "dossier_url": f"/slopsquat/{d.ecosystem.value}/{d.package_name}",
                "published_at": first_pub_iso,
                "created_at": rec_created_at_iso,
                "updated_at": rec_updated_at_iso,
                "facts": facts,
                "analysis": analysis,
            })

        # ==================== SORTING: Prioritize by Signal Quality, Severity & Brand ====================
        verdict_order = {
            "MALICIOUS": 5,
            "SUSPICIOUS": 4,
            "SQUATTED_STUB": 3,
            "BENIGN_COMMUNITY": 2,
            "VERIFIED_OFFICIAL": 1,
        }

        def _pkg_sort_key(r: Dict[str, Any]) -> Tuple[int, int, int, int, int, int, int, str]:
            v_val = r.get("verdict", "")
            sc = int(r.get("score", 0) if "score" in r else r.get("threat_score", 0))
            ui_facets = r.get("ui_facets", {})
            raw_pts = int(ui_facets.get("raw_score", sc))
            sig_qual = int(ui_facets.get("signal_quality_score", 0))
            crit_cnt = int(ui_facets.get("critical_signals_count", 0))
            sig_cnt = int(ui_facets.get("signals_count", 0))
            brand_wt = int(ui_facets.get("brand_priority", 500))
            created = r.get("created_at", "")
            return (
                verdict_order.get(v_val, 0),
                sc,
                sig_qual,
                raw_pts,
                crit_cnt,
                sig_cnt,
                brand_wt,
                created,
            )

        all_search_records.sort(key=_pkg_sort_key, reverse=True)
        pypi_search_records.sort(key=_pkg_sort_key, reverse=True)
        npm_search_records.sort(key=_pkg_sort_key, reverse=True)
        feed_records.sort(key=_pkg_sort_key, reverse=True)

        # Write unified master search index. "all_packages_index.json" is kept as a
        # symlink alias to "package_search_index.json" rather than a second full copy —
        # both filenames were previously written with byte-identical content every run
        # (336MB x2), presumably for backward compat with whichever name the
        # routes reference; a symlink preserves both paths at half the storage.
        # Compact JSON (separators=(',', ':')) avoids massive multi-hundred-megabyte string
        # allocations on memory-constrained shared hosts.
        primary_index_path = search_dir / "package_search_index.json"
        primary_index_path.write_text(json.dumps(all_search_records, separators=(",", ":")), encoding="utf-8")

        alias_index_path = search_dir / "all_packages_index.json"
        if alias_index_path.exists() or alias_index_path.is_symlink():
            alias_index_path.unlink()
        try:
            alias_index_path.symlink_to(primary_index_path.name)
        except OSError:
            # Filesystem doesn't support symlinks (or lacks permission) — fall back to
            # a full copy so the alias path still resolves.
            alias_index_path.write_text(json.dumps(all_search_records, separators=(",", ":")), encoding="utf-8")

        # Write ecosystem-partitioned search indexes
        (search_dir / "pypi_index.json").write_text(
            json.dumps(pypi_search_records, separators=(",", ":")), encoding="utf-8"
        )
        (search_dir / "npm_index.json").write_text(
            json.dumps(npm_search_records, separators=(",", ":")), encoding="utf-8"
        )

        # ==================== MODULAR DETECTION LAYER ARTIFACTS ====================
        # signal_catalog.json  -> labels/badges/descriptions for the facet sidebar
        # signal_stats.json    -> package/instance counts per signal ("83 in 83 packages")
        (search_dir / "signal_catalog.json").write_text(
            json.dumps(catalog_as_rows(), indent=2), encoding="utf-8"
        )
        _sig_pkgs: Dict[str, set] = {}
        _sig_cat: Dict[str, str] = {}
        for rec in all_search_records:
            for code in rec.get("ui_facets", {}).get("signal_codes", []):
                _sig_pkgs.setdefault(code, set()).add((rec["eco"], rec["name"]))
        for row in catalog_as_rows():
            _sig_cat[row["signal_code"]] = row["category"]
        signal_stats = sorted(
            (
                {
                    "signal_code": code,
                    "category": _sig_cat.get(code, "GENERAL"),
                    "package_count": len(pkgs),
                }
                for code, pkgs in _sig_pkgs.items()
            ),
            key=lambda r: (-r["package_count"], r["signal_code"]),
        )
        (search_dir / "signal_stats.json").write_text(
            json.dumps(signal_stats, indent=2), encoding="utf-8"
        )

        # Write feed
        (feed_dir / "latest_slopsquats.json").write_text(
            json.dumps(feed_records, separators=(",", ":")), encoding="utf-8"
        )


        # ==================== 4. AUTHOR & DOMAIN REVERSE INDEXES ====================
        authors_dir = self.output_dir / "authors"
        authors_dir.mkdir(parents=True, exist_ok=True)

        # Exclude BENIGN_COMMUNITY from author reverse-indexes too — an author's
        # unrelated benign packages shouldn't inflate their threat profile.
        publishable_detections = [d for d in detections if d.verdict != ThreatVerdict.BENIGN_COMMUNITY]
        email_indexes, domain_indexes, authors_summary = self._build_author_reverse_indexes(publishable_detections, datetime.now(timezone.utc))

        high_risk_domains = [d for d in domain_indexes if d.get("is_valid_domain") and (d.get("meets_high_volume_threshold") or d.get("is_high_risk_domain"))]

        # Write to search/ for instant client lookup
        (search_dir / "author_emails_index.json").write_text(
            json.dumps(email_indexes, indent=2), encoding="utf-8"
        )
        (search_dir / "author_domains_index.json").write_text(
            json.dumps(domain_indexes, indent=2), encoding="utf-8"
        )
        (search_dir / "high_risk_domains_index.json").write_text(
            json.dumps(high_risk_domains, indent=2), encoding="utf-8"
        )
        (search_dir / "authors_summary.json").write_text(
            json.dumps(authors_summary, indent=2), encoding="utf-8"
        )

        # Write to authors/ directory for dedicated endpoint mirroring
        (authors_dir / "author_emails.json").write_text(
            json.dumps(email_indexes, indent=2), encoding="utf-8"
        )
        (authors_dir / "author_domains.json").write_text(
            json.dumps(domain_indexes, indent=2), encoding="utf-8"
        )
        (authors_dir / "high_risk_domains.json").write_text(
            json.dumps(high_risk_domains, indent=2), encoding="utf-8"
        )
        (authors_dir / "summary.json").write_text(
            json.dumps(authors_summary, indent=2), encoding="utf-8"
        )

        # Mark unexported as exported
        if unexported:
            ids = [u.detection_id for u in unexported]
            await self.repository.mark_detections_exported(ids)

        return {
            "output_directory": str(self.output_dir.resolve()),
            "total_dossiers_generated": exported_count,
            "unified_search_entries": len(all_search_records),
            "pypi_search_entries": len(pypi_search_records),
            "npm_search_entries": len(npm_search_records),
            "feed_entries": len(feed_records),
            "unique_author_emails": len(email_indexes),
            "unique_author_domains": len(domain_indexes),
            "outlier_author_emails": authors_summary["outlier_emails_count"],
            "outlier_author_domains": authors_summary["outlier_domains_count"],
            "skipped_benign_count": skipped_benign_count,
            "cleaned_stale_dossiers_count": cleaned_stale_dossiers_count,
        }

    def _render_rich_markdown_dossier(
        self,
        detection: SquatDetection,
        upstream_url: str,
        summary_text: str,
        brand_info: Dict[str, str],
        entity: str,
        cap: str,
        fw: str,
        valid_domains: List[str],
        is_author_verified: bool,
        risk_reasons: List[str],
        machine_signals: List[Dict[str, Any]],
        facts: Dict[str, Any],
        created_at_iso: str,
        updated_at_iso: str,
    ) -> str:
        """Render a deep, multi-section forensic incident dossier with facts vs analysis."""
        flags = detection.analysis_details.get("flags", [])
        line_details = detection.analysis_details.get("line_details", [])
        author_email = detection.analysis_details.get("author_email", "Unverified")

        domains_formatted = ", ".join([f"`@{d}`" for d in valid_domains])
        author_status = "✅ Official Verified Domain" if is_author_verified else f"🚨 Third-Party Unverified (Expected: {domains_formatted})"

        frontmatter_flags = "\n".join([f'  - "{f}"' for f in flags]) or '  - "No active malicious hooks detected (clean or name-reservation stub)"'
        frontmatter_reasons = "\n".join([f'  - "{r}"' for r in risk_reasons])
        frontmatter_filter_codes = "\n".join([f'  - "{s["filter_code"]}"' for s in machine_signals])

        install_command = f"pip install {detection.package_name}" if detection.ecosystem == Ecosystem.PYPI else f"npm install {detection.package_name}"

        code_metrics = facts.get("code_metrics", {})
        code_tier_label = "🪹 Empty Name-Reservation Stub" if code_metrics.get("is_empty_stub") else f"📦 {code_metrics.get('code_size_tier', 'UNKNOWN')}"

        usage_metrics = facts.get("usage_metrics", {})
        monthly_dl = usage_metrics.get("monthly_downloads", 0)
        adoption_tier = usage_metrics.get("adoption_tier", "UNKNOWN")

        return f"""---
slug: slopsquat-{detection.ecosystem.value}-{detection.package_name}
title: "Slopsquatting Threat Analysis: {detection.package_name}"
ecosystem: {detection.ecosystem.value}
package_name: "{detection.package_name}"
published_at: "{format_iso_seconds(detection.published_at)}"
discovered_at: "{format_iso_seconds(detection.discovered_at)}"
created_at: "{created_at_iso}"
updated_at: "{updated_at_iso}"
threat_score: {detection.threat_score}
threat_level: "{calculate_threat_level(detection.threat_score)}"
verdict: "{detection.verdict.value}"
author_username: "{detection.author_username or 'Unknown'}"
author_email: "{author_email}"
package_version: "{detection.release_version}"
major_version: {facts.get('major_version', 0)}
is_inflated_version_risk: {str(facts.get('is_inflated_version_risk', False)).lower()}
upstream_registry_url: "{upstream_url}"
monthly_downloads: {monthly_dl}
adoption_tier: "{adoption_tier}"
lines_of_code: {code_metrics.get('total_lines_of_code', 0)}
code_size_bytes: {code_metrics.get('total_code_size_bytes', 0)}
code_size_tier: "{code_metrics.get('code_size_tier', 'UNKNOWN')}"
is_empty_stub: {str(code_metrics.get('is_empty_stub', False)).lower()}

impersonated_brand: "{brand_info['name']}"
brand_category: "{brand_info['category']}"
official_sdk_alternative: "{brand_info['official_sdk']}"
matched_filter_rules:
{frontmatter_filter_codes}
tags:
  - "slopsquatting"
  - "supply-chain"
  - "ai-hallucination"
  - "{detection.ecosystem.value}-threat"
why_suspicious:
{frontmatter_reasons}
ast_flags:
{frontmatter_flags}
---

# Threat Dossier: `{detection.package_name}`

## 1. Verified Facts (Observable Ground Truth)

| Fact Attribute | Observable Ground Truth | Source / Verification |
| :--- | :--- | :--- |
| **Package Name** | `{facts['package_name']}` | Upstream Registry Index |
| **Ecosystem** | `{detection.ecosystem.value.upper()}` | Public Registry API |
| **Publisher Account** | `{facts['author_username']}` | Registrant Account Record |
| **Publisher Email** | `{facts['author_email']}` | Package Metadata |
| **Email Domain** | `@{facts['author_email_domain']}` | Extracted Domain |
| **Homepage URL** | [{facts['homepage_url'] or 'None Provided'}]({facts['homepage_url'] or upstream_url}) | Package Metadata |
| **Release Version** | `{facts['release_version']}` (Major: `{facts.get('major_version', 0)}`) | Latest Published Wheel/Tarball |
| **Version Confusion Risk** | `{'🚨 High Risk (Inflated Major Version)' if facts.get('is_inflated_version_risk') else 'Normal Version Progression'}` | SemVer Lifecycle Audit |
| **First Published** | `{facts['timestamps']['first_published_at']}` | Registry Timestamp |
| **Latest Release** | `{facts['timestamps']['latest_release_at']}` | Registry Timestamp |
| **Discovered By Sentinel** | `{facts['timestamps']['first_detected_by_sentinel_at']}` | Sentinel Ingestion Time |
| **Record Created** | `{facts['timestamps']['record_created_at']}` | Database Ingestion Time |
| **Last Updated** | `{facts['timestamps']['record_updated_at']}` | Database Update Time |
| **Monthly Downloads** | `{monthly_dl:,} downloads/mo` | Public Registry Stats API |
| **Adoption Classification** | `{adoption_tier}` | Community Usage Monitor |
| **Total Source Files** | `{code_metrics.get('total_source_files', 1)} file(s)` | Source Tree Scan |
| **Lines of Code (LOC)** | `{code_metrics.get('total_lines_of_code', 0)} LOC` | Static AST Line Parser |
| **Uncompressed Code Size** | `{code_metrics.get('total_code_size_kb', 0.0)} KB ({code_metrics.get('total_code_size_bytes', 0):,} bytes)` | Codebase Extractor |
| **Codebase Size Tier** | `{code_tier_label}` | Code Effort Classifier |
| **Days Since Publication** | `{facts['lifespan']['days_since_first_publication']} days` | Timestamp Delta |
| **AST Install Hooks** | `{facts['ast_code_inspection']['has_install_time_hooks']}` | Bytecode AST Parser |


---

## 2. Threat Analysis & Interpretations

### Executive Summary:
**{summary_text}**

* **Threat Score**: **{detection.threat_score} points** ({calculate_threat_level(detection.threat_score)})
* **Security Verdict**: **`{detection.verdict.value}`**
* **Targeted Brand**: **{brand_info['name']}** (`{brand_info['category']}`)
* **Publisher Authenticity**: {author_status}
* **Safe Official Alternative**: **`{brand_info['official_sdk']}`**

### Key Suspicious Interpretations:
{chr(10).join([f'* ⚠️ **{r}**' for r in risk_reasons])}

---

## 3. Upstream References & External Links
* 🔗 **Official Registry Page**: [{detection.package_name} on {detection.ecosystem.value.upper()}]({upstream_url})
* 🛡️ **Threat Search & Dossier**: [View on the portal](/slopsquat/{detection.ecosystem.value}/{detection.package_name})
* 🏢 **Target Brand Homepage**: [Official {brand_info['name']} Documentation](https://{valid_domains[0]})

---

## 4. AI Hallucination & Supply Chain Attack Vector

```
[ Developer Prompt to LLM ]
"How do I configure {brand_info['name']} {cap.upper()} in {fw.capitalize()}?"
               │
               ▼
[ AI Code Generation (ChatGPT / Copilot / Claude) ]
```python
# LLM Hallucinated Dependency:
{install_command}
```
               │
               ▼
[ Threat Execution ]
Attacker registers `{detection.package_name}` on {detection.ecosystem.value.upper()}
Developer runs `{install_command}` -> Malicious payload executed
```

---

## 5. Technical AST & Bytecode Inspection
{self._render_flags_markdown(flags, line_details)}

---

## 6. Remediation & Incident Response Playbook

### Immediate Actions:
#### 1. Audit Dependencies
```bash
sentinel check requirements.txt
```

#### 2. Configure Repository Blocklist
Add `{detection.package_name}` to your internal Artifactory / Nexus / pip proxy blocklist.

#### 3. Use Official Vendor SDK
Replace with vendor-supported library:
```bash
pip install {brand_info['official_sdk'].split(' ')[0]}
```

---
*Report automatically generated by Sentinel.*
"""

    def _render_flags_markdown(self, flags: List[str], line_details: List[str]) -> str:
        if not flags:
            return "* ℹ️ No active malicious install hooks detected (classified as **clean community code** or **name-reservation stub**)."

        out = []
        for f in flags:
            out.append(f"* 🚨 **{f}**")
        if line_details:
            out.append("\n**Line Breakdown from Source AST:**")
            for ld in line_details:
                out.append(f"* `{ld}`")
        return "\n".join(out)

    def _build_author_reverse_indexes(
        self,
        detections: List[SquatDetection],
        now_utc: datetime,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
        """
        Build a high-performance reverse index aggregating packages by author_email
        and author_email_domain with publication velocity, threat heuristics, and outlier flags.
        """
        if now_utc.tzinfo is None:
            now_utc = now_utc.replace(tzinfo=timezone.utc)

        emails_map: Dict[str, Dict[str, Any]] = {}
        domains_map: Dict[str, Dict[str, Any]] = {}

        import re

        for d in detections:
            author_user = (d.author_username or "").strip()
            raw_email = (d.analysis_details.get("author_email") or "").strip()

            from sentinel.core.normalizers import extract_clean_email_and_domain
            clean_email, clean_domain = extract_clean_email_and_domain(raw_email or author_user)

            if clean_email and clean_domain:
                email = clean_email
                domain = clean_domain
                is_valid_email = True
            elif author_user and author_user.lower() not in ("unknown", "none", "unspecified"):
                email = f"account:{author_user.lower()}"
                domain = "user_accounts"
                is_valid_email = False
            else:
                email = "unspecified_or_anonymous"
                domain = "unspecified_or_anonymous"
                is_valid_email = False

            pub_dt = d.published_at or d.first_published_at or now_utc
            if pub_dt.tzinfo is None:
                pub_dt = pub_dt.replace(tzinfo=timezone.utc)

            delta_days = max(0.0, (now_utc - pub_dt).total_seconds() / 86400.0)
            is_1d = delta_days <= 1.0
            is_1w = delta_days <= 7.0
            is_1m = delta_days <= 30.0
            is_1y = delta_days <= 365.0

            score = d.threat_score
            verdict_val = d.verdict.value
            is_questionable = score >= 70 or verdict_val in ("SUSPICIOUS", "MALICIOUS", "SQUATTED_STUB")
            is_malicious = verdict_val == "MALICIOUS"
            is_suspicious = verdict_val == "SUSPICIOUS"
            is_stub = verdict_val == "SQUATTED_STUB" or d.analysis_details.get("code_metrics", {}).get("is_empty_stub", False)
            is_clean = verdict_val in ("VERIFIED_OFFICIAL", "BENIGN_COMMUNITY")
            brand = d.analysis_details.get("entity", "").strip().lower()
            eco = d.ecosystem.value
            flags = d.analysis_details.get("flags", [])
            code_metrics = d.analysis_details.get("code_metrics", {})
            loc = code_metrics.get("total_lines_of_code", 0)
            size_tier = code_metrics.get("code_size_tier", "UNKNOWN")

            pkg_entry = {
                "name": d.package_name,
                "ecosystem": eco,
                "release_version": d.release_version or "0.1.0",
                "author_username": d.author_username or "Unknown",
                "threat_score": score,
                "threat_level": calculate_threat_level(score),
                "verdict": verdict_val,
                "is_questionable": is_questionable,
                "is_empty_stub": is_stub,
                "lines_of_code": loc,
                "code_size_tier": size_tier,
                "ast_flags": flags,
                "monthly_downloads": int(d.analysis_details.get("usage_metrics", {}).get("monthly_downloads", 0) or 0),
                "published_at": format_iso_seconds(pub_dt),
                "days_since_publication": round(delta_days, 1),
                "targeted_brand": brand,
                "dossier_url": f"/slopsquat/{eco}/{d.package_name}",
            }

            # 1. Update Email Map
            if email not in emails_map:
                emails_map[email] = {
                    "author_email": email,
                    "author_email_domain": domain,
                    "is_valid_email": is_valid_email,
                    "associated_author_names": set(),
                    "seen_pkgs": set(),
                    "packages": [],
                    "targeted_brands": set(),
                    "ecosystems": set(),
                    "scores": [],
                    "malicious_count": 0,
                    "suspicious_count": 0,
                    "stub_count": 0,
                    "clean_count": 0,
                    "questionable_count": 0,
                    "pub_1d": 0,
                    "pub_1w": 0,
                    "pub_1m": 0,
                    "pub_1y": 0,
                }
            e_data = emails_map[email]
            if author_user and author_user.lower() not in ("unknown", "none"):
                e_data["associated_author_names"].add(author_user)
            pkg_key = (eco, d.package_name)
            if pkg_key not in e_data["seen_pkgs"]:
                e_data["seen_pkgs"].add(pkg_key)
                e_data["packages"].append(pkg_entry)
                if brand:
                    e_data["targeted_brands"].add(brand)
                e_data["ecosystems"].add(eco)
                e_data["scores"].append(score)
                if is_malicious:
                    e_data["malicious_count"] += 1
                if is_suspicious:
                    e_data["suspicious_count"] += 1
                if is_stub:
                    e_data["stub_count"] += 1
                if is_clean:
                    e_data["clean_count"] += 1
                if is_questionable:
                    e_data["questionable_count"] += 1
                if is_1d:
                    e_data["pub_1d"] += 1
                if is_1w:
                    e_data["pub_1w"] += 1
                if is_1m:
                    e_data["pub_1m"] += 1
                if is_1y:
                    e_data["pub_1y"] += 1

            # 2. Update Domain Map
            if domain not in domains_map:
                domains_map[domain] = {
                    "author_email_domain": domain,
                    "is_valid_domain": is_valid_email and domain not in ("user_accounts", "unspecified_or_anonymous"),
                    "associated_emails": set(),
                    "associated_author_names": set(),
                    "seen_pkgs": set(),
                    "packages": [],
                    "targeted_brands": set(),
                    "ecosystems": set(),
                    "scores": [],
                    "malicious_count": 0,
                    "suspicious_count": 0,
                    "stub_count": 0,
                    "clean_count": 0,
                    "questionable_count": 0,
                    "pub_1d": 0,
                    "pub_1w": 0,
                    "pub_1m": 0,
                    "pub_1y": 0,
                }
            d_data = domains_map[domain]
            if is_valid_email:
                d_data["associated_emails"].add(email)
            if author_user and author_user.lower() not in ("unknown", "none"):
                d_data["associated_author_names"].add(author_user)
            if pkg_key not in d_data["seen_pkgs"]:
                d_data["seen_pkgs"].add(pkg_key)
                d_data["packages"].append(pkg_entry)
                if brand:
                    d_data["targeted_brands"].add(brand)
                d_data["ecosystems"].add(eco)
                d_data["scores"].append(score)
                if is_malicious:
                    d_data["malicious_count"] += 1
                if is_suspicious:
                    d_data["suspicious_count"] += 1
                if is_stub:
                    d_data["stub_count"] += 1
                if is_clean:
                    d_data["clean_count"] += 1
                if is_questionable:
                    d_data["questionable_count"] += 1
                if is_1d:
                    d_data["pub_1d"] += 1
                if is_1w:
                    d_data["pub_1w"] += 1
                if is_1m:
                    d_data["pub_1m"] += 1
                if is_1y:
                    d_data["pub_1y"] += 1

        # Transform and score email records
        email_records: List[Dict[str, Any]] = []
        for email, ed in emails_map.items():
            total = len(ed["packages"])
            q_cnt = ed["questionable_count"]
            q_ratio = round(q_cnt / total, 3) if total > 0 else 0.0
            max_sc = max(ed["scores"]) if ed["scores"] else 0
            avg_sc = round(sum(ed["scores"]) / total, 1) if total > 0 else 0.0
            brands_list = sorted(list(ed["targeted_brands"]))
            ecos_list = sorted(list(ed["ecosystems"]))
            author_names = sorted(list(ed["associated_author_names"]))

            outlier_reasons: List[str] = []
            if ed["malicious_count"] >= 1:
                outlier_reasons.append(f"ACTIVE_MALWARE_AUTHOR: {ed['malicious_count']} weaponized package(s) detected")
            if ed["pub_1w"] >= 3:
                outlier_reasons.append(f"BURST_REGISTRATION_VELOCITY: {ed['pub_1w']} packages published in last 7 days")
            elif ed["pub_1m"] >= 5:
                outlier_reasons.append(f"HIGH_MONTHLY_VELOCITY: {ed['pub_1m']} packages published in last 30 days")
            if len(brands_list) >= 3 and ed["author_email_domain"] not in ("microsoft.com", "stripe.com", "google.com", "amazon.com", "apple.com", "github.com", "okta.com", "auth0.com", "supabase.io"):
                outlier_reasons.append(f"MULTI_BRAND_TARGETING: Impersonates {len(brands_list)} distinct vendor brands ({', '.join(brands_list[:4])})")
            if q_cnt >= 3 or (total >= 2 and q_ratio >= 0.75):
                outlier_reasons.append(f"HIGH_QUESTIONABLE_RATIO: {q_cnt}/{total} questionable packages ({int(q_ratio * 100)}%)")
            if ed["stub_count"] >= 3:
                outlier_reasons.append(f"MASS_STUB_HOLDING: {ed['stub_count']} empty placeholder stubs")

            is_outlier = len(outlier_reasons) > 0 and ed["is_valid_email"]
            anomaly_score = (
                (ed["malicious_count"] * 50)
                + (q_cnt * 20)
                + (len(brands_list) * 15)
                + (ed["pub_1w"] * 10)
                + (ed["pub_1m"] * 5)
            )

            email_records.append({
                "author_email": email,
                "author_email_domain": ed["author_email_domain"],
                "is_valid_email": ed["is_valid_email"],
                "associated_author_names": author_names,
                "is_outlier": is_outlier,
                "anomaly_score": anomaly_score,
                "outlier_reasons": outlier_reasons,
                "total_packages_count": total,
                "questionable_packages_count": q_cnt,
                "malicious_packages_count": ed["malicious_count"],
                "suspicious_packages_count": ed["suspicious_count"],
                "squatted_stub_count": ed["stub_count"],
                "clean_or_official_count": ed["clean_count"],
                "questionable_ratio": q_ratio,
                "max_threat_score": max_sc,
                "avg_threat_score": avg_sc,
                "recency_metrics": {
                    "published_last_1_day": ed["pub_1d"],
                    "published_last_1_week": ed["pub_1w"],
                    "published_last_1_month": ed["pub_1m"],
                    "published_last_1_year": ed["pub_1y"],
                },
                "targeted_brands": brands_list,
                "targeted_brands_count": len(brands_list),
                "ecosystems": ecos_list,
                "packages": sorted(ed["packages"], key=lambda p: (p["threat_score"], p["name"]), reverse=True),
            })

        # Sort email records: Valid identifiable emails with highest risk first, anonymous at the bottom
        email_records.sort(
            key=lambda r: (
                1 if r["is_valid_email"] else 0,
                1 if r["is_outlier"] else 0,
                r["malicious_packages_count"],
                r["anomaly_score"],
                r["questionable_packages_count"],
                r["max_threat_score"],
                r["avg_threat_score"],
                r["total_packages_count"],
            ),
            reverse=True,
        )

        # Transform and score domain records
        domain_records: List[Dict[str, Any]] = []
        for domain, dd in domains_map.items():
            total = len(dd["packages"])
            q_cnt = dd["questionable_count"]
            q_ratio = round(q_cnt / total, 3) if total > 0 else 0.0
            max_sc = max(dd["scores"]) if dd["scores"] else 0
            avg_sc = round(sum(dd["scores"]) / total, 1) if total > 0 else 0.0
            brands_list = sorted(list(dd["targeted_brands"]))
            ecos_list = sorted(list(dd["ecosystems"]))
            associated_emails_list = sorted(list(dd["associated_emails"]))
            associated_names_list = sorted(list(dd["associated_author_names"]))

            is_public_esp = domain.lower() in PUBLIC_EMAIL_PROVIDERS
            is_disposable = domain.lower() in DISPOSABLE_EMAIL_DOMAINS
            is_vendor = any(domain.lower() in [v.lower() for v in suffixes] for suffixes in VENDOR_DOMAINS.values())

            if is_disposable:
                domain_type = "DISPOSABLE_OR_ANONYMOUS"
                domain_type_label = "Disposable / Throwaway Email Service"
                domain_type_note = "Temporary burner email service frequently leveraged for ephemeral attacker registrations."
            elif is_public_esp:
                domain_type = "FREE_PUBLIC_ESP"
                domain_type_label = "Generic Free Public Email Provider"
                domain_type_note = "Generic public email service shared by millions of unrelated independent developers. High raw package count reflects ESP market share rather than a coordinated entity. Overall ecosystem fraud rate is low; individual risk must be evaluated per mailbox (author_email)."
            elif is_vendor:
                domain_type = "OFFICIAL_VENDOR"
                domain_type_label = "Verified Official Tech Vendor Domain"
                domain_type_note = "Recognized official infrastructure or SaaS vendor corporate domain."
            elif dd["is_valid_domain"]:
                domain_type = "CUSTOM_ORGANIZATIONAL"
                domain_type_label = "Custom / Private Organization Domain"
                domain_type_note = "Private custom domain owned by a specific organization, team, or developer."
            else:
                domain_type = "UNLISTED_OR_ANONYMOUS"
                domain_type_label = "Unlisted / Anonymous"
                domain_type_note = "No domain specified."

            meets_high_vol = total >= 10
            vol_tier = "HIGH_VOLUME (10+)" if total >= 10 else "MEDIUM_VOLUME (5-9)" if total >= 5 else "LOW_VOLUME (1-4)"
            is_high_risk = (
                (domain_type in ("CUSTOM_ORGANIZATIONAL", "DISPOSABLE_OR_ANONYMOUS") and (q_ratio >= 0.50 or dd["malicious_count"] >= 1))
                or (meets_high_vol and q_ratio >= 0.50)
                or (dd["malicious_count"] >= 1)
            )

            outlier_reasons = []
            if dd["malicious_count"] >= 1:
                outlier_reasons.append(f"ACTIVE_MALWARE_DOMAIN: {dd['malicious_count']} weaponized package(s) hosted under domain")
            if is_disposable:
                outlier_reasons.append("DISPOSABLE_BURNER_DOMAIN: High-risk throwaway temporary email provider")
            if meets_high_vol and not is_public_esp and q_ratio >= 0.70:
                outlier_reasons.append(f"HIGH_VOLUME_FRAUD_CONCENTRATION: {total} packages published with {round(q_ratio * 100, 1)}% potential fraud rate")
            if is_public_esp and meets_high_vol:
                outlier_reasons.append(f"PUBLIC_ESP_HIGH_VOLUME: {total} packages published by {len(associated_emails_list)} independent accounts across {len(brands_list)} brand namespaces (ESP ecosystem fraud rate is naturally low)")
            if dd["pub_1w"] >= 5 and not is_public_esp:
                outlier_reasons.append(f"DOMAIN_BURST_VELOCITY: {dd['pub_1w']} packages published across custom domain in last 7 days")
            elif dd["pub_1m"] >= 10 and not is_public_esp:
                outlier_reasons.append(f"HIGH_MONTHLY_DOMAIN_VELOCITY: {dd['pub_1m']} packages published in last 30 days")
            if len(brands_list) >= 3 and domain_type == "CUSTOM_ORGANIZATIONAL":
                outlier_reasons.append(f"MULTI_BRAND_DOMAIN_CONCENTRATION: Custom domain associated with {len(brands_list)} target brands ({', '.join(brands_list[:4])})")
            if (q_cnt >= 3 or (total >= 2 and q_ratio >= 0.75)) and not is_public_esp and domain_type == "CUSTOM_ORGANIZATIONAL":
                outlier_reasons.append(f"HIGH_QUESTIONABLE_DOMAIN_RATIO: {q_cnt}/{total} questionable packages ({int(q_ratio * 100)}%)")
            if dd["stub_count"] >= 5 and not is_public_esp:
                outlier_reasons.append(f"MASS_DOMAIN_STUB_HOLDING: {dd['stub_count']} empty placeholder stubs")

            is_outlier = len(outlier_reasons) > 0 and dd["is_valid_domain"]
            anomaly_score = (
                (dd["malicious_count"] * 50)
                + (q_cnt * 20 if not is_public_esp else q_cnt * 5)
                + (len(brands_list) * 15 if not is_public_esp else 10)
                + (dd["pub_1w"] * 10 if not is_public_esp else 5)
                + (dd["pub_1m"] * 5 if not is_public_esp else 2)
                + (len(associated_emails_list) * 5 if not is_public_esp else 2)
                + (50 if is_disposable else 0)
                + (40 if domain_type == "CUSTOM_ORGANIZATIONAL" and dd["malicious_count"] >= 1 else 0)
            )

            domain_records.append({
                "author_email_domain": domain,
                "domain_type": domain_type,
                "domain_type_label": domain_type_label,
                "domain_type_note": domain_type_note,
                "is_generic_public_esp": is_public_esp,
                "is_disposable_email": is_disposable,
                "is_valid_domain": dd["is_valid_domain"],
                "meets_high_volume_threshold": meets_high_vol,
                "is_high_risk_domain": is_high_risk,
                "volume_tier": vol_tier,
                "is_outlier": is_outlier,
                "anomaly_score": anomaly_score,
                "potential_fraud_rate": q_ratio,
                "fraud_percentage": f"{round(q_ratio * 100, 1)}%",
                "avg_threat_score": avg_sc,
                "max_threat_score": max_sc,
                "total_packages_count": total,
                "questionable_packages_count": q_cnt,
                "malicious_packages_count": dd["malicious_count"],
                "suspicious_packages_count": dd["suspicious_count"],
                "squatted_stub_count": dd["stub_count"],
                "clean_or_official_count": dd["clean_count"],
                "questionable_ratio": q_ratio,
                "outlier_reasons": outlier_reasons,
                "total_associated_emails_count": len(associated_emails_list),
                "recency_metrics": {
                    "published_last_1_day": dd["pub_1d"],
                    "published_last_1_week": dd["pub_1w"],
                    "published_last_1_month": dd["pub_1m"],
                    "published_last_1_year": dd["pub_1y"],
                },
                "associated_author_emails": associated_emails_list,
                "associated_author_names": associated_names_list,
                "targeted_brands": brands_list,
                "targeted_brands_count": len(brands_list),
                "ecosystems": ecos_list,
                "packages": sorted(dd["packages"], key=lambda p: (p["threat_score"], p["name"]), reverse=True),
            })

        # Sort domain records:
        # 1. Valid domains first
        # 2. Confirmed malicious & custom/disposable high-risk domains first
        # 3. High volume domains with high fraud rate
        domain_records.sort(
            key=lambda r: (
                1 if r["is_valid_domain"] else 0,
                r["malicious_packages_count"],
                1 if r["domain_type"] in ("CUSTOM_ORGANIZATIONAL", "DISPOSABLE_OR_ANONYMOUS") and r["potential_fraud_rate"] >= 0.70 else 0,
                r["anomaly_score"],
                1 if r["meets_high_volume_threshold"] else 0,
                r["potential_fraud_rate"],
                r["avg_threat_score"],
                r["total_packages_count"],
            ),
            reverse=True,
        )

        valid_email_records = [e for e in email_records if e["is_valid_email"]]
        valid_domain_records = [d for d in domain_records if d["is_valid_domain"]]
        high_risk_domain_records = [d for d in valid_domain_records if d["is_high_risk_domain"] or d["meets_high_volume_threshold"]]

        authors_summary = {
            "total_unique_emails": len(valid_email_records),
            "total_unique_domains": len(valid_domain_records),
            "high_risk_domains_count": len(high_risk_domain_records),
            "outlier_emails_count": sum(1 for e in valid_email_records if e["is_outlier"]),
            "outlier_domains_count": sum(1 for d in valid_domain_records if d["is_outlier"]),
            "unlisted_anonymous_packages_count": sum(len(e["packages"]) for e in email_records if not e["is_valid_email"]),
            "generated_at": format_iso_seconds(now_utc),
            "high_risk_domains_leaderboard": [
                {
                    "author_email_domain": d["author_email_domain"],
                    "domain_type": d["domain_type"],
                    "domain_type_label": d["domain_type_label"],
                    "domain_type_note": d["domain_type_note"],
                    "total_packages_count": d["total_packages_count"],
                    "potential_fraud_rate": d["potential_fraud_rate"],
                    "fraud_percentage": d["fraud_percentage"],
                    "avg_threat_score": d["avg_threat_score"],
                    "malicious_packages_count": d["malicious_packages_count"],
                    "questionable_packages_count": d["questionable_packages_count"],
                    "targeted_brands_count": d["targeted_brands_count"],
                    "outlier_reasons": d["outlier_reasons"],
                }
                for d in high_risk_domain_records[:10]
            ],
            "top_outlier_emails": [
                {
                    "author_email": e["author_email"],
                    "author_names": e["associated_author_names"],
                    "anomaly_score": e["anomaly_score"],
                    "malicious_packages_count": e["malicious_packages_count"],
                    "questionable_packages_count": e["questionable_packages_count"],
                    "total_packages_count": e["total_packages_count"],
                    "outlier_reasons": e["outlier_reasons"],
                }
                for e in valid_email_records[:10] if e["is_outlier"]
            ],
            "top_outlier_domains": [
                {
                    "author_email_domain": d["author_email_domain"],
                    "domain_type": d["domain_type"],
                    "anomaly_score": d["anomaly_score"],
                    "malicious_packages_count": d["malicious_packages_count"],
                    "questionable_packages_count": d["questionable_packages_count"],
                    "total_packages_count": d["total_packages_count"],
                    "outlier_reasons": d["outlier_reasons"],
                }
                for d in valid_domain_records[:10] if d["is_outlier"]
            ],
        }

        return email_records, domain_records, authors_summary




# Backwards compatibility alias
