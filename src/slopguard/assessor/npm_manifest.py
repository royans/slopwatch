"""
Sentinel npm Manifest Security Inspector.

Inspects package.json metadata and lifecycle installation scripts (preinstall,
install, postinstall) for malicious shell execution and download cradles.
"""

from typing import Dict, Any, List
from slopguard.core.dto import ASTSecurityReport, ThreatVerdict

DANGEROUS_COMMAND_PATTERNS = [
    ("curl", 35),
    ("wget", 35),
    ("bash", 35),
    ("sh -c", 35),
    ("powershell", 40),
    ("certutil", 40),
    ("eval(", 35),
    ("nc -e", 45),
    ("base64 -d", 35),
    ("node -e eval", 40),
    ("node -e buffer", 35),
    ("node -e require('http", 40),
    ("node -e require(\"http", 40),
]


def analyze_npm_package_manifest(manifest_data: Dict[str, Any], package_name: str) -> ASTSecurityReport:
    """Inspect npm package metadata and package.json lifecycle scripts."""
    flags: List[str] = []
    line_details: List[str] = []
    threat_score = 0
    has_lifecycle = False

    # Get latest version object
    dist_tags = manifest_data.get("dist-tags", {})
    latest_ver = dist_tags.get("latest", "0.1.0")
    versions = manifest_data.get("versions", {})
    ver_data = versions.get(latest_ver, manifest_data)

    scripts = ver_data.get("scripts", {})
    dangerous_hooks = ["preinstall", "install", "postinstall", "preuninstall", "postuninstall"]

    for hook in dangerous_hooks:
        cmd = scripts.get(hook)
        if cmd:
            has_lifecycle = True
            flags.append(f"LIFECYCLE_SCRIPT: '{hook}' -> '{cmd}'")
            threat_score += 25  # Unnecessary install hook in utility library

            cmd_lower = cmd.lower()
            for pattern, pts in DANGEROUS_COMMAND_PATTERNS:
                if pattern in cmd_lower:
                    threat_score += pts
                    flags.append(f"SUSPICIOUS_SHELL_COMMAND: Pattern '{pattern}' in '{hook}' script")
                    line_details.append(f"package.json:scripts.{hook} -> {cmd}")

    # Check for missing repository link
    if not ver_data.get("repository"):
        threat_score += 15
        flags.append("MISSING_SOURCE_REPOSITORY_URL")

    # Measure size and complexity indicators from manifest
    dist = ver_data.get("dist", {})
    unpacked_size = dist.get("unpackedSize", 0)
    file_count = dist.get("fileCount", 1)
    
    # Estimate LOC from scripts or unpacked size
    estimated_loc = max(5, unpacked_size // 40) if unpacked_size else 15
    is_empty = unpacked_size < 1024 and not scripts and not ver_data.get("dependencies")
    size_tier = "EMPTY_STUB" if is_empty else "TINY_CODEBASE" if estimated_loc < 150 else "MODERATE_CODEBASE" if estimated_loc < 1000 else "LARGE_CODEBASE"

    score = min(100, threat_score)
    verdict = ThreatVerdict.BENIGN_COMMUNITY
    if score >= 70:
        verdict = ThreatVerdict.MALICIOUS
    elif score >= 35:
        verdict = ThreatVerdict.SUSPICIOUS
    elif score > 0 or is_empty:
        verdict = ThreatVerdict.SQUATTED_STUB

    return ASTSecurityReport(
        has_lifecycle_scripts=has_lifecycle,
        total_source_files=file_count,
        total_lines_of_code=estimated_loc,
        total_code_size_bytes=unpacked_size or (estimated_loc * 35),
        is_empty_stub=is_empty,
        code_size_tier=size_tier,
        flags=flags,
        line_details=line_details,
        composite_threat_score=score,
        verdict=verdict,
    )


