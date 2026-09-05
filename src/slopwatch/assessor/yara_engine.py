"""
Sentinel — High-Performance YARA Scanning Engine.

Compiles and executes declarative YARA rules against package file contents,
replacing sequential Python regex searches with a single-pass bytecode engine.
Emits normalized flags, line-level evidence, and categorical match offsets for
composite threat analysis (e.g. proximity-based code loader and stealer detection).
"""

from __future__ import annotations

import ipaddress
import logging
import os
from pathlib import Path
import re
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("slopwatch.assessor.yara")

try:
    import yara
    _YARA_AVAILABLE = True
except ImportError:  # pragma: no cover - defensive fallback
    yara = None
    _YARA_AVAILABLE = False


PROXIMITY_WINDOW_CHARS = 400
COMPOSITE_PROXIMITY_WINDOW_CHARS = 400
_IP_REGEX = re.compile(r"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})")


def is_minified_content(content: str) -> bool:
    """Return True if content appears minified (mean line length > 500 or any line > 50KB)."""
    lines = content.splitlines()
    if not lines:
        return False
    if any(len(line) > 50_000 for line in lines):
        return True
    total_len = sum(len(line) for line in lines)
    return (total_len / len(lines)) > 500



def is_public_exfil_ip(ip_str: str) -> bool:
    """Return True only if IP is a routable public IP (not local, private, test, link-local, or documentation)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False
        octets = ip_str.split(".")
        if len(octets) == 4:
            first = int(octets[0])
            second = int(octets[1])
            third = int(octets[2])
            if first == 198 and second == 51 and third == 100:  # TEST-NET-2 (RFC 5737)
                return False
            if first == 192 and second == 0 and third == 2:     # TEST-NET-1 (RFC 5737)
                return False
            if first == 203 and second == 0 and third == 113:   # TEST-NET-3 (RFC 5737)
                return False
            if first == 100 and (64 <= second <= 127):          # CGNAT (RFC 6598)
                return False
        return True
    except ValueError:
        return False


def _find_default_rules_path() -> Path:
    """Locate the default index.yar file checking env var, package data, repo root, or cwd."""
    env_path = os.getenv("SENTINEL_YARA_RULES_PATH")
    if env_path:
        p = Path(env_path)
        if p.exists():
            return p

    # 1. Package resources (canonical when installed as a package via pip / wheel)
    try:
        import importlib.resources as pkg_resources
        rule_pkg = pkg_resources.files("slopwatch") / "rules" / "index.yar"
        if rule_pkg.is_file():
            return Path(str(rule_pkg))
    except Exception:
        pass

    # 2. Package tree relative to this file: src/slopwatch/rules/index.yar
    module_rules = Path(__file__).resolve().parent.parent / "rules" / "index.yar"
    if module_rules.exists():
        return module_rules

    # 3. Sentinel repo root: config/rules/index.yar
    slopwatch_root = Path(__file__).resolve().parent.parent.parent.parent
    candidate = slopwatch_root / "config" / "rules" / "index.yar"
    if candidate.exists():
        return candidate

    # 4. Fallback to relative path from workspace root
    cwd_candidate = Path("config/rules/index.yar").resolve()
    if cwd_candidate.exists():
        return cwd_candidate

    return candidate


class YaraPatternScanner:
    """Compiled YARA rule scanner for package source code inspection."""

    def __init__(self, rules_path: Optional[str | Path] = None) -> None:
        self.rules_path = Path(rules_path) if rules_path else _find_default_rules_path()
        self._compiled_rules: Optional["yara.Rules"] = None
        self._load_rules()

    def _load_rules(self) -> None:
        if not _YARA_AVAILABLE:
            logger.warning("yara-python is not installed; YARA scanning disabled.")
            return

        if not self.rules_path.exists():
            logger.warning("YARA rules file not found at %s", self.rules_path)
            return

        try:
            self._compiled_rules = yara.compile(filepath=str(self.rules_path))
            logger.info("Successfully compiled YARA rules from %s", self.rules_path)
        except Exception as e:
            logger.error("Failed to compile YARA rules from %s: %s", self.rules_path, e)
            self._compiled_rules = None

    @property
    def is_available(self) -> bool:
        return self._compiled_rules is not None

    def scan_file_content(
        self, content: str, filename: str
    ) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
        """
        Scan a source file's text using compiled YARA rules and composite heuristics.
        Returns (flags, line_details) as lists of (dedup_key, rendered_text) pairs.
        """
        if not self.is_available or not content:
            return [], []

        flags: List[Tuple[str, str]] = []
        line_details: List[Tuple[str, str]] = []

        # Position lists for composite detections
        positions: Dict[str, List[int]] = {
            "eval": [],
            "exec": [],
            "decode": [],
            "network": [],
            "env": [],
            "sensitive_env": [],
            "exfil": [],
            "cred": [],
            "worm": [],
            "obfuscation": [],
            "persistence": [],
            "evasion": [],
            "hook": [],
        }

        seen_keys_in_file: Set[str] = set()

        try:
            matches = self._compiled_rules.match(data=content)
        except Exception as e:
            logger.error("YARA match error on %s: %s", filename, e)
            return [], []

        for match in matches:
            meta = match.meta or {}
            prefix = meta.get("prefix", "CODE_ANALYSIS")
            label = meta.get("label", match.rule)
            category = meta.get("category", "")

            # .pth startup code injection rules only apply to .pth files
            if match.rule == "SupplyChain_Python_PTH_Code_Execution" and not filename.lower().endswith(".pth"):
                continue

            # If this is a raw IP check, we need semantic IP address validation
            if category == "raw_ip":
                for sm in match.strings:
                    for inst in sm.instances:
                        offset = inst.offset
                        data_str = inst.matched_data.decode("utf-8", errors="ignore")
                        ip_match = _IP_REGEX.search(data_str)
                        if not ip_match:
                            continue
                        ip_str = ip_match.group(1)
                        if is_public_exfil_ip(ip_str):
                            positions["exfil"].append(offset)
                            lineno = content.count("\n", 0, offset) + 1
                            dedup_key = f"{prefix}:{label}"
                            if dedup_key not in seen_keys_in_file:
                                seen_keys_in_file.add(dedup_key)
                                flags.append((dedup_key, f"{prefix}: '{label}' found in {filename}:{lineno}"))
                                line_details.append((dedup_key, f"{filename}:{lineno} -> {label} ({ip_str})"))
                continue

            # Standard rules
            first_offset: Optional[int] = None
            for sm in match.strings:
                for inst in sm.instances:
                    offset = inst.offset
                    if first_offset is None or offset < first_offset:
                        first_offset = offset
                    if category in positions:
                        positions[category].append(offset)

            if first_offset is not None:
                lineno = content.count("\n", 0, first_offset) + 1
                dedup_key = f"{prefix}:{label}"
                if dedup_key not in seen_keys_in_file:
                    seen_keys_in_file.add(dedup_key)
                    flags.append((dedup_key, f"{prefix}: '{label}' found in {filename}:{lineno}"))
                    line_details.append((dedup_key, f"{filename}:{lineno} -> {label}"))

        # Minified bundles defeat proximity heuristics (line folding creates false adjacency).
        # We preserve individual exact rule matches but suppress composite proximity heuristics.
        if is_minified_content(content):
            return flags, line_details

        # Composite heuristic 1: Dynamic code loader
        # triggers when eval/exec/Function is within COMPOSITE_PROXIMITY_WINDOW_CHARS of decode/network/obfuscation
        eval_positions = positions["eval"]
        decode_or_net_positions = positions["decode"] + positions["network"] + positions["obfuscation"]
        is_loader = any(
            abs(e - d) <= COMPOSITE_PROXIMITY_WINDOW_CHARS
            for e in eval_positions
            for d in decode_or_net_positions
        )
        if is_loader:
            key = "SOURCE_CODE_DYNAMIC_CODE_LOADER"
            flags.append((key, f"{key}: execution primitive combined with decode/network/obfuscation call in {filename}"))
            line_details.append((key, f"{filename} -> dynamic code loader (eval/exec + decode/network/obfuscation within {COMPOSITE_PROXIMITY_WINDOW_CHARS} chars)"))

        # Composite heuristic 2: Confirmed Information Stealer
        # exfiltration endpoint combined with secret/sensitive token harvesting or credential path access
        exfil_positions = positions["exfil"]
        cred_positions = positions["cred"]
        sensitive_env_positions = positions["sensitive_env"]
        target_cred_positions = cred_positions + sensitive_env_positions
        is_stealer = any(
            abs(e - c) <= COMPOSITE_PROXIMITY_WINDOW_CHARS
            for e in exfil_positions
            for c in target_cred_positions
        )
        if is_stealer:
            key = "SOURCE_CODE_CONFIRMED_STEALER"
            flags.append((key, f"{key}: potential exfiltration endpoint combined with credential/environment harvesting in {filename}"))
            line_details.append((key, f"{filename} -> suspected information stealer (exfiltration endpoint + secret access within {COMPOSITE_PROXIMITY_WINDOW_CHARS} chars)"))

        # Composite heuristic 3: Persistent Backdoor
        # persistence mechanism combined with execution, hooks, or outbound network
        persistence_positions = positions["persistence"]
        exec_or_net_positions = positions["exec"] + positions["eval"] + positions["network"] + positions["exfil"] + positions["hook"]
        is_backdoor = any(
            abs(p - en) <= COMPOSITE_PROXIMITY_WINDOW_CHARS
            for p in persistence_positions
            for en in exec_or_net_positions
        )
        if is_backdoor:
            key = "SOURCE_CODE_PERSISTENT_BACKDOOR"
            flags.append((key, f"{key}: persistence mechanism combined with execution/network in {filename}"))
            line_details.append((key, f"{filename} -> persistent backdoor (persistence + execution/network within {COMPOSITE_PROXIMITY_WINDOW_CHARS} chars)"))

        # Composite heuristic 4: Evasive Payload
        # anti-analysis / sandbox evasion check combined with execution or payload hook
        evasion_positions = positions["evasion"]
        payload_positions = positions["exec"] + positions["eval"] + positions["decode"] + positions["hook"] + positions["exfil"]
        is_evasive = any(
            abs(ev - pl) <= COMPOSITE_PROXIMITY_WINDOW_CHARS
            for ev in evasion_positions
            for pl in payload_positions
        )
        if is_evasive:
            key = "SOURCE_CODE_EVASIVE_PAYLOAD"
            flags.append((key, f"{key}: anti-analysis evasion combined with execution/payload hook in {filename}"))
            line_details.append((key, f"{filename} -> evasive payload (anti-analysis check + payload/hook within {COMPOSITE_PROXIMITY_WINDOW_CHARS} chars)"))

        return flags, line_details

    def scan_text(self, content: str, filename: str = "snippet.py") -> List[Dict[str, str]]:
        """Scan a text snippet and return formatted findings with rule details."""
        flags, line_details = self.scan_file_content(content, filename=filename)
        results = []
        for (tag, text) in flags:
            rule_part = tag.split(":", 1)[1] if ":" in tag else tag
            results.append({"rule": rule_part, "detail": text, "tag": tag})
        return results


# Process-level singleton scanner
_DEFAULT_SCANNER: Optional[YaraPatternScanner] = None


def get_yara_scanner() -> YaraPatternScanner:
    """Return the global cached YaraPatternScanner instance."""
    global _DEFAULT_SCANNER
    if _DEFAULT_SCANNER is None:
        _DEFAULT_SCANNER = YaraPatternScanner()
    return _DEFAULT_SCANNER
