"""
Agent-facing files shipped inside a package: SKILL.md, CLAUDE.md, AGENTS.md, GEMINI.md,
.cursorrules, Cursor .mdc rules, copilot-instructions.md, mcp.json. An agent that installs or
loads the package reads these as instructions, so they are an injection surface the source
scanners never looked at (they only read .js/.py).

Only the agent-injection YARA rules (rules/agent_injection.yar) are applied to them: these files
are prose and setup docs, where `curl … | bash` or `process.env` are instructions to a human,
not code that runs.
"""

from __future__ import annotations

import posixpath
from typing import List, Tuple

AGENT_INJECTION_PREFIX = "AGENT_INSTRUCTION_INJECTION"
AGENT_INJECTION_SCORE = 40
MAX_AGENT_FILE_BYTES = 256 * 1024

_AGENT_FILE_NAMES = frozenset({
    "skill.md", "claude.md", "agents.md", "gemini.md", ".cursorrules", ".windsurfrules",
    "copilot-instructions.md", "mcp.json", ".mcp.json",
})


def is_agent_instruction_file(path: str) -> bool:
    lower = path.replace("\\", "/").lower()
    base = posixpath.basename(lower)
    return base in _AGENT_FILE_NAMES or base.endswith(".mdc") or (
        base.endswith(".md") and ("/skills/" in lower or "/.claude/" in lower or "/prompts/" in lower)
    )


def scan_agent_file(content: str, filename: str) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    """(flags, line_details) as (dedup_key, text) pairs — agent-injection findings only."""
    from slopwatch.assessor.yara_engine import get_yara_scanner

    scanner = get_yara_scanner()
    if not scanner.is_available:
        return [], []
    flags, lines = scanner.scan_file_content(content, filename)
    keep = lambda pairs: [(k, t) for k, t in pairs if k.startswith(AGENT_INJECTION_PREFIX)]
    return keep(flags), keep(lines)
