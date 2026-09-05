#!/usr/bin/env python3
"""
Sentinel Standalone Pre-Submit Gatekeeper & Leak Protection.

Guarantees that no internal documents, API keys, credentials, local paths,
AI agent prompts, or un-sanitized internal imports exist in this repository.

Usage:
    python3 scripts/presubmit.py           # Scan all repository files
    python3 scripts/presubmit.py --staged  # Scan only git staged files
"""

import argparse
import ast
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent

# 1. Permitted Public Files & Directories Allowlist (Regex patterns)
PUBLIC_ALLOWLIST_PATTERNS = [
    r"^src/slopwatch/(?!integrations/flagthis/).*\.py$",
    r"^src/slopwatch/rules/.*\.yar$",
    r"^src/slopwatch/signatures/.*\.json$",
    r"^tests/.*\.py$",
    r"^tests/fixtures/.*(?:\.json|\.py)$",
    r"^config/config\.yaml\.template$",
    r"^config/signatures/parking_hashes\.json$",
    r"^config/rules/.*\.yar$",
    r"^scripts/presubmit\.py$",
    r"^scripts/install_hooks\.sh$",
    r"^\.githooks/pre-commit$",
    r"^\.pre-commit-config\.yaml$",
    r"^pyproject\.toml$",
    r"^requirements\.txt$",
    r"^MANIFEST\.in$",
    r"^\.pre-commit-hooks\.yaml$",
    r"^src/slopwatch/py\.typed$",
    r"^LICENSE$",
    r"^README\.md$",
    r"^docs/(?!internal/|private/|confidential/).*\.md$",
    r"^\.gitignore$",
    r"^\.github/.*$",
]

# 2. Blocked Directory & File Patterns (Fail immediately on match)
BLOCKED_PATH_PATTERNS = [
    (r"(?:^|/)\.agents(?:/|$)", "AI Agent Workspace (.agents)"),
    (r"(?:^|/)\.gemini(?:/|$)", "Gemini Config (.gemini)"),
    (r"(?:^|/)\.claude(?:/|$)", "Claude Config (.claude)"),
    (r"(?:^|/)\.cursor(?:/|$)", "Cursor Config (.cursor)"),
    (r"(?:^|/)\.windsurf(?:/|$)", "Windsurf Config (.windsurf)"),
    (r"(?:^|/)docs/internal(?:/|$)", "Internal Documentation Directory"),
    (r"(?:^|/)docs/private(?:/|$)", "Private Documentation Directory"),
    (r"(?:^|/)docs/confidential(?:/|$)", "Confidential Documentation Directory"),
    (r"(?:^|/)TODO\.md$", "Internal Roadmap (TODO.md)"),
    (r".*AGENTS\.md$", "Agent Instructions File (AGENTS.md)"),
    (r".*CLAUDE\.md$", "Claude Instructions File (CLAUDE.md)"),
    (r".*GEMINI\.md$", "Gemini Instructions File (GEMINI.md)"),
    (r".*SKILL\.md$", "Agent Skill File (SKILL.md)"),
    (r".*\.prompt$", "AI Prompt File (.prompt)"),
    (r".*\.rule$", "AI Rule File (.rule)"),
    (r".*\.pem$", "Private Key / Certificate (.pem)"),
    (r".*\.key$", "Private Key File (.key)"),
    (r".*\.secret$", "Secret Credentials File (.secret)"),
    (r"(?:^|/)\.env(?:$|\..*)", "Environment Variables File (.env)"),
    (r"(?:^|/)id_rsa.*", "SSH Private Key (id_rsa)"),
    (r"(?:^|/)id_ed25519.*", "SSH Private Key (id_ed25519)"),
    (r"^src/slopwatch/integrations/flagthis(?:/|$)", "Proprietary Enterprise FlagThis Integration"),
]

# 3. Secret & Credential Patterns (Regex patterns)
SECRET_PATTERNS = [
    (r"AIza[0-9A-Za-z-_]{35}", "Google / Gemini API Key"),
    (r"sk-[a-zA-Z0-9]{32,}", "OpenAI API Key"),
    (r"sk-proj-[a-zA-Z0-9-_]{32,}", "OpenAI Project API Key"),
    (r"sk-ant-[a-zA-Z0-9-_]{32,}", "Anthropic API Key"),
    (r"ghp_[a-zA-Z0-9]{36,}", "GitHub Personal Access Token"),
    (r"github_pat_[a-zA-Z0-9_]{60,}", "GitHub Fine-Grained Token"),
    (r"xox[baprs]-[0-9a-zA-Z]{10,}", "Slack Token"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "Private Key Header"),
    (r"(?:mysql|mariadb|postgres(?:ql)?|mongodb|redis)://[^:]+:[^@]+@", "Database Connection URI with Password"),
]

# 4. AI Instructions & Prompt Markers (Regex patterns)
AI_INSTRUCTION_PATTERNS = [
    (r"<(?:USER_REQUEST|system_instruction|conversation_history|conversation_transcript|antigravity|customizations|user_rules|slash_commands|planning_mode|artifacts|knowledge_items)>", "AI Agent System XML Tag"),
    (r"\bYou are Antigravity\b", "Antigravity Identity Prompt"),
    (r"\bAdvanced Agentic Coding\b", "Agent Harness Prompt Marker"),
    (r"\bGoogle Deepmind team\b", "Agent Identity Marker"),
    (r"\bParent AI Control Plane\b", "Internal Control Plane Marker"),
    (r"\bAI/AGENT rules\b", "AI Rule Marker"),
]

# 5. Internal Paths & PII Patterns (Regex patterns)
INTERNAL_PATTERNS = [
    (r"/home/royans\b", "Hardcoded Local Path (/home/royans)"),
    (r"/Users/[a-zA-Z0-9_-]+", "Hardcoded Local Path (/Users/...)"),
    (r"flagthis\.corp\b", "Internal Domain (flagthis.corp)"),
    (r"royans@gmail\.com", "Private Personal Email"),
    (r"#\s*(?:INTERNAL|PRIVATE|CONFIDENTIAL)\b", "Internal Tag Marker"),
    (r"\b(?i:mariadb)\b", "Forbidden Keyword: MariaDB"),
    (r"\b(?i:aiomysql)\b", "Forbidden Keyword: AioMySQL"),
    (r"\b(?i:pymysql)\b", "Forbidden Keyword: PyMySQL"),
    (r"\bsentinel_schema_version\b", "Internal Table Keyword"),
    (r"d[0o]mainr[1i]sk", "Internal Database Password"),
    (r"user:\s*[\"']flagthis[\"']", "Internal Database User Credential"),
]

# 6. Forbidden Python Imports
FORBIDDEN_IMPORTS = [
    "slopwatch.integrations.flagthis",
    "slopwatch.integrations",
    "sentinel.integrations.flagthis",
    "sentinel.integrations",
    "flagthis",
    "aiomysql",
    "pymysql",
    "mariadb",
]


class PresubmitGatekeeper:
    def __init__(self, root_dir: Path, staged_only: bool = False):
        self.root_dir = root_dir.resolve()
        self.staged_only = staged_only
        self.violations: List[Tuple[str, str, str]] = []  # (path, category, description)
        self.is_monorepo = (self.root_dir / "src" / "flagthis_sentinel").exists()

    def get_target_files(self) -> List[Path]:
        """Return list of files to inspect."""
        if self.staged_only:
            res = subprocess.run(
                ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
                cwd=str(self.root_dir),
                capture_output=True,
                text=True,
            )
            if res.returncode != 0:
                print(f"⚠️ Warning: Could not obtain staged git files, scanning working directory instead.")
                return self._walk_all_files()
            staged = [self.root_dir / line.strip() for line in res.stdout.splitlines() if line.strip()]
            return [p for p in staged if p.is_file()]
        return self._walk_all_files()

    def _walk_all_files(self) -> List[Path]:
        """Walk all tracked repository files, respecting .gitignore and skipping build/cache."""
        res = subprocess.run(
            ["git", "ls-files"],
            cwd=str(self.root_dir),
            capture_output=True,
            text=True,
        )
        if res.returncode == 0:
            lines = [line.strip() for line in res.stdout.splitlines() if line.strip()]
            return [self.root_dir / p for p in lines if (self.root_dir / p).is_file()]

        # Fallback if not a git worktree
        ignored_dirs = {
            ".git", "__pycache__", ".pytest_cache", ".venv", "venv",
            "data", "reports", "external", "logs", "build", "dist"
        }
        all_files = []
        for root, dirs, files in os.walk(self.root_dir):
            dirs[:] = [d for d in dirs if d not in ignored_dirs and not d.endswith(".egg-info")]
            for file in files:
                if file.endswith((".pyc", ".whl")):
                    continue
                all_files.append(Path(root) / file)
        return all_files

    def check_file_path(self, file_path: Path) -> bool:
        """Validate that file is in allowlist and does not match blocked patterns."""
        if self.is_monorepo:
            # Monorepo legitimately houses internal documentation, agents, and enterprise modules
            return True

        try:
            rel_path = file_path.relative_to(self.root_dir).as_posix()
        except ValueError:
            rel_path = file_path.as_posix()

        # Check explicitly blocked paths
        for pattern, desc in BLOCKED_PATH_PATTERNS:
            if re.search(pattern, rel_path):
                self.violations.append((rel_path, "BLOCKED_FILE", f"Forbidden file path detected: {desc}"))
                return False

        # Check against strict public allowlist
        allowed = any(re.match(pattern, rel_path) for pattern in PUBLIC_ALLOWLIST_PATTERNS)
        if not allowed:
            self.violations.append(
                (rel_path, "DISALLOWED_FILE", f"File is not in the public allowlist: {rel_path}")
            )
            return False
        return True

    def check_file_contents(self, file_path: Path) -> None:
        """Scan file contents for secrets, AI instructions, internal paths, and forbidden imports."""
        try:
            rel_path = file_path.relative_to(self.root_dir).as_posix()
        except ValueError:
            rel_path = file_path.as_posix()

        # Skip presubmit scripts and test suites from pattern scanning
        if rel_path in ("scripts/presubmit.py", "scripts/presubmit_leak_check.py", "tests/public/unit/test_leak_sanitization.py"):
            return

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            self.violations.append((rel_path, "READ_ERROR", f"Could not read file: {e}"))
            return

        # 1. Secret Scanning (applied universally)
        for pattern, secret_type in SECRET_PATTERNS:
            match = re.search(pattern, content)
            if match:
                line_no = content[: match.start()].count("\n") + 1
                self.violations.append(
                    (rel_path, "LEAKED_SECRET", f"Line {line_no}: Found {secret_type}")
                )

        if self.is_monorepo:
            # Monorepo legitimately houses internal AI prompts and MariaDB database connectivity
            return

        # 2. AI Instructions & Prompt Markers (public repo only)
        for pattern, ai_type in AI_INSTRUCTION_PATTERNS:
            match = re.search(pattern, content)
            if match:
                line_no = content[: match.start()].count("\n") + 1
                self.violations.append(
                    (rel_path, "AI_INSTRUCTION_LEAK", f"Line {line_no}: Found {ai_type}")
                )

        # 3. Internal Paths & PII (public repo only)
        for pattern, desc in INTERNAL_PATTERNS:
            match = re.search(pattern, content)
            if match:
                line_no = content[: match.start()].count("\n") + 1
                self.violations.append(
                    (rel_path, "INTERNAL_METADATA_LEAK", f"Line {line_no}: Found {desc}")
                )

        # 4. AST Import Checking for Python files (public repo only)
        if file_path.suffix == ".py":
            try:
                tree = ast.parse(content, filename=str(file_path))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            for forbidden in FORBIDDEN_IMPORTS:
                                if alias.name == forbidden or alias.name.startswith(f"{forbidden}."):
                                    self.violations.append(
                                        (
                                            rel_path,
                                            "FORBIDDEN_IMPORT",
                                            f"Line {node.lineno}: Disallowed import '{alias.name}'",
                                        )
                                    )
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            for forbidden in FORBIDDEN_IMPORTS:
                                if node.module == forbidden or node.module.startswith(f"{forbidden}."):
                                    self.violations.append(
                                        (
                                            rel_path,
                                            "FORBIDDEN_IMPORT",
                                            f"Line {node.lineno}: Disallowed from-import '{node.module}'",
                                        )
                                    )
            except SyntaxError:
                # Syntax errors will be caught by test suites/linters
                pass

    def run(self) -> bool:
        """Run all presubmit checks."""
        mode_str = "Git Staged Files" if self.staged_only else "All Repository Files"
        repo_type = "FlagThis Monorepo" if self.is_monorepo else "Sentinel Standalone"
        print("─" * 70)
        print(f"🔒 {repo_type} Pre-Submit Gatekeeper ({mode_str})")
        print(f"📁 Target: {self.root_dir}")
        print("─" * 70)

        target_files = self.get_target_files()
        print(f"🔍 Inspecting {len(target_files)} file(s)...")

        for f in target_files:
            if not f.is_file():
                continue
            path_ok = self.check_file_path(f)
            if path_ok:
                self.check_file_contents(f)

        print("─" * 70)
        if not self.violations:
            print("✅ PRE-SUBMIT CHECK PASSED: Zero leaks or unapproved files detected.")
            print("─" * 70)
            return True
        else:
            print(f"❌ PRE-SUBMIT CHECK FAILED: Found {len(self.violations)} violation(s):\n")
            for rel_path, category, message in self.violations:
                print(f"  • [{category}] {rel_path}: {message}")
            print("\n🚨 Please resolve all violations before committing or pushing to the repository.")
            print("─" * 70)
            return False


def main():
    parser = argparse.ArgumentParser(description="Sentinel Standalone Pre-Submit Gatekeeper")
    parser.add_argument("--staged", action="store_true", help="Scan only git staged files")
    parser.add_argument("--target-dir", default=None, help="Target directory to inspect (default: repository root)")
    args = parser.parse_args()

    target = Path(args.target_dir).resolve() if args.target_dir else ROOT_DIR
    gatekeeper = PresubmitGatekeeper(root_dir=target, staged_only=args.staged)
    success = gatekeeper.run()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
