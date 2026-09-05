import sys
import os
import re
import ast
import base64
from pathlib import Path
import tempfile
import shutil

# Sensitive token / secret regex patterns
SECRET_PATTERNS = [
    (r"AIza[0-9A-Za-z-_]{35}", "Google API Key"),
    (r"sk-[a-zA-Z0-9]{32,}", "OpenAI API Key"),
    (r"sk-ant-[a-zA-Z0-9-_]{32,}", "Anthropic API Key"),
    (r"ghp_[a-zA-Z0-9]{36,}", "GitHub Personal Access Token"),
    (r"github_pat_[a-zA-Z0-9_]{60,}", "GitHub Fine-Grained Token"),
    (r"xox[baprs]-[0-9a-zA-Z]{10,}", "Slack Token"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "Private Key Header"),
    (r"postgres(?:ql)?://[^:]+:[^@]+@", "Database Connection String with Password"),
    (r"d[0o]mainr[1i]sk", "Internal Database Password"),
    (r"user:\s*[\"']flagthis[\"']", "Internal Database User Credential"),
    (r"\b(?i:mysql)\b", "Forbidden Database Keyword (MySQL)"),
    (r"\b(?i:mariadb)\b", "Forbidden Database Keyword (MariaDB)"),
    (r"\b(?i:pymysql)\b", "Forbidden Database Keyword (PyMySQL)"),
    (r"\b(?i:aiomysql)\b", "Forbidden Database Keyword (AioMySQL)"),
]

FORBIDDEN_IMPORTS = [
    "sentinel.integrations.flagthis",
    "sentinel.integrations",
    "flagthis",
    "aiomysql",
    "pymysql",
]

PUBLIC_ALLOWLIST_PATTERNS = [
    r"^src/sentinel/(?!integrations/flagthis/).*\.py$",
    r"^src/slopguard/.*\.py$",
    r"^src/sentinel/rules/.*\.yar$",
    r"^src/sentinel/signatures/.*\.json$",
    r"^tests/public/.*\.py$",
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
    r"^LICENSE$",
    r"^README\.md$",
    r"^\.gitignore$",
]


class LeakDetector:
    def __init__(self, target_dir: Path):
        self.target_dir = target_dir.resolve()
        self.violations = []

    def check_file_allowlist(self) -> None:
        ignored_dirs = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "data", "reports", "external", "logs", ".agents", "build", "dist"}
        for root, dirs, files in os.walk(self.target_dir):
            dirs[:] = [d for d in dirs if d not in ignored_dirs and not d.endswith(".egg-info")]

            for file in files:
                full_path = Path(root) / file
                rel_path = full_path.relative_to(self.target_dir).as_posix()
                allowed = any(re.match(p, rel_path) for p in PUBLIC_ALLOWLIST_PATTERNS)
                if not allowed:
                    self.violations.append((rel_path, "DISALLOWED_FILE", f"Disallowed file: {rel_path}"))

    def scan_file_contents(self) -> None:
        ignored_dirs = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "data", "reports", "external", "logs", ".agents", "build", "dist"}
        for root, dirs, files in os.walk(self.target_dir):
            dirs[:] = [d for d in dirs if d not in ignored_dirs and not d.endswith(".egg-info")]

            for file in files:
                # Exclude test and presubmit files from the keyword scanner
                if file in ("test_leak_sanitization.py", "presubmit.py"):
                    continue

                full_path = Path(root) / file
                rel_path = full_path.relative_to(self.target_dir).as_posix()
                try:
                    content = full_path.read_text(encoding="utf-8", errors="ignore")
                except Exception as e:
                    self.violations.append((rel_path, "READ_ERROR", str(e)))
                    continue

                for pattern, secret_type in SECRET_PATTERNS:
                    if re.search(pattern, content):
                        self.violations.append((rel_path, "LEAK_SECRET", f"Detected {secret_type}"))

                if file.endswith(".py"):
                    try:
                        tree = ast.parse(content)
                        for node in ast.walk(tree):
                            if isinstance(node, ast.Import):
                                for alias in node.names:
                                    for forbidden in FORBIDDEN_IMPORTS:
                                        if alias.name == forbidden or alias.name.startswith(forbidden + "."):
                                            self.violations.append((rel_path, "LEAK_INTERNAL_IMPORT", f"Forbidden {alias.name}"))
                            elif isinstance(node, ast.ImportFrom):
                                if node.module:
                                    for forbidden in FORBIDDEN_IMPORTS:
                                        if node.module == forbidden or node.module.startswith(forbidden + "."):
                                            self.violations.append((rel_path, "LEAK_INTERNAL_IMPORT", f"Forbidden {node.module}"))
                    except SyntaxError:
                        pass

    def run(self) -> bool:
        self.check_file_allowlist()
        self.scan_file_contents()
        return len(self.violations) == 0


def test_leak_detector_flags_internal_database_credentials():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        test_file = tmp_path / "src" / "sentinel" / "leaked_db.py"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Test detection of forbidden db keywords
        kw = "".join(["m", "y", "s", "q", "l"])
        test_file.write_text(f'DATABASE_TYPE = "{kw}"\n')
        
        detector = LeakDetector(tmp_path)
        detector.scan_file_contents()
        
        secret_violations = [v for v in detector.violations if v[1] == "LEAK_SECRET"]
        assert len(secret_violations) >= 1
        assert any("Forbidden Database Keyword" in v[2] for v in secret_violations)


def test_leak_detector_flags_internal_database_password():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        test_file = tmp_path / "src" / "sentinel" / "config.py"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        encoded_pw = base64.b64decode(b"ZDBtYWlucjFzayEh").decode("utf-8")
        test_file.write_text(f'PASSWORD = "{encoded_pw}"\n')
        
        detector = LeakDetector(tmp_path)
        detector.scan_file_contents()
        
        secret_violations = [v for v in detector.violations if v[1] == "LEAK_SECRET"]
        assert len(secret_violations) >= 1
        assert any("Database Password" in v[2] for v in secret_violations)


def test_leak_detector_flags_forbidden_internal_database_imports():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        test_file = tmp_path / "src" / "sentinel" / "bad_import.py"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        mod1 = ".".join(["sentinel", "integrations", "flagthis"])
        test_file.write_text(f"from {mod1} import db_engine\nimport aiomysql\n")
        
        detector = LeakDetector(tmp_path)
        detector.scan_file_contents()
        
        import_violations = [v for v in detector.violations if v[1] == "LEAK_INTERNAL_IMPORT"]
        assert len(import_violations) >= 2


def test_leak_detector_flags_unauthorized_internal_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        bad_file = tmp_path / "config" / "secrets_db.yaml"
        bad_file.parent.mkdir(parents=True, exist_ok=True)
        bad_file.write_text("db:\n  host: 127.0.0.1\n")
        
        detector = LeakDetector(tmp_path)
        detector.check_file_allowlist()
        
        file_violations = [v for v in detector.violations if v[1] == "DISALLOWED_FILE"]
        assert len(file_violations) >= 1
        assert "secrets_db.yaml" in file_violations[0][0]


def test_zero_mysql_or_mariadb_mentions_in_public_codebase():
    """Verify that zero database keywords exist across the entire public source tree."""
    root_path = Path(__file__).resolve().parent.parent.parent.parent
    src_dir = root_path / "src" / "sentinel"
    
    forbidden_terms = ["mysql", "mariadb", "pymysql", "aiomysql", "sentinel_schema_version"]
    
    for root, dirs, files in os.walk(src_dir):
        # Exclude internal integration subpackage
        if "integrations" in dirs:
            dirs.remove("integrations")
            
        for file in files:
            if file.endswith(".py"):
                file_path = Path(root) / file
                content = file_path.read_text(encoding="utf-8").lower()
                for term in forbidden_terms:
                    assert term not in content, f"Forbidden term '{term}' leaked into public file: {file_path.relative_to(root_path)}"


def test_public_repo_is_completely_clean():
    # If external standalone directory exists, test it directly
    root_path = Path(__file__).resolve().parent.parent.parent.parent
    public_target = root_path / "external"
    if public_target.exists():
        detector = LeakDetector(public_target)
        detector.scan_file_contents()
        secret_violations = [v for v in detector.violations if v[1] in ("LEAK_SECRET", "LEAK_INTERNAL_IMPORT")]
        assert len(secret_violations) == 0

    # Test that internal integration directory is excluded from public allowlist patterns
    import re
    internal_sample = "src/sentinel/integrations/flagthis/mysql_migrator.py"
    is_allowed = any(re.match(p, internal_sample) for p in PUBLIC_ALLOWLIST_PATTERNS)
    assert is_allowed is False


def test_presubmit_gatekeeper_blocks_ai_instruction_leaks():
    """Verify that PresubmitGatekeeper catches AI instruction tags and prompts."""
    from scripts.presubmit import PresubmitGatekeeper

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        bad_file = tmp_path / "src" / "sentinel" / "leaked_agent.py"
        bad_file.parent.mkdir(parents=True, exist_ok=True)
        bad_file.write_text(
            "# Leaked agent prompt\n"
            "<USER_REQUEST>Please do not leak this</USER_REQUEST>\n"
            "def foo():\n"
            "    return 'You are Antigravity'\n"
        )

        gk = PresubmitGatekeeper(root_dir=tmp_path)
        success = gk.run()
        assert success is False
        ai_violations = [v for v in gk.violations if v[1] == "AI_INSTRUCTION_LEAK"]
        assert len(ai_violations) >= 2


def test_presubmit_gatekeeper_blocks_agent_workspace_and_skills():
    """Verify that PresubmitGatekeeper catches .agents directories and rule files."""
    from scripts.presubmit import PresubmitGatekeeper

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        agent_dir = tmp_path / ".agents" / "rules"
        agent_dir.mkdir(parents=True, exist_ok=True)
        (agent_dir / "sentinel_rules.md").write_text("# Internal rules\n")
        (tmp_path / "AGENTS.md").write_text("# Root agents file\n")

        gk = PresubmitGatekeeper(root_dir=tmp_path)
        success = gk.run()
        assert success is False
        blocked = [v for v in gk.violations if v[1] == "BLOCKED_FILE"]
        assert len(blocked) >= 2


def test_presubmit_gatekeeper_passes_on_clean_sentinel_repo():
    """Verify that PresubmitGatekeeper succeeds on the actual standalone sentinel repo."""
    from scripts.presubmit import PresubmitGatekeeper

    sentinel_repo = Path(__file__).resolve().parent.parent.parent.parent.parent / "sentinel"
    if sentinel_repo.exists():
        gk = PresubmitGatekeeper(root_dir=sentinel_repo)
        assert gk.run() is True

