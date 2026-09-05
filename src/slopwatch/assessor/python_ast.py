"""
Sentinel Python AST Static Malware Inspector.

Performs non-invasive AST parsing on package tarballs to detect malicious
installation hooks in setup.py and pyproject.toml while eliminating false positives
by distinguishing install-time execution from runtime library code.
"""

import ast
import io
import ipaddress
import re
import tarfile
import zipfile
import warnings
from typing import List, Tuple, Dict, Set, Optional
from slopwatch.core.dto import ASTSecurityReport, ThreatVerdict
from slopwatch.assessor.yara_engine import get_yara_scanner

DANGEROUS_MODULES = {
    "socket": 35,
    "subprocess": 30,
    "os": 10,
    "urllib": 15,
    "requests": 15,
    "http.client": 15,
    "base64": 15,
    "ctypes": 25,
}

DANGEROUS_CALLS = {
    "os.system": 45,
    "os.popen": 45,
    "subprocess.Popen": 40,
    "subprocess.run": 40,
    "subprocess.call": 40,
    "eval": 35,
    "exec": 45,
}

_RAW_IP_URL_RE = re.compile(
    r"https?://([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?::[0-9]{2,5})?",
    re.IGNORECASE,
)

from slopwatch.assessor.yara_engine import is_public_exfil_ip, get_yara_scanner

# Backward-compatible alias
_is_public_exfil_ip = is_public_exfil_ip


def _is_test_or_fixture_path(path: str) -> bool:
    """True if path is within a test/fixture/sample directory, vendored dependency, or is a test/spec file."""
    normalized = ("/" + path.replace("\\", "/").strip("/")).lower()
    if any(sub in normalized for sub in (
        "/test/", "/tests/", "/__tests__/", "/.git/", "/coverage/",
        "/fixtures/", "/fixture/", "/__fixtures__/", "/mocks/", "/mock/",
        "/testutils/", "/test-utils/", "/e2e/", "/samples/", "/examples/",
        "/docs/", "/documentation/", "/.github/",
        "/pybind11/", "/vendor/", "/vendored/", "/third_party/", "/third-party/",
        "/_vendor/", "/extern/", "/external/", "/deps/", "/.eggs/", "/site-packages/",
    )):
        return True
    filename = normalized.split("/")[-1]
    if filename.startswith("test_") or filename.endswith("_test.py"):
        return True
    return False


NATIVE_BINARY_EXTENSIONS = (".so", ".dll", ".dylib", ".exe", ".elf")

MAX_FILES_SCANNED = 500
MAX_BYTES_PER_FILE = 2 * 1024 * 1024        # skip individual files larger than this (2MB)
MAX_TOTAL_BYTES_SCANNED = 20 * 1024 * 1024  # stop actively scanning content past this cumulative size (20MB)



def _resolve_string(node: ast.AST) -> Optional[str]:
    """Recursively resolve string literals and string binary additions (e.g. 'sub' + 'process')."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left_str = _resolve_string(node.left)
        right_str = _resolve_string(node.right)
        if left_str is not None and right_str is not None:
            return left_str + right_str
    return None


def _get_dotted_name(node: ast.AST) -> str:
    """Extract dotted name from AST node, e.g. ctypes.cdll.LoadLibrary or getattr."""
    parts = []
    curr = node
    while isinstance(curr, ast.Attribute):
        parts.append(curr.attr)
        curr = curr.value
    if isinstance(curr, ast.Name):
        parts.append(curr.id)
        return ".".join(reversed(parts))
    return ""


def check_pth_content(content: str, filename: str) -> Tuple[List[str], bool, int]:
    """
    Inspect the content of a Python .pth configuration file.
    In Python, any line in a .pth file starting with 'import ' is automatically
    executed by the interpreter upon startup (site.py).
    Returns (flags, is_dangerous_code, threat_score).
    """
    flags = []
    has_dangerous = False
    max_score = 0

    lines = content.splitlines()
    has_any_import = False
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("import ") or stripped.startswith("import\t"):
            has_any_import = True
            try:
                tree = ast.parse(stripped)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            root_mod = alias.name.split(".")[0]
                            if root_mod in ("os", "sys", "subprocess", "socket", "urllib", "requests", "base64", "builtins", "shutil", "ctypes", "codecs"):
                                flags.append(f"PYTHON_PTH_CODE_EXECUTION: Dangerous startup module '{alias.name}' imported in {filename}: '{stripped[:120]}'")
                                has_dangerous = True
                                max_score = max(max_score, 85)
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            root_mod = node.module.split(".")[0]
                            if root_mod in ("os", "sys", "subprocess", "socket", "urllib", "requests", "base64", "builtins", "shutil", "ctypes", "codecs"):
                                flags.append(f"PYTHON_PTH_CODE_EXECUTION: Dangerous startup module '{node.module}' imported in {filename}: '{stripped[:120]}'")
                                has_dangerous = True
                                max_score = max(max_score, 85)
                    elif isinstance(node, ast.Call):
                        call_id = ""
                        if isinstance(node.func, ast.Name):
                            call_id = node.func.id
                        elif isinstance(node.func, ast.Attribute):
                            call_id = node.func.attr
                        if call_id in ("eval", "exec", "system", "popen", "run", "Popen", "call", "connect", "b64decode"):
                            flags.append(f"PYTHON_PTH_CODE_EXECUTION: Startup execution call '{call_id}()' in {filename}: '{stripped[:120]}'")
                            has_dangerous = True
                            max_score = max(max_score, 85)
            except Exception:
                flags.append(f"PYTHON_PTH_STARTUP_HOOK: Unparseable startup import statement in {filename}: '{stripped[:120]}'")
                max_score = max(max_score, 40)

    if has_any_import and not has_dangerous:
        flags.append(f"PYTHON_PTH_STARTUP_HOOK: Startup .pth file declared in package: {filename}")
        max_score = max(max_score, 35)

    return flags, has_dangerous, max_score


# PEP 517/518 build backends known to be maintained, widely-used build tools —
# declaring one of these in pyproject.toml's [build-system].build-backend is
# unremarkable. Anything else is an unverified custom backend whose hooks
# (build_wheel, build_sdist, etc.) run automatically during `pip install` the
# same way setup.py does, and is worth inspecting the same way.
KNOWN_SAFE_BUILD_BACKENDS = {
    "setuptools.build_meta",
    "setuptools.build_meta:__legacy__",
    "hatchling.build",
    "flit_core.buildapi",
    "flit.buildapi",
    "poetry.core.masonry.api",
    "poetry.masonry.api",
    "pdm.backend",
    "pdm.pep517.api",
    "maturin",
    "scikit_build_core.build",
    "mesonpy",
    "uv_build",
    "uv_build.build",
    "uv",
    "whey",
    "trampolim",
}


def parse_pyproject_build_backend(pyproject_content: str):
    """Parse pyproject.toml text; return the declared [build-system].build-backend name, or None."""
    try:
        import tomllib
        data = tomllib.loads(pyproject_content)
    except Exception:
        return None
    return data.get("build-system", {}).get("build-backend") or None


def is_unverified_build_backend(backend: str) -> bool:
    backend_root = backend.split(":")[0]
    return backend not in KNOWN_SAFE_BUILD_BACKENDS and backend_root not in KNOWN_SAFE_BUILD_BACKENDS


INSTALL_BASE_CLASSES = {
    "install", "develop", "egg_info", "build_py", "build_ext",
    "install_scripts", "install_lib", "bdist_egg", "bdist_wheel"
}


class SetupASTVisitor(ast.NodeVisitor):
    def __init__(self, is_install_script: bool = True):
        self.is_install_script = is_install_script
        self.scope_depth = 0
        self.current_class_name = ""
        self.current_func_name = ""
        self.custom_install_classes: Dict[str, str] = {}  # class_name -> base_name
        self.cmdclass_registered_classes: Set[str] = set()
        self.top_level_calls: List[Tuple[str, int]] = []
        self.cmdclass_override_calls: List[Tuple[str, str, int]] = []  # (class_name, call_name, lineno)
        self.dynamic_obfuscation_calls: List[Tuple[str, int]] = []  # (detail, lineno)
        self.function_calls: List[Tuple[str, int]] = []
        self.imported_modules: List[str] = []
        self.env_var_accesses: List[Tuple[str, int, bool]] = []
        self.function_count = 0
        self.class_count = 0
        self.has_socket = False
        self.has_subprocess = False
        self.has_os_system = False
        self.has_base64_eval = False
        self.has_cmdclass_override = False
        self.has_dynamic_obfuscation = False
        self.install_time_lines: Set[int] = set()

    def generic_visit(self, node: ast.AST):
        if hasattr(node, "lineno") and self.is_install_script:
            if self.scope_depth == 0 or self.current_class_name in self.custom_install_classes:
                self.install_time_lines.add(node.lineno)
        super().generic_visit(node)


    def visit_ClassDef(self, node: ast.ClassDef):
        self.class_count += 1
        prev_class = self.current_class_name
        self.current_class_name = node.name

        # Detect inheritance from setuptools install/develop commands
        for base in node.bases:
            base_name = ""
            if isinstance(base, ast.Name):
                base_name = base.id
            elif isinstance(base, ast.Attribute):
                base_name = base.attr
            if base_name in INSTALL_BASE_CLASSES or "install" in base_name.lower():
                self.custom_install_classes[node.name] = base_name

        self.scope_depth += 1
        self.generic_visit(node)
        self.scope_depth -= 1
        self.current_class_name = prev_class

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.function_count += 1
        prev_func = self.current_func_name
        self.current_func_name = node.name
        self.scope_depth += 1
        self.generic_visit(node)
        self.scope_depth -= 1
        self.current_func_name = prev_func

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.function_count += 1
        prev_func = self.current_func_name
        self.current_func_name = node.name
        self.scope_depth += 1
        self.generic_visit(node)
        self.scope_depth -= 1
        self.current_func_name = prev_func

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            mod_name = alias.name.split(".")[0]
            self.imported_modules.append(alias.name)
            if mod_name == "socket":
                self.has_socket = True
            elif mod_name == "subprocess":
                self.has_subprocess = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            mod_name = node.module.split(".")[0]
            self.imported_modules.append(node.module)
            if mod_name == "socket":
                self.has_socket = True
            elif mod_name == "subprocess":
                self.has_subprocess = True
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        # Detect __dict__ or __getattribute__ access for dynamic execution bypass
        if node.attr in ("__dict__", "__getattribute__") and self.is_install_script:
            self.dynamic_obfuscation_calls.append((f"Access to '{node.attr}'", node.lineno))
            self.has_dynamic_obfuscation = True
        elif node.attr == "environ" and self.is_install_script:
            self.env_var_accesses.append(("Access to os.environ", node.lineno, False))
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        if self.is_install_script:
            val_name = _get_dotted_name(node.value)
            if val_name in ("__builtins__", "builtins.__dict__", "sys.modules"):
                slice_str = _resolve_string(node.slice)
                if slice_str and slice_str in ("exec", "eval", "system", "popen", "__import__", "subprocess", "posix"):
                    self.dynamic_obfuscation_calls.append((f"Subscript access {val_name}['{slice_str}']", node.lineno))
                    self.has_dynamic_obfuscation = True
                elif isinstance(node.slice, (ast.BinOp, ast.Call)):
                    self.dynamic_obfuscation_calls.append((f"Subscript access {val_name}[...] with dynamic expression", node.lineno))
                    self.has_dynamic_obfuscation = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        call_name = _get_dotted_name(node.func)

        # 1. Detect setup(cmdclass=...) binding
        if call_name in ("setup", "setuptools.setup") and self.is_install_script:
            for kw in node.keywords:
                if kw.arg == "cmdclass":
                    self.has_cmdclass_override = True
                    if isinstance(kw.value, ast.Dict):
                        for val in kw.value.values:
                            if isinstance(val, ast.Name):
                                self.cmdclass_registered_classes.add(val.id)

        # 2. Detect getattr() / __import__() / ctypes dynamic obfuscation
        if call_name == "getattr" and self.is_install_script:
            if len(node.args) >= 2:
                second_arg = node.args[1]
                resolved_str = _resolve_string(second_arg)
                if resolved_str and resolved_str in ("system", "popen", "run", "Popen", "call", "exec", "eval", "socket", "subprocess", "__import__"):
                    self.dynamic_obfuscation_calls.append((f"getattr() resolving '{resolved_str}'", node.lineno))
                    self.has_dynamic_obfuscation = True
                    self.has_os_system = True
                elif isinstance(second_arg, (ast.BinOp, ast.Call)):
                    self.dynamic_obfuscation_calls.append(("getattr() with dynamic attribute expression", node.lineno))
                    self.has_dynamic_obfuscation = True

        elif call_name == "__import__" and self.is_install_script:
            if len(node.args) >= 1:
                first_arg = node.args[0]
                resolved_str = _resolve_string(first_arg)
                if resolved_str and resolved_str in ("subprocess", "socket", "os", "pty", "posix"):
                    self.dynamic_obfuscation_calls.append((f"__import__() dynamic loading '{resolved_str}'", node.lineno))
                    self.has_dynamic_obfuscation = True
                    if resolved_str in ("os", "subprocess"):
                        self.has_subprocess = True
                    elif resolved_str == "socket":
                        self.has_socket = True
                elif isinstance(first_arg, (ast.BinOp, ast.Call)):
                    self.dynamic_obfuscation_calls.append(("__import__() with dynamic module expression", node.lineno))
                    self.has_dynamic_obfuscation = True

        elif call_name in ("ctypes.CDLL", "ctypes.cdll.LoadLibrary", "ctypes.windll.LoadLibrary") and self.is_install_script:
            self.dynamic_obfuscation_calls.append((f"Dynamic native library loading via {call_name}()", node.lineno))
            self.has_dynamic_obfuscation = True

        # Detect os.getenv() / os.environ.get() in install script
        if call_name in ("os.getenv", "os.environ.get") and self.is_install_script:
            is_sensitive = False
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                arg_val = node.args[0].value.upper()
                if any(k in arg_val for k in ("SECRET", "TOKEN", "KEY", "PASSWORD", "AUTH", "CRED", "API")):
                    is_sensitive = True
            self.env_var_accesses.append((f"Call to {call_name}()", node.lineno, is_sensitive))

        # 3. Dangerous call evaluation in install script vs library
        if call_name in DANGEROUS_CALLS:
            # Check if inside custom install class run() method
            is_inside_custom_install = (
                self.current_class_name in self.custom_install_classes
                and self.current_func_name in ("run", "initialize_options", "finalize_options")
            )

            if is_inside_custom_install and self.is_install_script:
                self.cmdclass_override_calls.append((self.current_class_name, call_name, node.lineno))
                self.has_os_system = True
                self.has_cmdclass_override = True
            elif self.scope_depth == 0 and self.is_install_script:
                # Top-level install-time execution hook
                if call_name == "exec":
                    is_benign_exec = False
                    if node.args and isinstance(node.args[0], ast.Call):
                        first_arg = node.args[0]
                        if isinstance(first_arg.func, ast.Name) and first_arg.func.id in ("open", "compile", "read"):
                            is_benign_exec = True
                        elif isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr in ("read", "read_text"):
                            is_benign_exec = True
                    if not is_benign_exec:
                        self.top_level_calls.append((call_name, node.lineno))
                        self.has_os_system = True
                else:
                    self.top_level_calls.append((call_name, node.lineno))
                    if "os.system" in call_name or "os.popen" in call_name:
                        self.has_os_system = True
                    if "eval" in call_name:
                        self.has_base64_eval = True
            else:
                self.function_calls.append((call_name, node.lineno))

        self.generic_visit(node)


def inspect_python_code_ast(code_content: str, filename: str, force_install_script: Optional[bool] = None) -> ASTSecurityReport:
    """
    Parse python source code with AST and separate top-level install hooks from
    runtime logic. `force_install_script` overrides the filename-based inference —
    used for pyproject.toml custom build-backend modules, whose hooks (build_wheel,
    etc.) run automatically during `pip install` the same as setup.py, but whose
    filename obviously isn't literally "setup.py".
    """
    flags: List[str] = []
    line_details: List[str] = []
    threat_score = 0

    norm_fn = filename.replace("\\", "/").lower()
    is_install_script = (
        force_install_script
        if force_install_script is not None
        else (
            ("setup.py" in norm_fn)
            and (norm_fn.count("/") <= 1)
            and not _is_test_or_fixture_path(norm_fn)
        )
    )
    raw_lines = code_content.splitlines()
    loc = len([l for l in raw_lines if l.strip() and not l.strip().startswith("#")])
    code_bytes = len(code_content.encode("utf-8", errors="ignore"))

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(code_content)
    except SyntaxError as e:
        return ASTSecurityReport(
            total_source_files=1,
            total_lines_of_code=loc,
            total_code_size_bytes=code_bytes,
            is_empty_stub=False,
            code_size_tier="TINY_CODEBASE" if loc < 150 else "MODERATE_CODEBASE",
            flags=[f"SYNTAX_ERROR_IN_{filename}: {e}"],
            composite_threat_score=20,
            verdict=ThreatVerdict.SUSPICIOUS,
        )

    visitor = SetupASTVisitor(is_install_script=is_install_script)
    visitor.visit(tree)

    # 1. Critical Install-Time Top-Level Execution
    for call, lineno in visitor.top_level_calls:
        pts = DANGEROUS_CALLS.get(call, 40)
        threat_score += pts
        flags.append(f"INSTALL_TIME_EXECUTION: '{call}' executed at top-level in {filename}:{lineno}")
        line_details.append(f"{filename}:{lineno} -> {call}() [TOP_LEVEL]")

    # 2. Critical cmdclass install-time override
    for cls_name, call_name, lineno in visitor.cmdclass_override_calls:
        pts = DANGEROUS_CALLS.get(call_name, 45)
        threat_score += pts
        flags.append(f"INSTALL_TIME_CMDCLASS_OVERRIDE: '{cls_name}.run()' executes '{call_name}' during installation in {filename}:{lineno}")
        line_details.append(f"{filename}:{lineno} -> {cls_name}.run() -> {call_name}() [CMDCLASS_OVERRIDE]")

    # 3. Dynamic Obfuscated Function Resolution (getattr, __dict__)
    for detail, lineno in visitor.dynamic_obfuscation_calls:
        pts = 45 if "resolving" in detail else 25
        threat_score += pts
        flags.append(f"OBFUSCATED_DYNAMIC_ACCESS: {detail} detected in {filename}:{lineno}")
        line_details.append(f"{filename}:{lineno} -> {detail} [OBFUSCATED_DYNAMIC_ACCESS]")

    # 4. Check for socket connection during install
    if visitor.has_socket and is_install_script and (visitor.top_level_calls or visitor.cmdclass_override_calls):
        threat_score += 35
        flags.append(f"INSTALL_TIME_NETWORK_SOCKET: 'socket' module used during {filename} installation")

    # 5. Environment variable / secret harvesting during install (AST level)
    for detail, lineno, is_sensitive in visitor.env_var_accesses[:3]:
        pts = 20 if is_sensitive else 0
        threat_score += pts
        flags.append(f"SOURCE_CODE_ENV_VARS_ACCESS: {detail} in {filename}:{lineno}")
        line_details.append(f"{filename}:{lineno} -> {detail}")

    # 6. Unified YARA pattern scanner for payload / IOC inspection
    has_exfiltration = False
    has_credential_harvesting = False
    yara_scanner = get_yara_scanner()
    if yara_scanner.is_available:
        y_flags, y_lines = yara_scanner.scan_file_content(code_content, filename)
        seen_flag_keys = set()
        for dedup_key, f_text in y_flags:
            if f_text not in flags:
                flags.append(f_text)

            prefix = dedup_key.split(":")[0]
            if prefix in seen_flag_keys:
                continue
            seen_flag_keys.add(prefix)

            if prefix == "EXFILTRATION_DESTINATION_DETECTED":
                has_exfiltration = True
                threat_score += 45
            elif prefix == "CREDENTIAL_PATH_HARVESTING":
                has_credential_harvesting = True
                threat_score += 40
            elif prefix == "SOURCE_CODE_CONFIRMED_STEALER":
                threat_score += 80
            elif prefix == "CROSS_ECOSYSTEM_WORM_PROPAGATION":
                has_credential_harvesting = True
                threat_score += 45
            elif prefix == "ANTI_ANALYSIS_EVASION":
                threat_score += 30
            elif prefix == "SYSTEM_PERSISTENCE_TAMPERING":
                threat_score += 45
            elif prefix == "SOURCE_CODE_PERSISTENT_BACKDOOR":
                threat_score += 45
            elif prefix == "SOURCE_CODE_EVASIVE_PAYLOAD":
                threat_score += 35
            elif prefix == "SOURCE_CODE_DYNAMIC_CODE_LOADER":
                threat_score += 45
            elif prefix == "SOURCE_CODE_ENV_VARS_ACCESS" and not visitor.env_var_accesses:
                if any(s in dedup_key for s in ("Sensitive Token", "Bulk Environment")):
                    threat_score += 20
                else:
                    threat_score += 0
            elif prefix in ("SOURCE_CODE_DYNAMIC_EXECUTION", "SOURCE_CODE_ENCODED_PAYLOAD"):
                threat_score += 25

        for _, l_text in y_lines:
            if l_text not in line_details:
                line_details.append(l_text)

    # 7. Check for empty stub reservation
    is_empty_stub = (
        visitor.function_count == 0
        and visitor.class_count == 0
        and len(visitor.top_level_calls) == 0
        and len(visitor.cmdclass_override_calls) == 0
        and len(flags) == 0
        and loc <= 25
    )

    score = min(100, threat_score)
    verdict = ThreatVerdict.BENIGN_COMMUNITY
    if score >= 70:
        verdict = ThreatVerdict.MALICIOUS
    elif score >= 35:
        verdict = ThreatVerdict.SUSPICIOUS
    elif is_empty_stub:
        verdict = ThreatVerdict.SQUATTED_STUB

    size_tier = (
        "EMPTY_STUB" if is_empty_stub
        else "TINY_CODEBASE" if loc < 150
        else "MODERATE_CODEBASE" if loc < 1000
        else "LARGE_CODEBASE"
    )

    return ASTSecurityReport(
        has_socket=visitor.has_socket,
        has_subprocess=visitor.has_subprocess,
        has_os_system=visitor.has_os_system,
        has_base64_eval=visitor.has_base64_eval,
        has_exfiltration_destination=has_exfiltration,
        has_credential_harvesting=has_credential_harvesting,
        has_dynamic_obfuscation=visitor.has_dynamic_obfuscation,
        total_source_files=1,
        total_lines_of_code=loc,
        total_code_size_bytes=code_bytes,
        is_empty_stub=is_empty_stub,
        code_size_tier=size_tier,
        flags=flags,
        line_details=line_details,
        composite_threat_score=score,
        verdict=verdict,
    )



def analyze_python_package_tarball(tarball_bytes: bytes, package_name: str) -> ASTSecurityReport:
    """Unpack in-memory tarball or wheel and analyze setup.py / pyproject.toml / .pth files / binaries."""
    all_flags: List[str] = []
    all_lines: List[str] = []
    max_score = 0
    total_files = 0
    total_source_files = 0
    files_scanned = 0
    bytes_scanned = 0
    total_loc = 0
    total_code_bytes = 0
    has_functions_or_classes = False
    has_pth_execution = False
    has_exfiltration = False
    has_cred_harvesting = False
    has_bundled_binary = False

    # Try reading as tar.gz / tar.bz2
    try:
        with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:*") as tar:
            members = tar.getmembers()
            total_files = len(members)
            for member in members:
                # Check for startup .pth files
                if member.name.endswith(".pth"):
                    if member.size > MAX_BYTES_PER_FILE or bytes_scanned >= MAX_TOTAL_BYTES_SCANNED:
                        continue
                    pf = tar.extractfile(member)
                    if pf:
                        raw = pf.read(MAX_BYTES_PER_FILE + 1)
                        if len(raw) > MAX_BYTES_PER_FILE:
                            continue
                        bytes_scanned += len(raw)
                        pth_content = raw.decode("utf-8", errors="ignore")
                        p_flags, p_dang, p_score = check_pth_content(pth_content, member.name)
                        all_flags.extend(p_flags)
                        if p_dang:
                            has_pth_execution = True
                        max_score = max(max_score, p_score)
                elif any(member.name.endswith(ext) for ext in NATIVE_BINARY_EXTENSIONS):
                    if not _is_test_or_fixture_path(member.name):
                        all_flags.append(f"BUNDLED_NATIVE_BINARY: Unexpected compiled binary '{member.name}' in package archive")
                        has_bundled_binary = True
                        max_score = max(max_score, 25)

                if member.name.endswith(".py"):
                    if _is_test_or_fixture_path(member.name):
                        continue
                    total_source_files += 1
                    if member.size > MAX_BYTES_PER_FILE or bytes_scanned >= MAX_TOTAL_BYTES_SCANNED or files_scanned >= MAX_FILES_SCANNED:
                        continue
                    f = tar.extractfile(member)
                    if f:
                        raw = f.read(MAX_BYTES_PER_FILE + 1)
                        if len(raw) > MAX_BYTES_PER_FILE:
                            continue
                        bytes_scanned += len(raw)
                        files_scanned += 1
                        content = raw.decode("utf-8", errors="ignore")
                        loc = len([l for l in content.splitlines() if l.strip() and not l.strip().startswith("#")])
                        total_loc += loc
                        total_code_bytes += len(raw)
                        is_top_level_setup = (
                            (member.name == "setup.py" or (member.name.endswith("/setup.py") and member.name.count("/") == 1))
                            and not _is_test_or_fixture_path(member.name)
                        )
                        if is_top_level_setup or member.name.endswith("__init__.py") or total_source_files <= 5:
                            report = inspect_python_code_ast(content, member.name, force_install_script=is_top_level_setup)
                            all_flags.extend(report.flags)
                            all_lines.extend(report.line_details)
                            max_score = max(max_score, report.composite_threat_score)
                            if report.has_exfiltration_destination:
                                has_exfiltration = True
                            if report.has_credential_harvesting:
                                has_cred_harvesting = True
                            if not report.is_empty_stub:
                                has_functions_or_classes = True
                        else:
                            yara_scanner = get_yara_scanner()
                            if yara_scanner.is_available:
                                y_flags, y_lines = yara_scanner.scan_file_content(content, member.name)
                                for _, f_text in y_flags:
                                    if f_text not in all_flags:
                                        all_flags.append(f_text)
                                for _, l_text in y_lines:
                                    if l_text not in all_lines:
                                        all_lines.append(l_text)


            # pyproject.toml custom build-backend inspection (PEP 517/518).
            pyproject_member = next(
                (m for m in members if m.name.endswith("pyproject.toml") and m.name.count("/") <= 1),
                None,
            )
            if pyproject_member and pyproject_member.size <= MAX_BYTES_PER_FILE and bytes_scanned < MAX_TOTAL_BYTES_SCANNED:
                pf = tar.extractfile(pyproject_member)
                if pf:
                    raw = pf.read(MAX_BYTES_PER_FILE + 1)
                    if len(raw) <= MAX_BYTES_PER_FILE:
                        bytes_scanned += len(raw)
                        backend = parse_pyproject_build_backend(raw.decode("utf-8", errors="ignore"))
                        if backend and is_unverified_build_backend(backend):
                            all_flags.append(f"CUSTOM_BUILD_BACKEND_UNVERIFIED: '{backend}' declared in pyproject.toml")
                            max_score = max(max_score, 20)

                            backend_module = backend.split(":")[0].split(".")[0]
                            candidates = [
                                m for m in members
                                if m.name == f"{backend_module}.py"
                                or m.name.endswith(f"/{backend_module}.py")
                                or m.name.endswith(f"/{backend_module}/__init__.py")
                            ]
                            for cand in candidates[:3]:
                                if cand.size > MAX_BYTES_PER_FILE or bytes_scanned >= MAX_TOTAL_BYTES_SCANNED:
                                    continue
                                cf = tar.extractfile(cand)
                                if not cf:
                                    continue
                                raw_cand = cf.read(MAX_BYTES_PER_FILE + 1)
                                if len(raw_cand) > MAX_BYTES_PER_FILE:
                                    continue
                                bytes_scanned += len(raw_cand)
                                cand_content = raw_cand.decode("utf-8", errors="ignore")
                                report = inspect_python_code_ast(cand_content, cand.name, force_install_script=True)
                                all_flags.extend(report.flags)
                                all_lines.extend(report.line_details)
                                max_score = max(max_score, report.composite_threat_score)
                                if report.has_exfiltration_destination:
                                    has_exfiltration = True
                                if report.has_credential_harvesting:
                                    has_cred_harvesting = True
    except Exception:
        # Try reading as zip (wheels)
        try:
            with zipfile.ZipFile(io.BytesIO(tarball_bytes)) as z:
                infolist = z.infolist()
                total_files = len(infolist)
                for info in infolist:
                    filename = info.filename
                    # Check for startup .pth files in wheels
                    if filename.endswith(".pth"):
                        if info.file_size > MAX_BYTES_PER_FILE or bytes_scanned >= MAX_TOTAL_BYTES_SCANNED:
                            continue
                        try:
                            with z.open(info) as pf:
                                raw = pf.read(MAX_BYTES_PER_FILE + 1)
                            if len(raw) > MAX_BYTES_PER_FILE:
                                continue
                            bytes_scanned += len(raw)
                            pth_content = raw.decode("utf-8", errors="ignore")
                            p_flags, p_dang, p_score = check_pth_content(pth_content, filename)
                            all_flags.extend(p_flags)
                            if p_dang:
                                has_pth_execution = True
                            max_score = max(max_score, p_score)
                        except Exception:
                            pass
                    elif any(filename.endswith(ext) for ext in NATIVE_BINARY_EXTENSIONS):
                        if not _is_test_or_fixture_path(filename):
                            is_standard_py_extension = (
                                (".cpython-" in filename and filename.endswith(".so"))
                                or (".abi3." in filename and filename.endswith(".so"))
                                or filename.endswith(".pyd")
                            )
                            if not is_standard_py_extension:
                                all_flags.append(f"BUNDLED_NATIVE_BINARY: Unexpected compiled binary '{filename}' in wheel archive")
                                has_bundled_binary = True
                                max_score = max(max_score, 25)

                    if filename.endswith(".py"):
                        if _is_test_or_fixture_path(filename):
                            continue
                        total_source_files += 1
                        if info.file_size > MAX_BYTES_PER_FILE or bytes_scanned >= MAX_TOTAL_BYTES_SCANNED or files_scanned >= MAX_FILES_SCANNED:
                            continue
                        try:
                            with z.open(info) as pf:
                                raw = pf.read(MAX_BYTES_PER_FILE + 1)
                            if len(raw) > MAX_BYTES_PER_FILE:
                                continue
                            bytes_scanned += len(raw)
                            files_scanned += 1
                            content = raw.decode("utf-8", errors="ignore")
                            loc = len([l for l in content.splitlines() if l.strip() and not l.strip().startswith("#")])
                            total_loc += loc
                            total_code_bytes += len(raw)
                            report = inspect_python_code_ast(content, filename)
                            all_flags.extend(report.flags)
                            all_lines.extend(report.line_details)
                            max_score = max(max_score, report.composite_threat_score)
                            if report.has_exfiltration_destination:
                                has_exfiltration = True
                            if report.has_credential_harvesting:
                                has_cred_harvesting = True
                            if not report.is_empty_stub:
                                has_functions_or_classes = True
                        except Exception:
                            pass
        except Exception as e:
            return ASTSecurityReport(
                flags=[f"ARCHIVE_EXTRACTION_FAILED: {e}"],
                composite_threat_score=25,
                verdict=ThreatVerdict.SUSPICIOUS,
            )


    is_empty_stub = (total_loc <= 25 and not has_functions_or_classes) or (total_source_files <= 1 and total_loc <= 10)
    size_tier = "EMPTY_STUB" if is_empty_stub else "TINY_CODEBASE" if total_loc < 150 else "MODERATE_CODEBASE" if total_loc < 1000 else "LARGE_CODEBASE"

    verdict = ThreatVerdict.BENIGN_COMMUNITY
    if max_score >= 70 or has_pth_execution:
        verdict = ThreatVerdict.MALICIOUS
    elif max_score >= 35:
        verdict = ThreatVerdict.SUSPICIOUS
    elif is_empty_stub and max_score == 0:
        verdict = ThreatVerdict.SQUATTED_STUB

    return ASTSecurityReport(
        has_socket=any("SOCKET" in f for f in all_flags),
        has_subprocess=any("subprocess" in f for f in all_flags),
        has_os_system=any("os.system" in f or "os.popen" in f or "exec" in f for f in all_flags),
        has_base64_eval=any("eval" in f or "base64" in f for f in all_flags),
        has_pth_execution=has_pth_execution,
        has_exfiltration_destination=has_exfiltration,
        has_credential_harvesting=has_cred_harvesting,
        has_bundled_binary=has_bundled_binary,
        has_dynamic_obfuscation=any("OBFUSCATED" in f or "dynamic" in f.lower() for f in all_flags),
        total_source_files=total_source_files or total_files,
        total_lines_of_code=total_loc,
        total_code_size_bytes=total_code_bytes,
        is_empty_stub=is_empty_stub,
        code_size_tier=size_tier,
        flags=all_flags,
        line_details=all_lines,
        composite_threat_score=max_score,
        verdict=verdict,
    )



class PythonASTAssessor:
    """Convenience class for performing AST static analysis on Python source code."""

    def analyze_source(self, code: str, filename: str = "setup.py") -> ASTSecurityReport:
        """Statically analyze a Python source code snippet and return security findings."""
        return inspect_python_code_ast(code, filename=filename)

    def analyze_tarball(self, tarball_path: str) -> ASTSecurityReport:
        """Statically analyze an extracted or raw package tarball."""
        return analyze_python_package_tarball(tarball_path)
