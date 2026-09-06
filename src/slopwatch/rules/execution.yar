/* Dynamic Execution & Payload YARA Rules
 *
 * `confidence` here matters more than almost any other file: these are the
 * generic, single-primitive patterns (eval, subprocess, network, base64,
 * env access) that are individually ubiquitous in legitimate code — and
 * exactly the ones whose flat point-stacking produced this session's two
 * confirmed false positives (`playwright`, `agentdiscover`). Confidence is
 * "how informative is a BARE match of this pattern, on its own, in
 * real-world code" — not severity (how bad it'd be if genuinely malicious).
 * See core/confidence.py for how this is consumed.
 */

rule Exec_Eval {
    meta:
        prefix = "SOURCE_CODE_DYNAMIC_EXECUTION"
        label = "eval()"
        category = "eval"
        // Used by real templating/validation/codegen libraries, not just malware.
        confidence = "LOW"
        description = "Dynamic JavaScript code execution via eval()"
    strings:
        $ = /\beval\s*\(/ ascii
    condition:
        any of them
}

rule Exec_NewFunction {
    meta:
        prefix = "SOURCE_CODE_DYNAMIC_EXECUTION"
        label = "new Function()"
        category = "eval"
        confidence = "LOW"
        description = "Dynamic JavaScript code execution via new Function constructor"
    strings:
        $ = /\bnew\s+Function\s*\(/ ascii
    condition:
        any of them
}

rule Exec_ChildProcess {
    meta:
        prefix = "SOURCE_CODE_DYNAMIC_EXECUTION"
        label = "require('child_process')"
        category = "exec"
        // Extremely common in legitimate build tools, git wrappers, test
        // runners (confirmed: playwright, esbuild both use this legitimately).
        confidence = "LOW"
        description = "Node.js child_process module invocation"
    strings:
        $ = /require\s*\(\s*['"`]child_process['"`]\s*\)/ ascii
        $ = /require\s*\(\s*`[^`]*child_process[^`]*`\s*\)/ ascii
    condition:
        any of them
}

rule Exec_GlobalThis_Eval {
    meta:
        prefix = "SOURCE_CODE_DYNAMIC_EXECUTION"
        label = "globalThis['eval']"
        category = "eval"
        // Bracket-notation indirection to reach eval specifically reads as
        // deliberate evasion of naive `eval(` text scanning.
        confidence = "MEDIUM"
        description = "Dynamic JavaScript code execution via globalThis, window, or global subscript"
    strings:
        $ = /\b(globalThis|window|global)\s*\[\s*['"`]eval['"`]\s*\]/ ascii
    condition:
        any of them
}

rule Exec_Process_Binding {
    meta:
        prefix = "SOURCE_CODE_DYNAMIC_EXECUTION"
        label = "process.binding/mainModule"
        category = "exec"
        // Internal/deprecated Node API meant for core, not userland — real
        // packages essentially never have a legitimate reason to touch it.
        confidence = "HIGH"
        description = "Node.js internal process binding or mainModule access"
    strings:
        $ = /\bprocess\s*\.\s*(binding|mainModule)\b/ ascii
    condition:
        any of them
}

rule Exec_SyncSpawn {
    meta:
        prefix = "SOURCE_CODE_DYNAMIC_EXECUTION"
        label = "execSync/spawnSync"
        category = "exec"
        // Common in legitimate native-addon build/install scripts (confirmed:
        // esbuild's install.js).
        confidence = "LOW"
        description = "Synchronous OS command execution primitive"
    strings:
        $ = /\b(execSync|spawnSync|execFileSync)\s*\(/ ascii
    condition:
        any of them
}

rule Exec_Python_Subprocess {
    meta:
        prefix = "SOURCE_CODE_DYNAMIC_EXECUTION"
        label = "Python Subprocess / OS Execution"
        category = "exec"
        // Bare, context-free text match (fires the same whether the call is
        // top-level or safely inside a function) — ubiquitous in legitimate
        // CLI/build tooling. The much stronger, narrower signal — this exact
        // call sitting at module/install-time top level — is a separate,
        // AST-derived HIGH-confidence flag (INSTALL_TIME_EXECUTION /
        // MODULE_TOPLEVEL_EXECUTION); this bare-text rule should stay LOW.
        confidence = "LOW"
        description = "Python os.system, os.popen, or subprocess invocation"
    strings:
        $ = /(os\.(system|popen)|subprocess\.(Popen|run|call|check_output))\s*\(/ ascii
    condition:
        any of them
}

rule Dangerous_VM_RunInContext {
    meta:
        prefix = "SOURCE_CODE_DYNAMIC_EXECUTION"
        label = "vm.runInContext"
        category = "eval"
        // Real legitimate sandboxing/testing-framework use exists alongside
        // malicious payload-execution use.
        confidence = "MEDIUM"
        description = "Node.js VM module code evaluation primitive"
    strings:
        $ = /\bvm\s*\.\s*(runInContext|runInNewContext|runInThisContext)\s*\(/ ascii
    condition:
        any of them
}

rule Decode_Buffer_Base64 {
    meta:
        prefix = "SOURCE_CODE_ENCODED_PAYLOAD"
        label = "Buffer.from(..., 'base64')"
        category = "decode"
        // Ubiquitous for legitimate binary/text handling (file uploads,
        // images, JWTs) — confirmed: playwright uses this legitimately.
        confidence = "LOW"
        description = "Base64 payload decode routine"
    strings:
        $ = /Buffer\.from\([^)]{0,120},\s*['"]base64['"]\s*\)/ ascii
    condition:
        any of them
}

rule Decode_Atob {
    meta:
        prefix = "SOURCE_CODE_ENCODED_PAYLOAD"
        label = "atob()"
        category = "decode"
        confidence = "LOW"
        description = "atob base64 decode primitive"
    strings:
        $ = /\batob\s*\(/ ascii
    condition:
        any of them
}

rule Network_HttpRequire {
    meta:
        prefix = "SOURCE_CODE_NETWORK_CALL"
        label = "require('http(s)')"
        category = "network"
        // Universal for any package that makes network calls at all.
        confidence = "LOW"
        description = "Node.js HTTP/HTTPS module import"
    strings:
        $ = /require\s*\(\s*['"]https?['"]\s*\)/ ascii
    condition:
        any of them
}

rule Network_FetchAxiosXhr {
    meta:
        prefix = "SOURCE_CODE_NETWORK_CALL"
        label = "fetch/axios/XMLHttpRequest"
        category = "network"
        confidence = "LOW"
        description = "HTTP client call primitive"
    strings:
        $ = /\bfetch\s*\(|\baxios\.[a-z]+\s*\(|\bXMLHttpRequest\b/ ascii
    condition:
        any of them
}

rule Env_ProcessEnv {
    meta:
        prefix = "SOURCE_CODE_ENV_VARS_ACCESS"
        label = "Environment Variable Access (process.env / os.environ)"
        category = "env"
        // Virtually every real-world app reads config from env vars.
        confidence = "LOW"
        description = "Access to environment variables via process.env or os.environ / os.getenv"
    strings:
        $node = /\bprocess\s*(\.\s*env|\[\s*['"]env['"]\s*\])/ ascii
        $py   = /\bos\.(environ|getenv)\b/ ascii
    condition:
        any of them
}

rule Env_SensitiveTokenHarvesting {
    meta:
        prefix = "SOURCE_CODE_ENV_VARS_ACCESS"
        label = "Sensitive Token Harvesting"
        category = "sensitive_env"
        // More deliberate than bare env access, but legitimate CI-integration
        // tooling reads these exact named vars too (a GitHub Action helper
        // reading GITHUB_TOKEN is completely normal).
        confidence = "MEDIUM"
        description = "Targeted extraction of API keys, tokens, or credentials from environment"
    strings:
        $node = /process\.env\.(AWS_[A-Z_]*KEY|NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|SLACK_[A-Z_]*TOKEN|DISCORD_[A-Z_]*TOKEN|PRIVATE_KEY|SECRET_KEY|API_KEY|ACCESS_TOKEN)\b/ ascii nocase
        $py   = /os\.(environ(\.get)?|getenv)\s*[\(\[]\s*['"](AWS_[A-Z_]*KEY|PYPI_[A-Z_]*TOKEN|GITHUB_TOKEN|GH_TOKEN|SLACK_[A-Z_]*TOKEN|DISCORD_[A-Z_]*TOKEN|PRIVATE_KEY|SECRET_KEY|API_KEY|ACCESS_TOKEN)['"]/ ascii nocase
    condition:
        any of them
}

rule Env_BulkHarvesting {
    meta:
        prefix = "SOURCE_CODE_ENV_VARS_ACCESS"
        label = "Bulk Environment Harvesting"
        category = "sensitive_env"
        // More deliberate than a single named var, but legitimate crash-
        // reporting/telemetry SDKs sometimes capture full env context too
        // (usually with redaction) — real but not overwhelming on its own.
        confidence = "MEDIUM"
        description = "Serialization or mass dump of process.env"
    strings:
        $ = /(JSON\.stringify|Object\.(keys|values|entries))\s*\(\s*process\.env\s*\)/ ascii nocase
        $py = /dict\s*\(\s*os\.environ\s*\)/ ascii
    condition:
        any of them
}

rule Exec_Reverse_Shell_Socket {
    meta:
        prefix = "SOURCE_CODE_DYNAMIC_EXECUTION"
        label = "Interactive Reverse Shell / Raw Socket"
        category = "exec"
        // /dev/tcp redirection, nc -e /bin/sh, dup2-onto-socket — classic,
        // extremely specific reverse-shell primitives, essentially never
        // legitimate in real package code.
        confidence = "HIGH"
        description = "Spawning an interactive reverse shell or piping socket to process input"
    strings:
        $dev_tcp  = /\/dev\/tcp\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,5}/ ascii
        $nc_sh    = /\b(nc|ncat|netcat)\s+(-[a-zA-Z0-9]*e\s+|.*-e\s+)(\/bin\/)?(ba)?sh\b/ ascii nocase
        $py_dup2  = /os\.dup2\s*\(\s*[a-zA-Z0-9_.]+\.fileno\s*\(\s*\)/ ascii
        $node_net = /net\.(createConnection|Socket)\b[^;\n]{0,80}\.pipe\b/ ascii
    condition:
        any of them
}

rule Exec_PowerShell_Cradle {
    meta:
        prefix = "SOURCE_CODE_DYNAMIC_EXECUTION"
        label = "PowerShell Execution Cradle"
        category = "exec"
        // Encoded download-and-execute cradles, certutil URL-cache abuse —
        // well-documented dropper techniques, essentially never legitimate.
        confidence = "HIGH"
        description = "PowerShell hidden download cradle or encoded command execution"
    strings:
        $ps_enc   = /powershell(\.exe)?\s+[^\n]{0,100}\s+(-e|-enc|-encodedcommand)\s+[A-Za-z0-9+\/=]{12,}/ ascii nocase
        $ps_dl    = /powershell(\.exe)?\s+[^\n]{0,120}\b(DownloadString|DownloadFile|Invoke-WebRequest|iwr)\b[^\n]{0,120}\b(iex|Invoke-Expression)\b/ ascii nocase
        $certutil = /certutil(\.exe)?\s+(-urlcache|-split)\s+(-f\s+)?https?:\/\// ascii nocase
    condition:
        any of them
}

rule Exec_Python_Setup_Hook {
    meta:
        prefix = "INSTALL_TIME_EXECUTION"
        label = "Python setup.py Custom Install Hook"
        category = "exec"
        // A confidence/severity split worth calling out explicitly: this
        // structural pattern (a custom install/develop cmdclass override
        // EXISTS) is real signal — it correctly caught "0wneg" — but the
        // same structure is common in legitimate packages compiling native
        // extensions (confirmed false positives this session: `daff`,
        // `orange-widget-base`). What makes a cmdclass override malicious is
        // WHAT it calls, not that it exists — that's handled separately, at
        // HIGH, by the AST visitor's own cmdclass_override_calls detection
        // (INSTALL_TIME_CMDCLASS_OVERRIDE, gated on an actual dangerous call
        // inside it). This YARA-only structural match, alone, is MEDIUM.
        confidence = "MEDIUM"
        description = "Custom install command hook executing commands during pip installation"
    strings:
        $class_hook = /class\s+[A-Za-z0-9_]+\s*\(\s*(install|develop|build_py)\s*\):/ ascii
        $cmdclass   = /cmdclass\s*=\s*\{[^\}]{0,60}['"](install|develop)['"]\s*:/ ascii
        $run_call   = /(install|develop|build_py)\.run\s*\(\s*self\s*\)/ ascii
    condition:
        ($class_hook and $run_call) or $cmdclass
}
