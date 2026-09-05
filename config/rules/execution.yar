/* Dynamic Execution & Payload YARA Rules */

rule Exec_Eval {
    meta:
        prefix = "SOURCE_CODE_DYNAMIC_EXECUTION"
        label = "eval()"
        category = "eval"
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
        description = "Node.js child_process module invocation"
    strings:
        $ = /require\s*\(\s*['"]child_process['"]\s*\)/ ascii
    condition:
        any of them
}

rule Exec_SyncSpawn {
    meta:
        prefix = "SOURCE_CODE_DYNAMIC_EXECUTION"
        label = "execSync/spawnSync"
        category = "exec"
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
        description = "Custom install command hook executing commands during pip installation"
    strings:
        $class_hook = /class\s+[A-Za-z0-9_]+\s*\(\s*(install|develop|build_py)\s*\):/ ascii
        $cmdclass   = /cmdclass\s*=\s*\{[^\}]{0,60}['"](install|develop)['"]\s*:/ ascii
        $run_call   = /(install|develop|build_py)\.run\s*\(\s*self\s*\)/ ascii
    condition:
        ($class_hook and $run_call) or $cmdclass
}
