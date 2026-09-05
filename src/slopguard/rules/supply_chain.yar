/* Supply-Chain & Runtime Execution Hooks YARA Rules */

rule SupplyChain_NPM_Lifecycle_Command {
    meta:
        prefix = "SUPPLY_CHAIN_EXECUTION_HOOK"
        label = "NPM Dangerous Lifecycle Hook Command"
        category = "hook"
        severity = 85
        description = "Dangerous shell commands inside package scripts (curl pipe to sh, wget, powershell)"
    strings:
        $ = /['"](preinstall|postinstall|prepack|install)['"]\s*:\s*['"][^'"]*(curl\s+-[sS]*[kL]*\s+|wget\s+|powershell\s+|bash\s+-c\s+['"]curl|sh\s+-c\s+['"]curl)[^'"]*['"]/ ascii nocase
    condition:
        any of them
}

rule SupplyChain_PyPI_Custom_Install_Command {
    meta:
        prefix = "SUPPLY_CHAIN_EXECUTION_HOOK"
        label = "PyPI Custom Install Class Override"
        category = "hook"
        severity = 80
        description = "Overriding setuptools install/develop command classes to run arbitrary code on pip install"
    strings:
        $cmdclass = /cmdclass\s*=\s*\{['"](install|develop)['"]\s*:/ ascii
        $install_sub = /class\s+[A-Za-z0-9_]+\s*\(\s*(setuptools\.command\.install\.install|install)\s*\):/ ascii
    condition:
        $cmdclass or $install_sub
}

rule SupplyChain_Python_PTH_Code_Execution {
    meta:
        prefix = "SUPPLY_CHAIN_EXECUTION_HOOK"
        label = "Python .pth Startup Code Injection"
        category = "hook"
        severity = 95
        description = "Lines in .pth files executing code via import statements on Python interpreter startup"
    strings:
        $ = /^(import\s+[a-zA-Z0-9_.]+(\s*,\s*[a-zA-Z0-9_.]+)*|import\s+sys[;,]|import\s+os[;,])/ ascii
    condition:
        any of them
}

rule SupplyChain_Fileless_Memory_Execution {
    meta:
        prefix = "SUPPLY_CHAIN_EXECUTION_HOOK"
        label = "Fileless Memory Execution (memfd_create / libc)"
        category = "exec"
        severity = 95
        description = "Direct invocation of memfd_create, fexecve, or libc system via ctypes/ffi"
    strings:
        $cdll = /ctypes\.(CDLL|cdll)\s*\(\s*['"](libc\.so|msvcrt\.dll)/ ascii
        $memfd = /\b(memfd_create|fexecve)\b/ ascii
        $pyapi = /ctypes\.pythonapi/ ascii
    condition:
        ($cdll and $memfd) or $pyapi
}

rule SupplyChain_Network_Monkey_Patching {
    meta:
        prefix = "SUPPLY_CHAIN_EXECUTION_HOOK"
        label = "HTTP/HTTPS Network Interception Monkey Patch"
        category = "hook"
        severity = 85
        description = "Monkey patching core Node.js http/https request methods to intercept traffic"
    strings:
        $ = /(https?\.request|http\.get|https\.get)\s*=\s*(function|[a-zA-Z0-9_]+\s*=>)/ ascii
    condition:
        any of them
}
