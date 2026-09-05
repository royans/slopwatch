/* Anti-Analysis & Sandbox Evasion YARA Rules */

rule Evasion_CI_Sandbox_Probing {
    meta:
        prefix = "ANTI_ANALYSIS_EVASION"
        label = "CI/CD & Sandbox Environment Detection"
        category = "evasion"
        severity = 75
        description = "Detects environment variables typical of CI runners or automated sandboxes"
    strings:
        $ = /\b(GITHUB_ACTIONS|TRAVIS_BUILD_ID|CIRCLECI|GITLAB_CI|BITBUCKET_BUILD_NUMBER|JENKINS_URL)\b/ ascii
        $ = /(process\.env|os\.environ(\.get)?|ENV)\s*\[?['"](CI|CONTINUOUS_INTEGRATION)['"]\]?/ ascii
    condition:
        any of them
}

rule Evasion_Sandbox_Hostname_Fingerprinting {
    meta:
        prefix = "ANTI_ANALYSIS_EVASION"
        label = "Sandbox / VM Hostname Fingerprinting"
        category = "evasion"
        severity = 80
        description = "Detects checks for known security sandbox or analysis hostnames and users"
    strings:
        $s1 = /['"](cuckoo|sandbox|virus|malware|sample|testbox|analyst)['"]\s*(in|==|!=)\s*[\w.]*(hostname|gethostname|host|user|username)/ ascii nocase
        $s2 = /[\w.]*(hostname|gethostname|host|user|username)\s*(in|==|!=)\s*['"](cuckoo|sandbox|virus|malware|sample|testbox|analyst)['"]/ ascii nocase
        $s3 = /[\w.]*(hostname|gethostname|host|user|username)\s*(in|==|!=)\s*\[[^\]]*['"](cuckoo|sandbox|virus|malware|sample|testbox|analyst)['"]/ ascii nocase
    condition:
        any of them
}

rule Evasion_Low_Resource_Threshold_Check {
    meta:
        prefix = "ANTI_ANALYSIS_EVASION"
        label = "Hardware Resource Threshold Probing"
        category = "evasion"
        severity = 70
        description = "Checking for minimal CPU core counts or memory sizes to detect virtual sandboxes"
    strings:
        $ = /(os\.cpu_count\(\)|os\.cpus\(\)\.length)\s*(<=?|<)\s*[12]\b/ ascii
        $ = /(totalmem\(\)|virtual_memory\(\)\.total)\s*(<=?|<)\s*[0-9]{9,10}\b/ ascii
    condition:
        any of them
}

rule Evasion_Extended_Timeout_Stall {
    meta:
        prefix = "ANTI_ANALYSIS_EVASION"
        label = "Extended Scanner Timeout Stall"
        category = "evasion"
        severity = 60
        description = "Excessive sleep or timeout delays designed to outlast security scanner execution budgets"
    strings:
        $ = /time\.sleep\(\s*(300|[4-9][0-9]{2}|[1-9][0-9]{3,})\s*\)/ ascii
        $ = /setTimeout\([^,]+,\s*(300000|[4-9][0-9]{5}|[1-9][0-9]{6,})\s*\)/ ascii
    condition:
        any of them
}
