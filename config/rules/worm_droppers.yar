/* Worm & Runtime Droppers YARA Rules */

rule Worm_PyPI_Upload_Endpoint {
    meta:
        prefix = "CROSS_ECOSYSTEM_WORM_PROPAGATION"
        label = "PyPI Registry Upload Endpoint (Worm Replication)"
        category = "worm"
        description = "Direct target to PyPI legacy package upload endpoint for self-replication"
    strings:
        $ = /upload\.pypi\.org\/legacy\// ascii nocase
    condition:
        any of them
}

rule Worm_Token_Validator {
    meta:
        prefix = "CROSS_ECOSYSTEM_WORM_PROPAGATION"
        label = "Cross-Ecosystem Token Validator (Shai-Hulud Worm)"
        category = "worm"
        description = "Shai-Hulud worm multi-ecosystem token validator functions"
    strings:
        $ = /\b(handlePypiTokens|handleNpmTokens|handleRubygemsTokens)\b/ ascii
    condition:
        any of them
}

rule Worm_PyPI_Token_Probing {
    meta:
        prefix = "CROSS_ECOSYSTEM_WORM_PROPAGATION"
        label = "PyPI Token Harvesting / Probing"
        category = "worm"
        description = "PyPI authentication token format probing"
    strings:
        $ = /pypi-[A-Za-z0-9_-]{30,}/ ascii
    condition:
        any of them
}

rule Worm_Secondary_Runtime_Dropper {
    meta:
        prefix = "CROSS_ECOSYSTEM_WORM_PROPAGATION"
        label = "Automated Secondary Runtime Dropper (Bun/Deno/Python)"
        category = "worm"
        description = "Automated download of secondary standalone runtimes (Bun, Deno, Python)"
    strings:
        $ = /github\.com\/(oven-sh\/bun|denoland\/deno|indygreg\/python-build-standalone)\/releases\/download\// ascii nocase
    condition:
        any of them
}

rule Worm_Nodejs_Dropper {
    meta:
        prefix = "CROSS_ECOSYSTEM_WORM_PROPAGATION"
        label = "Automated Portable Node.js Dropper"
        category = "worm"
        description = "Automated download of portable Node.js runtime"
    strings:
        $ = /nodejs\.org\/dist\/v[0-9.]+\/node-v[0-9.]+/ ascii nocase
    condition:
        any of them
}

rule Worm_CI_Memory_Dump {
    meta:
        prefix = "CROSS_ECOSYSTEM_WORM_PROPAGATION"
        label = "CI Runner Memory Dump / Evasion"
        category = "worm"
        description = "CI/CD runner memory dumping and anti-analysis evasion"
    strings:
        $ = /\b(detectHardenRunner|Runner\.Worker|dumpMemory)\b/ ascii
    condition:
        any of them
}

rule Dropper_Hidden_Payload_Unpack {
    meta:
        prefix = "CROSS_ECOSYSTEM_WORM_PROPAGATION"
        label = "Steganography / Audio Dropper (Telnyx / TeamPCP Pattern)"
        category = "worm"
        description = "Steganographic payload delivery hiding executables in audio/image streams"
    strings:
        $wav_payload = /https?:\/\/[^\s"'`]+\.(wav|mp3|png|jpg|bmp)\b[^\n]{0,120}\b(subprocess|exec|os\.system|tarfile|base64)\b/ ascii nocase
        $tar_unpack   = /tarfile\.open\([^\)]{0,80}\)\.extractall\b/ ascii
    condition:
        any of them
}

rule Persistence_Implant {
    meta:
        prefix = "CROSS_ECOSYSTEM_WORM_PROPAGATION"
        label = "System Persistence Implant (systemd/cron/registry)"
        category = "worm"
        description = "Installation of scheduled persistence via systemd units, cron jobs, or startup run keys"
    strings:
        $systemd = /(~|\$HOME|\/etc)\/\.?config\/systemd\/user\/[a-zA-Z0-9_-]+\.service/ ascii nocase
        $cron    = /(\/etc\/cron\.(daily|hourly|d)\/|crontab\s+(-l|-r|.*\|\s*crontab))/ ascii nocase
        $win_run = /(Software\\Microsoft\\Windows\\CurrentVersion\\Run|Microsoft\\Windows\\Start Menu\\Programs\\Startup)/ ascii nocase
    condition:
        any of them
}
