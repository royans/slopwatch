/* Worm & Runtime Droppers YARA Rules */

rule Worm_PyPI_Upload_Endpoint {
    meta:
        prefix = "CROSS_ECOSYSTEM_WORM_PROPAGATION"
        label = "PyPI Registry Upload Endpoint (Worm Replication)"
        category = "worm"
        // Real publishing tools (twine, build backends) use this endpoint,
        // but they ARE the publishing tool — a random unrelated package
        // embedding it is the actual worm self-replication mechanism seen
        // in real campaigns (Shai-Hulud).
        confidence = "HIGH"
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
        // Literal function names lifted from the real Shai-Hulud worm's
        // source — near-zero legitimate collision risk.
        confidence = "HIGH"
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
        // Matches the FORMAT of a real PyPI token — could also appear in
        // legitimate docs/CI examples/test fixtures as a redacted placeholder.
        confidence = "MEDIUM"
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
        // Genuine worm behavior, but legitimate polyglot bootstrapper/
        // installer tooling can plausibly do this too.
        confidence = "MEDIUM"
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
        // Legitimate Node version managers (nvm/volta/fnm-style tools) do
        // exactly this.
        confidence = "MEDIUM"
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
        // Specific-looking internal names, but no confirmed real-world
        // false-positive or true-positive example checked this session —
        // rated cautiously pending real evidence either way.
        confidence = "MEDIUM"
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
        // The condition is "any of them": $tar_unpack alone
        // (tarfile.open(...).extractall()) can fire this on its own, and
        // that specific idiom is extremely common in totally legitimate
        // Python code (any tool that unpacks a downloaded archive). Rated
        // for the weaker of the two alternatives, not the stronger one.
        confidence = "MEDIUM"
        description = "Steganographic payload delivery hiding executables in audio/image streams"
    strings:
        $wav_payload = /https?:\/\/[^\s"'`]+\.(wav|mp3|png|jpg|bmp)\b[^\n]{0,120}\b(subprocess|exec|os\.system|tarfile|base64)\b/ ascii nocase
        $tar_unpack   = /tarfile\.open\([^\)]{0,80}\)\.extractall\b/ ascii
    condition:
        any of them
}

rule Persistence_Implant {
    meta:
        prefix = "SYSTEM_PERSISTENCE_TAMPERING"
        label = "System Persistence Implant (systemd/cron/registry)"
        category = "persistence"
        // Confirmed false positive on real-world `agentdiscover`: a
        // legitimate security-scanning tool's own detection-signature
        // string (checking whether a THIRD-PARTY agent has installed a
        // systemd/LaunchAgent persistence service) matches this bare path
        // pattern identically to code that actually WRITES such a file.
        // Same root cause as Cred_IDE_AI_Agent_Hijacking (credentials.yar).
        confidence = "LOW"
        description = "Installation of scheduled persistence via systemd units, cron jobs, or startup run keys"
    strings:
        $systemd = /(~|\$HOME|\/etc)\/\.?config\/systemd\/user\/[a-zA-Z0-9_-]+\.service/ ascii nocase
        $cron    = /(\/etc\/cron\.(daily|hourly|d)\/|crontab\s+(-l|-r|.*\|\s*crontab))/ ascii nocase
        $win_run = /(Software\\Microsoft\\Windows\\CurrentVersion\\Run|Microsoft\\Windows\\Start Menu\\Programs\\Startup)/ ascii nocase
    condition:
        any of them
}
