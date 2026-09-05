/* Persistence & System Tampering YARA Rules */

rule Persistence_Cron_Tampering {
    meta:
        prefix = "SYSTEM_PERSISTENCE_TAMPERING"
        label = "Cron Job Installation / Tampering"
        category = "persistence"
        severity = 90
        description = "Attempts to install a persistent scheduled job via cron"
    strings:
        $ = /\/etc\/(cron\.d|cron\.daily|cron\.hourly|cron\.weekly|crontab)\b/ ascii nocase
        $ = /\/var\/spool\/cron\/(crontabs\/)?[A-Za-z0-9_.-]+/ ascii nocase
        $ = /crontab\s+(-l\s*\|\s*grep|-[eiru]\b|\s+-[a-z]*e)/ ascii nocase
    condition:
        any of them
}

rule Persistence_Shell_Profile_Modification {
    meta:
        prefix = "SYSTEM_PERSISTENCE_TAMPERING"
        label = "Shell Profile Backdoor Injection"
        category = "persistence"
        severity = 90
        description = "Attempts to append payloads to user shell profile startup scripts"
    strings:
        $ = /(~|\$HOME|%USERPROFILE%|[A-Za-z]:\\Users\\[^\\]+)\/\.(bashrc|zshrc|profile|bash_profile|config\/fish\/config\.fish)/ ascii nocase
        $ = /echo\s+['"].*['"]\s*>>\s*[\$\~A-Za-z0-9_\/.-]*\.(bashrc|zshrc|profile)/ ascii nocase
    condition:
        any of them
}

rule Persistence_Systemd_LaunchAgent {
    meta:
        prefix = "SYSTEM_PERSISTENCE_TAMPERING"
        label = "Systemd / macOS LaunchAgent Persistence"
        category = "persistence"
        severity = 90
        description = "Creation or tampering of system services or user LaunchAgents"
    strings:
        $ = /\/etc\/systemd\/system\/[A-Za-z0-9_.-]+\.service/ ascii nocase
        $ = /Library\/LaunchAgents\/[A-Za-z0-9_.-]+\.plist/ ascii nocase
    condition:
        any of them
}

rule Persistence_Windows_Registry_Run {
    meta:
        prefix = "SYSTEM_PERSISTENCE_TAMPERING"
        label = "Windows Run Key Persistence"
        category = "persistence"
        severity = 90
        description = "Writing to Windows autorun registry keys"
    strings:
        $ = /Software\\Microsoft\\Windows\\CurrentVersion\\Run\b/ ascii nocase
        $ = /reg\s+(add|copy)\s+['"]?HK(CU|LM)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/ ascii nocase
    condition:
        any of them
}
