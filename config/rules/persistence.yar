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
        $append_redir = />>\s*[\$\~A-Za-z0-9_\/.-]*\.(bashrc|zshrc|profile|bash_profile|config\/fish\/config\.fish)/ ascii nocase
        $append_tee   = /tee\s+-a\s+[\$\~A-Za-z0-9_\/.-]*\.(bashrc|zshrc|profile|bash_profile)/ ascii nocase
        $append_fn    = /(appendFile|appendFileSync|writeFile|writeFileSync)\s*\([^)]*\.(bashrc|zshrc|profile|bash_profile)/ ascii nocase
        $append_py    = /open\s*\([^)]*\.(bashrc|zshrc|profile|bash_profile)['"][^)]*['"][aw]/ ascii nocase
    condition:
        any of them
}

rule Persistence_Systemd_LaunchAgent {
    meta:
        prefix = "SYSTEM_PERSISTENCE_TAMPERING"
        label = "Systemd / macOS LaunchAgent Persistence"
        category = "persistence"
        confidence = "LOW"
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

rule Persistence_Shortcut_Hijacking {
    meta:
        prefix = "SYSTEM_PERSISTENCE_TAMPERING"
        label = "Shortcut Hijacking (.lnk Rewrite / Browser Extension Sideload)"
        category = "persistence"
        severity = 90
        description = "Rewrites an existing desktop/Start Menu/taskbar .lnk shortcut via WScript.Shell COM automation (MITRE ATT&CK T1547.009), commonly to inject --load-extension and auto-sideload a malicious browser extension on every launch"
    strings:
        // WScript.Shell.CreateShortcut() is the real API used to read/modify an
        // EXISTING .lnk file's target/arguments — a normal package has no
        // legitimate reason to touch other applications' pre-existing shortcuts.
        // Real confirmed-malicious sample this was written for: "beautifulsup4"
        // (typosquats beautifulsoup4), which walks the Start Menu / Quick Launch
        // / Desktop / TaskBar looking for chrome.exe/msedge.exe/brave.exe
        // shortcuts and rewrites their Arguments to `--load-extension=` a
        // clipboard-hijacking crypto-address-swapper extension it just dropped.
        $create_shortcut = /\.CreateShortcut\s*\(/ ascii
        $wscript_shell = /WScript\.Shell/ ascii
        // Requiring co-occurrence with the extension-sideload flag makes this
        // the strongest possible signal without the ambiguity of $load_ext
        // alone (legitimate browser-automation test tooling can pass
        // --load-extension for its OWN bundled extension under test — but never
        // via WScript.Shell shortcut rewriting, which is the actual
        // persistence mechanism, not test automation).
        $load_ext = /--load-extension=/ ascii nocase
    condition:
        ($create_shortcut and $wscript_shell) or $load_ext and $wscript_shell
}
