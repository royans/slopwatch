/* Exfiltration & C2 YARA Rules */

rule Exfil_Discord_Webhook {
    meta:
        prefix = "EXFILTRATION_DESTINATION_DETECTED"
        label = "Discord Webhook"
        category = "exfil"
        description = "Outbound exfiltration channel to Discord webhook"
    strings:
        $ = /https?:\/\/(ptb\.|canary\.)?discord(app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/ ascii nocase
    condition:
        any of them
}

rule Exfil_Telegram_Bot {
    meta:
        prefix = "EXFILTRATION_DESTINATION_DETECTED"
        label = "Telegram Bot API"
        category = "exfil"
        description = "Outbound command and exfiltration channel to Telegram Bot API"
    strings:
        $ = /https?:\/\/api\.telegram\.org\/bot[0-9]+:[A-Za-z0-9_-]+/ ascii nocase
    condition:
        any of them
}

rule Exfil_OAST_Callback {
    meta:
        prefix = "EXFILTRATION_DESTINATION_DETECTED"
        label = "OAST / Callback Service"
        category = "exfil"
        description = "Out-of-band application security testing / data collector callback domain"
    strings:
        $ = /https?:\/\/[a-zA-Z0-9_-]+\.(webhook\.site|pipedream\.net|interact\.sh|oastify\.com|burpcollaborator\.net|requestcatcher\.com|beeceptor\.com|hookdeck\.com)/ ascii nocase
    condition:
        any of them
}

rule Exfil_Tunneling {
    meta:
        prefix = "EXFILTRATION_DESTINATION_DETECTED"
        label = "Tunneling Service"
        category = "exfil"
        description = "Reverse tunneling service endpoint"
    strings:
        $ = /https?:\/\/[a-zA-Z0-9_-]+\.(ngrok-free\.app|ngrok\.io|localtunnel\.me|serveo\.net|trycloudflare\.com|bore\.pub|pinggy\.io)/ ascii nocase
    condition:
        any of them
}

rule Exfil_GitHub_Gists {
    meta:
        prefix = "EXFILTRATION_DESTINATION_DETECTED"
        label = "GitHub Gists API Exfiltration (Dead Drop)"
        category = "exfil"
        description = "GitHub Gists dead drop API endpoint"
    strings:
        $ = /https?:\/\/api\.github\.com\/gists\b/ ascii nocase
    condition:
        any of them
}

rule Exfil_GitLab_Snippets {
    meta:
        prefix = "EXFILTRATION_DESTINATION_DETECTED"
        label = "GitLab Snippets API Exfiltration"
        category = "exfil"
        description = "GitLab Snippets API endpoint"
    strings:
        $ = /https?:\/\/gitlab\.com\/api\/v4\/snippets\b/ ascii nocase
    condition:
        any of them
}

rule Exfil_Pastebin {
    meta:
        prefix = "EXFILTRATION_DESTINATION_DETECTED"
        label = "Pastebin API Exfiltration"
        category = "exfil"
        description = "Pastebin / text paste exfiltration endpoint"
    strings:
        $ = /https?:\/\/(pastebin\.com\/api|hastebin\.com\/documents|ghostbin\.com\/paste)/ ascii nocase
    condition:
        any of them
}

rule Exfil_Hardcoded_GitHub_PAT {
    meta:
        prefix = "EXFILTRATION_DESTINATION_DETECTED"
        label = "Hardcoded GitHub Personal Access Token"
        category = "exfil"
        description = "Hardcoded GitHub classic or fine-grained Personal Access Token"
    strings:
        $ = /\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b/ ascii
    condition:
        any of them
}

rule Exfil_TLS_Verification_Bypass {
    meta:
        prefix = "EXFILTRATION_DESTINATION_DETECTED"
        label = "TLS / SSL Verification Bypass (Defense Evasion)"
        category = "exfil"
        description = "Disabling SSL/TLS certificate verification for covert communications"
    strings:
        $ = /(ssl\._create_unverified_context|check_hostname\s*=\s*False|verify_mode\s*=\s*(ssl\.)?CERT_NONE|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"0])/ ascii nocase
    condition:
        any of them
}

rule Exfil_Raw_IP_Endpoint {
    meta:
        prefix = "EXFILTRATION_DESTINATION_DETECTED"
        label = "Raw Public IP Endpoint"
        category = "raw_ip"
        description = "URL containing raw IPv4 address requiring routability validation"
    strings:
        $ = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(:[0-9]{2,5})?/ ascii nocase
    condition:
        any of them
}

rule Exfil_DNS_Tunneling {
    meta:
        prefix = "EXFILTRATION_DESTINATION_DETECTED"
        label = "DNS Subdomain Exfiltration"
        category = "exfil"
        description = "Secret exfiltration via DNS subdomain queries"
    strings:
        $dns1 = /dns\.(resolve|lookup)\s*\([^\)]{0,80}\.(oast\.fun|ceye\.io|vcap\.me)/ ascii nocase
        $dns2 = /gethostbyname\s*\([^\)]{0,80}\.(oast\.fun|ceye\.io|interactsh\.com)/ ascii nocase
    condition:
        any of them
}
