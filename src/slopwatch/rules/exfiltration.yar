/* Exfiltration & C2 YARA Rules
 *
 * `confidence` (HIGH / MEDIUM / LOW) is a distinct axis from `severity`:
 * severity is "how bad if this is real", confidence is "how likely is a bare
 * match of this pattern to actually BE malicious, on its own, in real-world
 * legitimate code". A hardcoded live Discord webhook has near-zero legitimate
 * explanation; a raw public IP in a URL is routine (self-hosted services,
 * CDN edges, internal tooling) — treating them identically, as the scorer
 * did before this field existed, is exactly how a genuinely low-signal match
 * ends up mislabeled with the same confidence as a real C2 channel. See
 * flagthis_sentinel task.md's "Detection confidence" project note for the
 * full audit this is part of and how `confidence` is meant to be consumed
 * (UNVERIFIED_HIGH_SIGNAL verdict gating, not MALICIOUS/SUSPICIOUS, when
 * every contributing signal is below HIGH).
 */

rule Exfil_Discord_Webhook {
    meta:
        prefix = "EXFILTRATION_DESTINATION_DETECTED"
        label = "Discord Webhook"
        category = "exfil"
        confidence = "HIGH"
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
        confidence = "HIGH"
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
        // Pentest/OOB-interaction-testing services (webhook.site, interact.sh,
        // Burp Collaborator, ...) have no legitimate reason to appear in
        // shipped, non-security-tooling package code.
        confidence = "HIGH"
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
        // A hardcoded live ngrok/localtunnel/serveo URL shipped in a published
        // package is essentially never legitimate — these are local dev/test
        // endpoints, not something a real product embeds in its source.
        confidence = "HIGH"
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
        // Unusual but not unheard-of for legitimate low-effort tooling
        // (changelog fetchers, simple update-checkers genuinely do use Gists
        // as a public data store) — real, just meaningfully rarer than the
        // HIGH-confidence channels above.
        confidence = "MEDIUM"
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
        confidence = "MEDIUM"
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
        // Predominantly a malware dead-drop pattern historically, but some
        // legitimate CLI tools do offer an explicit "share output to
        // Pastebin" feature — kept MEDIUM rather than HIGH pending real
        // examples either way.
        confidence = "MEDIUM"
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
        // Severity is high regardless (a real secret hardcoded in shipped
        // source is bad either way), but confidence-of-MALICE is only
        // MEDIUM: this pattern equally matches an accidentally-committed
        // credential leak by an otherwise-legitimate maintainer, not
        // exclusively deliberate backdoor provisioning.
        confidence = "MEDIUM"
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
        // Bad practice, but real legitimate uses exist: internal/self-signed
        // cert testing tooling, some enterprise proxy compatibility shims.
        confidence = "MEDIUM"
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
        // The user-facing example this whole confidence axis was built for:
        // a raw (even routable) IP in a URL is routine in legitimate code
        // (self-hosted services, CDN edge nodes, internal APIs, health
        // checks) — the rule's own prior description already admitted this
        // "requires routability validation"; that validation (is_public_exfil_ip)
        // filters out private/loopback ranges, but even a public IP alone is
        // nowhere near as indicative as a named C2/dead-drop destination.
        confidence = "LOW"
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
        // Same reasoning as Exfil_OAST_Callback: these specific domains
        // (oast.fun, ceye.io, interactsh.com) are OOB-testing infrastructure
        // with no legitimate production use.
        confidence = "HIGH"
        description = "Secret exfiltration via DNS subdomain queries"
    strings:
        $dns1 = /dns\.(resolve|lookup)\s*\([^\)]{0,80}\.(oast\.fun|ceye\.io|vcap\.me)/ ascii nocase
        $dns2 = /gethostbyname\s*\([^\)]{0,80}\.(oast\.fun|ceye\.io|interactsh\.com)/ ascii nocase
    condition:
        any of them
}
