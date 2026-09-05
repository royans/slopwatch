/* Credential Harvesting YARA Rules */

rule Cred_AWS_Credentials {
    meta:
        prefix = "CREDENTIAL_PATH_HARVESTING"
        label = "AWS Credentials (~/.aws/credentials)"
        category = "cred"
    strings:
        $ = /(~|\$HOME|%USERPROFILE%|[A-Za-z]:\\Users\\[^\\]+)\/(.aws\/credentials|.aws\/config)/ ascii nocase
    condition:
        any of them
}

rule Cred_SSH_Private_Keys {
    meta:
        prefix = "CREDENTIAL_PATH_HARVESTING"
        label = "SSH Private Keys (~/.ssh)"
        category = "cred"
    strings:
        $ = /(~|\$HOME|%USERPROFILE%|[A-Za-z]:\\Users\\[^\\]+)\/(.ssh\/id_rsa|.ssh\/id_ed25519|.ssh\/id_ecdsa|.ssh\/authorized_keys)/ ascii nocase
    condition:
        any of them
}

rule Cred_SSH_Directory {
    meta:
        prefix = "CREDENTIAL_PATH_HARVESTING"
        label = "SSH Directory / Private Keys (~/.ssh)"
        category = "cred"
    strings:
        $ = /(~|\$HOME|%USERPROFILE%|[A-Za-z]:\\Users\\[^\\]+)\/\.ssh(\b|\/|\b)/ ascii nocase
    condition:
        any of them
}

rule Cred_Registry_Git_Config {
    meta:
        prefix = "CREDENTIAL_PATH_HARVESTING"
        label = "Registry / Git Configuration (~/.yarnrc, ~/.gitconfig)"
        category = "cred"
    strings:
        $ = /(~|\$HOME|%USERPROFILE%|[A-Za-z]:\\Users\\[^\\]+)\/(.yarnrc|.gitconfig)/ ascii nocase
    condition:
        any of them
}

rule Cred_Cloud_Provider {
    meta:
        prefix = "CREDENTIAL_PATH_HARVESTING"
        label = "Cloud Provider Credentials (GCP, Azure, DigitalOcean)"
        category = "cred"
    strings:
        $ = /(~|\$HOME|%USERPROFILE%|[A-Za-z]:\\Users\\[^\\]+)\/(.config\/gcloud\/(application_default_credentials\.json|properties)|.azure\/(azureProfile|accessTokens)\.json|.config\/doctl\/config\.yaml)/ ascii nocase
    condition:
        any of them
}

rule Cred_Infra_DB {
    meta:
        prefix = "CREDENTIAL_PATH_HARVESTING"
        label = "Infrastructure & DB Credentials (~/.terraform.d, ~/.vault-token, ~/.pgpass, ~/.netrc)"
        category = "cred"
    strings:
        $ = /(~|\$HOME|%USERPROFILE%|[A-Za-z]:\\Users\\[^\\]+)\/(.terraform\.d\/credentials\.tfrc\.json|.vault-token|.pgpass|.netrc)/ ascii nocase
    condition:
        any of them
}

rule Cred_Shell_History {
    meta:
        prefix = "CREDENTIAL_PATH_HARVESTING"
        label = "Shell Command History (~/.bash_history, ~/.zsh_history)"
        category = "cred"
    strings:
        $ = /(~|\$HOME|%USERPROFILE%|[A-Za-z]:\\Users\\[^\\]+)\/\.(bash|zsh|python|sh)_history\b/ ascii nocase
    condition:
        any of them
}

rule Cred_Registry_Git {
    meta:
        prefix = "CREDENTIAL_PATH_HARVESTING"
        label = "Registry / Git Credentials (~/.npmrc, ~/.pypirc)"
        category = "cred"
    strings:
        $ = /(~|\$HOME|%USERPROFILE%|[A-Za-z]:\\Users\\[^\\]+)\/(.npmrc|.pypirc|.git-credentials)/ ascii nocase
    condition:
        any of them
}

rule Cred_Kube_Docker {
    meta:
        prefix = "CREDENTIAL_PATH_HARVESTING"
        label = "Kube / Docker Credentials"
        category = "cred"
    strings:
        $ = /(~|\$HOME|%USERPROFILE%|[A-Za-z]:\\Users\\[^\\]+)\/(.kube\/config|.docker\/config\.json)/ ascii nocase
    condition:
        any of them
}

rule Cred_Browser {
    meta:
        prefix = "CREDENTIAL_PATH_HARVESTING"
        label = "Browser Credentials / Cookies"
        category = "cred"
    strings:
        $ = /(Google\/Chrome|BraveSoftware\/Brave-Browser|Microsoft\/Edge)\/User Data\/Default\/(Login Data|Local State|Cookies)/ ascii nocase
    condition:
        any of them
}

rule Cred_Crypto_Wallet {
    meta:
        prefix = "CREDENTIAL_PATH_HARVESTING"
        label = "Crypto Wallet Extension Storage"
        category = "cred"
    strings:
        $ = /\b(nkbihfbeogaeaoehlefnkodbefgpgknn|ibnejdfjmmkpcnlpebklmnkoeoihofec|bfnaelmomeimhlpmgjnjophhpkkoljpa)\b/ ascii nocase
    condition:
        any of them
}

rule Cred_System {
    meta:
        prefix = "CREDENTIAL_PATH_HARVESTING"
        label = "System Credentials (/etc/shadow, /etc/passwd)"
        category = "cred"
    strings:
        $ = /\/etc\/(shadow|passwd)\b/ ascii
    condition:
        any of them
}

rule Cred_Cloud_IMDS {
    meta:
        prefix = "CREDENTIAL_PATH_HARVESTING"
        label = "Cloud Instance Metadata (AWS/GCP/Azure IMDS)"
        category = "cred"
    strings:
        $ = /(169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal\/computeMetadata\/v1|metadata\/identity\/oauth2\/token|latest\/api\/token\b)/ ascii nocase
    condition:
        any of them
}

rule Cred_Kubernetes_Token {
    meta:
        prefix = "CREDENTIAL_PATH_HARVESTING"
        label = "Kubernetes Service Account Token"
        category = "cred"
    strings:
        $ = /\/var\/run\/secrets\/kubernetes\.io\/serviceaccount(\/token)?/ ascii
    condition:
        any of them
}

rule Cred_Vault_Token {
    meta:
        prefix = "CREDENTIAL_PATH_HARVESTING"
        label = "HashiCorp Vault Credentials / Endpoint"
        category = "cred"
    strings:
        $ = /(\bVAULT_TOKEN\b|127\.0\.0\.1:8200)/ ascii nocase
    condition:
        any of them
}

rule Cred_IDE_AI_Agent_Hijacking {
    meta:
        prefix = "CREDENTIAL_PATH_HARVESTING"
        label = "IDE / AI Agent Configuration Hijacking"
        category = "cred"
    strings:
        $s1 = /(~|\$HOME|%USERPROFILE%|%APPDATA%|Library\/Application Support)\/[^\s"'\)]*(\.(vscode|claude|gemini|cursor)|Claude|Cursor)\/(settings|tasks|rules|mcp|claude_desktop_config|\.cursorrules)/ ascii nocase
        $s2 = /(["'\/]|^)(\.cursorrules|claude_desktop_config\.json|mcp\.json|setup-chrome-mcp|chrome-mcp)(\b|["'\/]|\.[a-zA-Z0-9]+)/ ascii nocase
    condition:
        $s1 or $s2
}

rule Cred_Browser_Vaults {
    meta:
        prefix = "CREDENTIAL_PATH_HARVESTING"
        label = "Browser Vaults & Password Databases"
        category = "cred"
        description = "Targeting browser profile credential databases and master keys"
    strings:
        $chrome_login = /(User Data|Default)\/(Login Data|Web Data|Cookies|Network\/Cookies)/ ascii nocase
        $firefox_key  = /(key4\.db|key3\.db|logins\.json|cert9\.db|profiles\.ini)/ ascii nocase
    condition:
        any of them
}

rule Cred_MacOS_Keychain {
    meta:
        prefix = "CREDENTIAL_PATH_HARVESTING"
        label = "macOS Keychain Dump"
        category = "cred"
        description = "Targeting macOS keychain items and passwords"
    strings:
        $ = /security\s+(find-generic-password|find-certificate|dump-keychain)\b/ ascii nocase
    condition:
        any of them
}
