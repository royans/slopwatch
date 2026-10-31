/* AI-agent instruction injection: text a package hands to a coding agent
   (MCP tool descriptions, SKILL.md / CLAUDE.md / AGENTS.md / .cursorrules, prompts in source)
   that tells the agent to act against its user. Patterned on the published MCP tool-poisoning
   and "ASCII smuggling" attacks. Every rule needs an action or a concealment directive, not just
   a suspicious phrase: security tooling and prompt-injection test suites quote the phrases. */

rule Agent_Tool_Poisoning_Concealed_Secret_Access {
    meta:
        prefix = "AGENT_INSTRUCTION_INJECTION"
        label = "Concealed instruction to read or send secrets"
        category = "agent_injection"
        severity = 85
        confidence = "HIGH"
        description = "Tells an agent to read/send credentials or keys and to keep that from the user"
    strings:
        $conceal = /(do not|don't|dont|never|must not|without)\s+(tell|telling|mention|mentioning|inform|informing|reveal|revealing|disclose|disclosing|notify|notifying|alert|alerting)\s+(this\s+to\s+|it\s+to\s+)?(the\s+)?user/ nocase
        $secret = /(~\/\.ssh|id_rsa|id_ed25519|\.aws\/credentials|mcp\.json|\.npmrc|\.pypirc|\.git-credentials|\.env\b|private[ _]key|api[ _-]?keys?\b|access[ _]tokens?\b|seed phrase|mnemonic)/ nocase
        $action = /\b(read|cat|open|send|upload|post|include|attach|pass|copy|exfiltrate|transmit)\b/ nocase
    condition:
        $conceal and $secret and $action
}

rule Agent_Tool_Poisoning_Important_Tag {
    meta:
        prefix = "AGENT_INSTRUCTION_INJECTION"
        label = "Hidden <IMPORTANT> block targeting secrets"
        category = "agent_injection"
        severity = 85
        confidence = "HIGH"
        description = "An <IMPORTANT>-style block in agent-facing text that points the agent at credential files"
    strings:
        $ = /<(IMPORTANT|important|CRITICAL|SYSTEM)>[\s\S]{0,600}(~\/\.ssh|id_rsa|\.aws\/credentials|mcp\.json|\.cursor\/|\.npmrc|\.env\b|private key)/
    condition:
        any of them
}

rule Agent_Hidden_Unicode_Tag_Smuggling {
    meta:
        prefix = "AGENT_INSTRUCTION_INJECTION"
        label = "Invisible Unicode tag characters (ASCII smuggling)"
        category = "agent_injection"
        severity = 80
        confidence = "HIGH"
        description = "Runs of U+E0000-U+E007F tag characters: text an agent reads but a human reviewer cannot see"
    strings:
        $ = /(\xF3\xA0[\x80\x81][\x80-\xBF]){8,}/
    condition:
        any of them
}

rule Agent_Instruction_Override {
    meta:
        prefix = "AGENT_INSTRUCTION_INJECTION"
        label = "Instruction-override phrase"
        category = "agent_injection"
        severity = 40
        confidence = "MEDIUM"
        description = "Classic prompt-injection override ('ignore all previous instructions') in agent-facing text"
    strings:
        $ = /(ignore|disregard|forget)\s+(all\s+)?(of\s+)?(the\s+|your\s+)?(previous|prior|above|earlier|preceding)\s+(instructions|rules|directives|guidelines)/ nocase
    condition:
        any of them
}

rule Agent_AutoApprove_Config_Tampering {
    meta:
        prefix = "AGENT_INSTRUCTION_INJECTION"
        label = "Writes agent auto-approval settings"
        category = "agent_injection"
        severity = 60
        confidence = "MEDIUM"
        description = "Code that writes a config enabling agent auto-approval / permission bypass"
    strings:
        $flag = /(dangerously-skip-permissions|dangerously-bypass-approvals-and-sandbox|"autoApprove"\s*:\s*\[|chat\.tools\.autoApprove"?\s*:\s*true|"alwaysAllow"\s*:\s*\[|enableAllProjectMcpServers"?\s*:\s*true|"defaultMode"\s*:\s*"bypassPermissions")/
        $write = /(writeFileSync|writeFile|appendFileSync|\.write_text\(|json\.dump\(|open\([^)]{0,120}['"][wa]['"])/
    condition:
        $flag and $write
}
