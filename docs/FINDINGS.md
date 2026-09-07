# 📇 SlopWatch Finding Codes

Every finding SlopWatch's dependency gate (`slopwatch check`, `slopwatch audit`)
can raise on a manifest has a **stable identifier** of the form `SLOP-XXXX`.

Stable means: a code never changes meaning and is never reused. You can safely

- cite a code in an issue, PR review, or CI log,
- diff `--json` output across runs by code,
- suppress a code precisely with `--ignore SLOP-0003` on the CLI, or an
  `ignore:` list in `.slopwatch.yaml`.

Suppressed findings are **not** silently dropped — they still appear in the
run output, listed in the **suppression ledger**, and in `--json` under
`suppressions`.

---

## Manifest gate codes (`SLOP-XXXX`)

| Code | Title | Default severity | Category | Meaning |
| :--- | :--- | :--- | :--- | :--- |
| `SLOP-0001` | Unregistered / hallucinated package | HIGH | hallucination | Name does not resolve on the public registry (HTTP 404). Typically an LLM-invented name, or a real name an attacker has not parked yet. |
| `SLOP-0002` | Name matches an active slopsquat watchlist entry | CRITICAL | slopsquat | Name matches a candidate on SlopWatch's slopsquat watchlist — a plausible hallucination target being actively monitored for adversarial registration. |
| `SLOP-0003` | Typosquat of a popular package | HIGH | typosquat | Name is within edit distance 1 of a well-known package (e.g. `reqeusts` → `requests`). The concrete `reason` names the target (`SUSPICIOUS_TYPOSQUAT_OF_REQUESTS`). |
| `SLOP-0004` | Direct VCS or raw-URL dependency | MEDIUM | unpinned | Dependency is pulled from a VCS ref or raw URL rather than a registry release, bypassing registry verification and (usually) version pinning. |

The machine-readable source of truth is
[`slopwatch/core/finding_catalog.py`](../src/slopwatch/core/finding_catalog.py).

### Suppressing a code

```yaml
# .slopwatch.yaml
ignore:
  - "SLOP-0004"          # accept direct VCS/URL deps in this repo
```

```bash
slopwatch check . --ignore SLOP-0004 --ignore SLOP-0003
```

An `--ignore` token may be a code (`SLOP-0004`, case-insensitive) or a full
reason string (`SUSPICIOUS_TYPOSQUAT_OF_REQUESTS`). Unknown tokens are
reported and otherwise ignored.

---

## Deep-inspection evidence codes (`RULE_*`)

`slopwatch inspect <package>` runs the full AST + metadata + provenance
scoring engine. Each contributing signal carries a `rule_code` in `--json`
output (`evidence[].rule_code` / `flags`). These are **evidence identifiers**,
not gate findings — they explain how a threat score was reached rather than
gating CI, so they are versioned with the scoring engine rather than frozen
in this catalog. The current namespace:

| Group | Codes |
| :--- | :--- |
| Registration age | `RULE_AI_ERA_RECENT_REGISTRATION`, `RULE_AI_ERA_1YR_WINDOW`, `RULE_PRE_AI_HISTORICAL_PACKAGE` |
| Naming / brand | `RULE_GRAMMAR_TRIPLET_MATCH`, `RULE_HIGH_VALUE_BRAND`, `RULE_INTERNAL_KEYWORD_HEURISTIC` |
| Publisher authenticity | `RULE_CRYPTOGRAPHIC_PROVENANCE`, `RULE_OFFICIAL_AUTHOR_DOMAIN`, `RULE_OFFICIAL_REPO_LINEAGE`, `RULE_ORGANIZATIONAL_DOMAIN_ALIGNMENT`, `RULE_DYNAMIC_DOMAIN_TRUST`, `RULE_UNVERIFIED_AUTHOR_DOMAIN` |
| Documentation / effort | `RULE_RICH_DOCUMENTATION`, `RULE_MINIMAL_DESCRIPTION`, `RULE_EMPTY_CODE_STUB`, `RULE_SUBSTANTIAL_CODEBASE` |
| Version anomalies | `RULE_RAPID_SEMVER_BURST`, `RULE_FUTURE_CALVER_DATE`, `RULE_INFLATED_MAJOR_VERSION`, `RULE_URL_CONFUSION_SOURCERANK_HIJACK` |
| Code analysis | `RULE_AST_WEAPONIZED_EXEC`, `RULE_AST_SUSPICIOUS_CALL`, `RULE_AST_CLEAN` |
| Community adoption | `RULE_HIGH_DOWNLOAD_MOMENTUM`, `RULE_POPULAR_COMMUNITY_PACKAGE`, `RULE_ACTIVE_COMMUNITY_USAGE`, `RULE_MODERATE_COMMUNITY_USAGE` |
| Vendor / lifecycle | `RULE_TRUSTED_VENDOR_DISCOUNT`, `RULE_VENDOR_TAKEOVER_ALERT`, `RULE_REGISTRY_DEPRECATED` |
