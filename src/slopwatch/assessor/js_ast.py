"""
JavaScript data-flow analysis (optional: ``pip install "slopwatch[js]"``, tree-sitter).

The regex/YARA scan in npm_source.py reports that patterns *exist* in a file — `atob(`,
`fetch(`, `process.env`. In bundled SDKs those co-occur constantly with no relation between
them, which is how packages like `@clerk/clerk-js` reached UNVERIFIED_HIGH_SIGNAL. Malware is
defined by the connection: the secret goes *into* the request, the decoded string goes *into*
eval. This module parses the file and follows values from sources to sinks:

  JS_DATAFLOW_SECRET_EXFIL        the whole env, a credential file, or another service's token
                                   (NPM_TOKEN, AWS_*...) -> network call
  JS_DATAFLOW_HOST_RECON_BEACON   hostname/username/homedir/cwd -> network call
                                   (dependency-confusion beacons; MEDIUM on its own)
  JS_DATAFLOW_DECODE_TO_EXEC      base64/hex/charcode-decoded data -> eval/Function/vm/child_process
  JS_DATAFLOW_REMOTE_CODE_EXEC    a network response -> eval/Function/vm/child_process
  JS_SHELL_DOWNLOAD_CRADLE        child_process run with `curl|sh`, `powershell -enc`, ...

Flow tracking is deliberately simple — flow-insensitive, through variable declarations and
assignments to a fixpoint, with each name resolved to the function scope that declares it (so a
minifier's reused one-letter names do not connect unrelated code). It cannot follow values
through function parameters, returns or object properties, so it under-reports.
It only ever *adds* evidence: an absent flow does not clear a package (benchmark 2026-10-31:
discounting unconnected weak patterns cleared real malware and no popular package).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Dict, List, Optional, Set, Tuple

MAX_AST_BYTES = 768 * 1024
_MAX_EXPR_CHARS = 4000
_MAX_PASSES = 4

SECRET, CREDENTIAL, RECON, DECODED, REMOTE = "secret", "credential", "recon", "decoded", "remote"

# The whole environment, or a credential file. Either leaving the machine is exfiltration.
_BULK_SECRET_RE = re.compile(
    r"process\.env(?![\w.\[])"  # JSON.stringify(process.env), {...process.env}, Object.entries(process.env)
    r"|read(?:File|FileSync)\s*\([^;\n]{0,240}?(?:\.ssh|\.aws|\.npmrc|\.git-credentials|\.docker/config|\.kube/config|id_rsa|id_ed25519|\.env\b|Login Data|Local State|\.config/gcloud|keychain|wallet)",
    re.IGNORECASE,
)
# Credentials for *other* services. Not `OPENAI_API_KEY`: an SDK sending its own key to its
# own API is the normal case. A CI/registry token sent anywhere but its issuer is not.
_FOREIGN_CREDENTIAL_RE = re.compile(
    r"process\.env(?:\.|\[\s*['\"`])(?:NPM_TOKEN|NODE_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|GH_PAT|"
    r"AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SESSION_TOKEN|GOOGLE_APPLICATION_CREDENTIALS|"
    r"CI_JOB_TOKEN|VAULT_TOKEN|PYPI_TOKEN|TWINE_PASSWORD|DOCKER_PASSWORD|SSH_PRIVATE_KEY|"
    r"CIRCLE_TOKEN|GITLAB_TOKEN|ACTIONS_RUNTIME_TOKEN|ACTIONS_ID_TOKEN_REQUEST_TOKEN)\b"
)
# A named credential sent to its own issuer (npm publish tooling -> registry.npmjs.org).
_ISSUER_HOST_RE = re.compile(
    r"registry\.npmjs\.org|registry\.yarnpkg\.com|api\.github\.com|uploads\.github\.com|github\.com/login"
    r"|amazonaws\.com|googleapis\.com|gitlab\.com|upload\.pypi\.org|docker\.io|vault",
    re.IGNORECASE,
)
_RECON_RE = re.compile(
    r"\bos\s*\.\s*(?:hostname|userInfo|homedir|networkInterfaces)\s*\("
    r"|require\(\s*['\"]os['\"]\s*\)\s*\.\s*(?:hostname|userInfo|homedir|networkInterfaces)\s*\("
    r"|process\.env(?:\.|\[\s*['\"])(?:USER|USERNAME|LOGNAME|HOME|COMPUTERNAME|USERDOMAIN|HOSTNAME)\b"
    r"|\bprocess\.cwd\s*\(",
)
_DECODE_RE = re.compile(
    r"Buffer\s*\.\s*from\s*\([^()]{0,400}?,\s*['\"](?:base64|hex)['\"]"
    r"|\batob\s*\("
    r"|String\s*\.\s*fromCharCode\s*\("
    r"|zlib\s*\.\s*(?:inflate|gunzip|unzip|brotliDecompress)Sync\s*\(",
)
_NETWORK_FN_RE = re.compile(
    r"^(?:fetch|axios(?:\.\w+)?|got(?:\.\w+)?|needle(?:\.\w+)?|request|superagent\.\w+"
    r"|https?\.(?:request|get)|http2\.connect|net\.(?:connect|createConnection)|tls\.connect"
    r"|dns(?:\.promises)?\.(?:lookup|resolve\w*)|\w+\.(?:sendBeacon))$"
)
_NETWORK_CTOR_RE = re.compile(r"^(?:WebSocket|XMLHttpRequest|net\.Socket)$")
_HANDLE_WRITE_RE = re.compile(r"^(\w+)\.(?:write|end|send)$")
_EXEC_FN_RE = re.compile(
    r"^(?:eval|Function|(?:global|globalThis|window)\s*\.\s*eval"
    r"|vm\.(?:runInThisContext|runInNewContext|runInContext|compileFunction)"
    r"|(?:\w+\.)?(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|fork))$"
)
_EXEC_CTOR_RE = re.compile(r"^(?:Function|vm\.Script)$")
_CHILD_PROCESS_RE = re.compile(r"child_process")
_CRADLE_RE = re.compile(
    r"(?:curl|wget)\b[^|;&]{0,300}\|\s*(?:ba|z)?sh\b"
    r"|powershell[^'\"`]{0,80}\s-(?:e|enc|encodedcommand)\s"
    r"|\b(?:iwr|Invoke-WebRequest|Invoke-Expression|iex)\b"
    r"|certutil[^'\"`]{0,80}-urlcache",
    re.IGNORECASE,
)
_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")

_QUERY = """
(call_expression function: (_) @fn arguments: (arguments) @args) @call
(new_expression constructor: (_) @fn arguments: (arguments) @args) @call
(variable_declarator name: (identifier) @lhs value: (_) @rhs) @decl
(variable_declarator name: (identifier) @declonly !value) @decl
(assignment_expression left: (identifier) @lhs right: (_) @rhs) @assign
(formal_parameters (identifier) @param)
(formal_parameters (assignment_pattern left: (identifier) @param))
(arrow_function parameter: (identifier) @param)
"""

_FUNCTION_TYPES = frozenset({
    "function_declaration", "function_expression", "arrow_function", "method_definition",
    "generator_function_declaration", "generator_function", "function",
})
_NON_VALUE_TYPES = frozenset({"function_expression", "arrow_function", "class", "function", "generator_function"})
_MAX_TAINT_EXPR_CHARS = 1200
_REMOTE_HEAD_RE = re.compile(
    r"^\s*(?:await\s+)?\(?\s*(?:fetch|axios(?:\.\w+)?|got(?:\.\w+)?|needle(?:\.\w+)?|https?\.get)\s*\("
)


@dataclass
class JsFlowReport:
    analysed: bool = False
    flows: List[Tuple[str, str]] = field(default_factory=list)  # (flag_prefix, detail)

    @property
    def flag_prefixes(self) -> Set[str]:
        return {p for p, _ in self.flows}


@lru_cache(maxsize=1)
def _parser_and_query():
    try:
        import tree_sitter as ts
        import tree_sitter_javascript as tsj
    except ImportError:
        return None
    lang = ts.Language(tsj.language())
    return ts.Parser(lang), ts.Query(lang, _QUERY), ts.QueryCursor


def available() -> bool:
    return _parser_and_query() is not None


def _text(node) -> str:
    raw = node.text or b""
    return raw[:_MAX_EXPR_CHARS].decode("utf-8", errors="ignore")


def _direct_kinds(text: str, network_calls_are_remote: bool) -> Set[str]:
    kinds: Set[str] = set()
    if _BULK_SECRET_RE.search(text):
        kinds.add(SECRET)
    if _FOREIGN_CREDENTIAL_RE.search(text):
        kinds.add(CREDENTIAL)
    if _RECON_RE.search(text):
        kinds.add(RECON)
    if _DECODE_RE.search(text):
        kinds.add(DECODED)
    if network_calls_are_remote and _REMOTE_HEAD_RE.match(text):
        kinds.add(REMOTE)
    return kinds


def analyze_js_source(content: str, filename: str) -> JsFlowReport:
    """Follow secrets / decoded data / network responses into network and execution sinks."""
    pq = _parser_and_query()
    if pq is None or len(content) > MAX_AST_BYTES:
        return JsFlowReport(analysed=False)
    parser, query, cursor_cls = pq
    try:
        tree = parser.parse(content.encode("utf-8", errors="ignore"))
        matches = cursor_cls(query).matches(tree.root_node)
    except Exception:
        return JsFlowReport(analysed=False)

    # Scopes: every value is keyed by the function that declares it, so the one-letter names a
    # minifier reuses in thousands of functions (`t`, `e`) do not link unrelated code.
    chains: Dict[int, Tuple[int, ...]] = {}

    def chain(node) -> Tuple[int, ...]:
        """Enclosing function scopes, innermost first; 0 = module scope."""
        path, n = [], node.parent
        while n is not None:
            if n.id in chains:
                return tuple(path) + chains[n.id]
            if n.type in _FUNCTION_TYPES:
                path.append(n.id)
            n = n.parent
        return tuple(path) + (0,)

    def memo_chain(node) -> Tuple[int, ...]:
        c = chain(node)
        chains[node.id] = c
        return c

    declared: Dict[int, Set[str]] = {}
    assigns: List[Tuple[str, Tuple[int, ...], str, Tuple[int, ...], bool]] = []  # (lhs, lhs_chain, rhs, rhs_chain, is_decl)
    calls: List[Tuple[str, str, Tuple[int, ...], bool]] = []  # (fn_text, args_text, chain, is_new)
    for _, cap in matches:
        if "param" in cap:
            p = cap["param"][0]
            fn_node = p.parent
            while fn_node is not None and fn_node.type not in _FUNCTION_TYPES:
                fn_node = fn_node.parent
            if fn_node is not None:
                declared.setdefault(fn_node.id, set()).add(_text(p))
        elif "declonly" in cap:
            declared.setdefault(memo_chain(cap["decl"][0])[0], set()).add(_text(cap["declonly"][0]))
        elif "lhs" in cap:
            rhs_node = cap["rhs"][0]
            is_decl = "decl" in cap
            ch = memo_chain(cap["decl"][0] if is_decl else cap["assign"][0])
            name = _text(cap["lhs"][0])
            if is_decl:
                declared.setdefault(ch[0], set()).add(name)
            if rhs_node.type in _NON_VALUE_TYPES or rhs_node.end_byte - rhs_node.start_byte > _MAX_TAINT_EXPR_CHARS:
                continue  # a function body or a huge expression is not "the value" of anything
            assigns.append((name, ch, _text(rhs_node), ch, is_decl))
        elif "fn" in cap:
            call = cap["call"][0]
            calls.append((_text(cap["fn"][0]).replace(" ", ""), _text(cap["args"][0]), memo_chain(call),
                          call.type == "new_expression"))

    def home(name: str, ch: Tuple[int, ...]) -> int:
        """The scope that owns `name` as seen from `ch` (module scope if undeclared)."""
        for sid in ch:
            if name in declared.get(sid, ()):
                return sid
        return 0

    taint: Dict[Tuple[int, str], Set[str]] = {}
    handles: Set[Tuple[int, str]] = set()  # request/socket objects: req.write(data) is a sink

    def expr_kinds(text: str, ch: Tuple[int, ...]) -> Set[str]:
        kinds = _direct_kinds(text, network_calls_are_remote=True)
        for ident in set(_IDENT_RE.findall(text)):
            kinds |= taint.get((home(ident, ch), ident), set())
        return kinds

    for _ in range(_MAX_PASSES):
        changed = False
        for lhs, lch, rhs, rch, is_decl in assigns:
            key = (lch[0] if is_decl else home(lhs, lch), lhs)
            kinds = expr_kinds(rhs, rch)
            if kinds - taint.get(key, set()):
                taint.setdefault(key, set()).update(kinds)
                changed = True
            if key not in handles and re.match(r"\s*(?:https?\.request|https?\.get|net\.(?:connect|createConnection)|tls\.connect|new\s+(?:WebSocket|net\.Socket))\b", rhs):
                handles.add(key)
                changed = True
        if not changed:
            break

    file_uses_child_process = bool(_CHILD_PROCESS_RE.search(content))
    flows: Dict[str, str] = {}
    for fn, args, ch, is_new in calls:
        if len(args) > _MAX_TAINT_EXPR_CHARS:
            continue  # e.g. a webpack module wrapper passed as an argument
        is_network = (
            (not is_new and _NETWORK_FN_RE.match(fn))
            or (is_new and _NETWORK_CTOR_RE.match(fn))
            or bool((m := _HANDLE_WRITE_RE.match(fn)) and (home(m.group(1), ch), m.group(1)) in handles)
        )
        is_exec = (
            (not is_new and _EXEC_FN_RE.match(fn) and (
                fn in ("eval", "Function") or "eval" in fn or fn.startswith("vm.") or file_uses_child_process))
            or (is_new and _EXEC_CTOR_RE.match(fn))
        )
        if not (is_network or is_exec):
            continue
        kinds = expr_kinds(args, ch)
        if is_network:
            kinds.discard(REMOTE)  # fetch(url) inside another fetch's args is not exfil
            if SECRET in kinds or (CREDENTIAL in kinds and not _ISSUER_HOST_RE.search(args)):
                flows.setdefault("JS_DATAFLOW_SECRET_EXFIL", f"secret data reaches {fn}() in {filename}")
            elif RECON in kinds:
                flows.setdefault("JS_DATAFLOW_HOST_RECON_BEACON", f"host/user details reach {fn}() in {filename}")
        if is_exec:
            if DECODED in kinds:
                flows.setdefault("JS_DATAFLOW_DECODE_TO_EXEC", f"decoded data reaches {fn}() in {filename}")
            if REMOTE in kinds:
                flows.setdefault("JS_DATAFLOW_REMOTE_CODE_EXEC", f"a network response reaches {fn}() in {filename}")
            if fn not in ("eval", "Function") and _CRADLE_RE.search(args):
                flows.setdefault("JS_SHELL_DOWNLOAD_CRADLE", f"{fn}() runs a download-and-execute shell command in {filename}")

    return JsFlowReport(analysed=True, flows=sorted(flows.items()))
