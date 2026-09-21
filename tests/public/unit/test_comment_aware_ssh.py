"""~/.ssh matches inside source comments (docs/examples) are ignored; real code, and comment-disguised code, is not."""
from unittest.mock import patch

import pytest

from slopwatch.assessor.comments import is_in_comment
from slopwatch.assessor import npm_source
from slopwatch.assessor.yara_engine import get_yara_scanner

SSH = "~/.ssh/id_ed25519"


def _off(content):
    return content.index("~/.ssh")


@pytest.mark.parametrize("content,filename,expected", [
    (f"/** usage: ssh -i {SSH} host */", "a.js", True),                  # JSDoc, single line
    (f"/**\n * run: ssh -i {SSH}\n */", "a.ts", True),                    # block comment continuation line
    (f"// ssh -i {SSH}", "a.js", True),
    (f"    // ssh -i {SSH}", "a.mjs", True),
    (f"# ssh -i {SSH}", "a.py", True),
    (f"/* x */ fs.readFileSync('{SSH}')", "a.js", False),                # code after a closed comment
    (f"fs.readFileSync('{SSH}') // {SSH}", "a.js", False),               # code on the line
    (f"fs.readFileSync('{SSH}')", "a.js", False),
    (f"open('{SSH}')  # {SSH}", "a.py", False),
    (f"# note\nopen('{SSH}')", "a.py", False),                           # next line is code
    (f"# {SSH}", "a.js", False),                                         # '#' is not a JS comment
    (f"// {SSH}", "README.md", False),                                   # unknown file type: not treated as comment
])
def test_is_in_comment(content, filename, expected):
    assert is_in_comment(content, _off(content), filename) is expected


JSDOC = f"""/** Configure sandbox SSH key. Example:
 * ```bash ssh -o ExitOnForwardFailure=yes -i {SSH} -N -R 7777:127.0.0.1:7777 user@host```
 */
export function configure() {{ return 1; }}
"""
CODE = f"const k = require('fs').readFileSync(process.env.HOME + '/x'); require('fs').readFileSync('{SSH}');\n"
DISGUISED = f"/* config */ require('fs').readFileSync('{SSH}');\n"


def _ssh_flags(flags):
    return [f for f in flags if "~/.ssh" in f[0]]


@pytest.mark.parametrize("use_yara", [True, False])
def test_scanners_ignore_ssh_in_comments_but_not_in_code(use_yara):
    scanner = get_yara_scanner()
    if use_yara and not scanner.is_available:
        pytest.skip("yara not available")
    ctx = patch.object(type(scanner), "is_available", property(lambda self: use_yara))
    with ctx:
        assert _ssh_flags(npm_source._scan_file_content(JSDOC, "lib/boat.js")[0]) == []
        assert _ssh_flags(npm_source._scan_file_content(CODE, "lib/steal.js")[0]) != []
        assert _ssh_flags(npm_source._scan_file_content(DISGUISED, "lib/steal.js")[0]) != []


def test_only_ssh_rules_are_comment_aware():
    """Other credential paths keep flagging inside comments: this change is scoped to ~/.ssh."""
    assert npm_source._COMMENT_INSENSITIVE_LABELS == {"SSH Private Keys (~/.ssh)", "SSH Directory / Private Keys (~/.ssh)"}
