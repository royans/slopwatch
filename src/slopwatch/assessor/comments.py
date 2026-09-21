"""Is a match position inside a source comment?

Used only to stop documentation from tripping credential-path rules (a JSDoc usage example such as
``ssh -i ~/.ssh/id_ed25519`` is not code that reads the key). Deliberately conservative so it cannot be
used to hide real code:

* only whole-line comment forms are recognised: a line that STARTS with ``//``, ``/*`` or ``*`` (JS-like
  files) or ``#`` (Python/shell-like files), and, for block comments, only when no ``*/`` appears before
  the match on that line, so ``/* x */ readFile('~/.ssh/id_rsa')`` is still code;
* a trailing comment after code (``run(); // ~/.ssh``) is NOT treated as a comment;
* multi-line block comments whose interior lines do not start with ``*`` are not recognised.
"""

_SLASH_EXTS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".java", ".go", ".c", ".h",
               ".cc", ".cpp", ".rs", ".php", ".kt", ".swift")
_HASH_EXTS = (".py", ".pyw", ".sh", ".bash", ".zsh", ".rb", ".pl", ".yml", ".yaml", ".toml", ".cfg", ".ini")


def is_in_comment(content: str, offset: int, filename: str) -> bool:
    line_start = content.rfind("\n", 0, offset) + 1
    prefix = content[line_start:offset]
    stripped = prefix.lstrip()
    name = (filename or "").lower()
    if name.endswith(_SLASH_EXTS):
        if stripped.startswith("//"):
            return True
        if stripped.startswith("/*") or stripped.startswith("*"):
            return "*/" not in prefix
        return False
    if name.endswith(_HASH_EXTS):
        return stripped.startswith("#")
    return False
