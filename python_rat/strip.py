import re

def strip_php(content: str) -> str:
    """
    Remove PHP string literals and comments so regex detectors don't fire inside them.
    Mimics precise Python vs naive PHP (PHP counted inside '__STR__' literals).
    Returns content with strings replaced by __STRn__ placeholders and comments removed.
    """
    strings = []
    def _repl(m):
        strings.append(m.group(0))
        return f"__STR{len(strings)-1}__"
    # Strings: single and double quoted (handle escaped)
    tmp = re.sub(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"", _repl, content)
    # // comments
    tmp = re.sub(r"//.*", "", tmp)
    # # comments at line start (avoid breaking # in other contexts)
    tmp = re.sub(r"^\s*#.*", "", tmp, flags=re.M)
    # /* block */
    tmp = re.sub(r"/\*.*?\*/", "", tmp, flags=re.S)
    return tmp
