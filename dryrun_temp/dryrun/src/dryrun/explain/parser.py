"""Shell command-line parser for the POSIX-ish subset dryrun analyzes.

The parser never expands anything: words keep their literal text and are
tagged (``glob``, ``var``, ``tilde``) so the auditor and explainer can
reason about them.  It parses or raises :class:`ShellParseError`; it
never crashes on malformed input.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from dryrun.explain.ast_nodes import (
    CommandList,
    Pipeline,
    Redirect,
    SimpleCommand,
    Substitution,
    Word,
)

_REDIRECT_OPS = (">>", "<<", ">&", "<&", "&>")
_SEP_TWO = ("&&", "||")


class ShellParseError(ValueError):
    """Raised when the command line cannot be parsed."""


def _is_operator_start(ch: str) -> bool:
    """Return True when ``ch`` can begin an operator token."""
    return ch in "|&;()<>"


def _word_kind(text: str) -> str:
    """Classify a word as glob / var / tilde / plain (no expansion)."""
    if text.startswith("~"):
        return "tilde"
    if "$" in text:
        return "var"
    if "*" in text or "?" in text or "[" in text:
        return "glob"
    return "plain"


def _skip_ws(s: str, i: int) -> int:
    """Advance ``i`` past spaces and tabs."""
    while i < len(s) and s[i] in " \t":
        i += 1
    return i


def _scan_quoted(s: str, i: int, quote: str) -> Tuple[str, int]:
    """Scan a quoted region starting at ``s[i] == quote``.

    Returns the unquoted text and the index just past the closing quote.
    Raises ShellParseError for an unterminated quote.
    """
    out: List[str] = []
    i += 1
    while i < len(s):
        ch = s[i]
        if quote == "'" and ch == "'":
            return "".join(out), i + 1
        if quote == '"':
            if ch == '"':
                return "".join(out), i + 1
            if ch == "\\" and i + 1 < len(s) and s[i + 1] in '"\\$`':
                out.append(s[i + 1])
                i += 2
                continue
        out.append(ch)
        i += 1
    raise ShellParseError(f"unterminated {quote} quote")


def _scan_substitution(s: str, i: int) -> Tuple[str, int, str]:
    """Scan a ``$(...)`` region starting at ``s[i] == '$'``.

    Returns ``(inner_text, index_past_close, style)`` where style is
    ``parens`` or ``arith`` (when the construct is ``$((...))``).
    """
    if s.startswith("$((", i):
        depth = 0
        j = i + 3  # past the full "$((" opener; a "(" here nests
        while j < len(s):
            if s[j] == "(":
                depth += 1
            elif s[j] == ")":
                if depth == 0:
                    if s.startswith("))", j):
                        return s[i + 3:j], j + 2, "arith"
                    raise ShellParseError("unbalanced $(( substitution")
                depth -= 1
            j += 1
        raise ShellParseError("unterminated arithmetic substitution")
    depth = 0
    j = i + 2  # past "$("
    while j < len(s):
        if s[j] == "(":
            depth += 1
        elif s[j] == ")":
            if depth == 0:
                return s[i + 2:j], j + 1, "parens"
            depth -= 1
        j += 1
    raise ShellParseError("unterminated command substitution")


def _scan_backtick(s: str, i: int) -> Tuple[str, int]:
    """Scan a backtick substitution starting at ``s[i] == '`'``."""
    j = i + 1
    while j < len(s):
        if s[j] == "`":
            return s[i + 1:j], j + 1
        j += 1
    raise ShellParseError("unterminated backtick substitution")


def _scan_word(s: str, i: int) -> Tuple[str, int, List[Substitution]]:
    """Scan one unquoted word starting at ``s[i]``.

    Returns ``(text, index_past_word, substitutions)``.  Stops at
    whitespace, a newline, or an operator character.  A ``#`` only
    starts a comment at a word boundary, so ``a#b`` stays one word.
    Command substitutions inside the word are extracted and kept raw.
    """
    start = i
    out: List[str] = []
    subs: List[Substitution] = []
    while i < len(s):
        ch = s[i]
        if ch in " \t\n" or _is_operator_start(ch):
            break
        if ch == "#" and i == start:
            break  # a comment marker must start the word
        if ch == "'":
            text, i = _scan_quoted(s, i, "'")
            out.append(text)
            continue
        if ch == '"':
            text, i = _scan_quoted(s, i, '"')
            out.append(text)
            continue
        if ch == "\\" and i + 1 < len(s):
            if s[i + 1] == "\n":  # line continuation
                i += 2
                continue
            out.append(s[i + 1])
            i += 2
            continue
        if ch == "$" and i + 1 < len(s) and s[i + 1] == "(":
            text, i, _style = _scan_substitution(s, i)
            subs.append(Substitution(text))
            out.append("$(" + text + ")")
            continue
        if ch == "`":
            text, i = _scan_backtick(s, i)
            subs.append(Substitution(text))
            out.append("`" + text + "`")
            continue
        out.append(ch)
        i += 1
    return "".join(out), i, subs


def _match_redirect(s: str, i: int) -> Optional[str]:
    """Match a redirect operator at ``i`` if one starts there.

    Covers ``>``, ``>>``, ``<``, ``<<``, ``<<<``, ``>&``, ``<&``, ``&>``,
    ``2>``, ``2>>``, and ``2>&1``.  ``2>`` forms only match at a word
    boundary so ``x2>file`` stays word + plain redirect.
    """
    if s.startswith("2>&1", i) and (i == 0 or s[i - 1] in " \t"):
        return "2>&1"
    if s.startswith("2>>", i) and (i == 0 or s[i - 1] in " \t"):
        return "2>>"
    if s.startswith("2>", i) and (i == 0 or s[i - 1] in " \t"):
        return "2>"
    if s.startswith("<<<", i):
        return "<<<"
    two = s[i:i + 2]
    if two in _REDIRECT_OPS:
        return two
    if two == "&&" or two == "||":
        return None
    if s[i] in "<>":
        return s[i]
    return None


def _read_redirect_target(s: str, i: int, op: str) -> Tuple[Redirect, int,
                                                            List[Substitution]]:
    """Read the target word of redirect ``op`` starting at ``i``."""
    if op == "2>&1":  # the "&1" is part of the operator
        return Redirect(op=op, target=Word("1"), fd=2), i, []
    j = _skip_ws(s, i)
    if j >= len(s) or s[j] in "#\n":
        raise ShellParseError(f"redirect {op} without a target")
    text, j2, subs = _scan_word(s, j)
    if not text and not subs:
        raise ShellParseError(f"redirect {op} without a target")
    fd = 2 if op.startswith("2") else 1
    return (Redirect(op=op, target=Word(text, _word_kind(text)), fd=fd),
            j2, subs)


def _is_assignment_name(name: str) -> bool:
    """Return True when ``name`` is a valid shell variable name."""
    if not name:
        return False
    if not (name[0].isalpha() or name[0] == "_"):
        return False
    return all(c.isalnum() or c == "_" for c in name)


def parse(cmdline: str) -> CommandList:
    """Parse a command line into a CommandList.

    Raises ShellParseError on unbalanced quotes or substitutions.
    """
    s = cmdline
    items: List[Pipeline] = []
    separators: List[str] = []
    pipeline: Optional[Pipeline] = None
    current: Optional[SimpleCommand] = None

    def new_command() -> SimpleCommand:
        nonlocal pipeline, current
        if pipeline is None:
            pipeline = Pipeline()
        if current is None:
            current = SimpleCommand()
        return current

    def flush_command() -> None:
        nonlocal current, pipeline
        if current is not None and (current.words or current.assignments
                                    or current.redirects):
            if pipeline is None:
                pipeline = Pipeline()
            pipeline.commands.append(current)
        current = None

    def flush_pipeline() -> None:
        nonlocal pipeline
        flush_command()
        if pipeline is not None and pipeline.commands:
            items.append(pipeline)
        pipeline = None

    n = len(s)
    i = 0
    while i < n:
        i = _skip_ws(s, i)
        if i >= n:
            break
        ch = s[i]
        if ch == "#":
            break  # comment runs to end of line
        if ch == "\n":
            flush_pipeline()
            separators.append(";")
            i += 1
            continue
        two = s[i:i + 2]
        if two in _SEP_TWO:
            flush_pipeline()
            separators.append(two)
            i += 2
            continue
        if ch == "&" and two == "&>":
            redirect, i2, subs = _read_redirect_target(s, i + 2, "&>")
            new_command().redirects.append(redirect)
            current.substitutions.extend(subs)
            i = i2
            continue
        op = _match_redirect(s, i)
        if op is not None:
            redirect, i2, subs = _read_redirect_target(s, i + len(op), op)
            new_command().redirects.append(redirect)
            current.substitutions.extend(subs)
            i = i2
            continue
        if ch == "|":
            if current is None or not (current.words or current.assignments
                                       or current.redirects):
                raise ShellParseError("pipe without a preceding command")
            flush_command()
            i += 1
            continue
        if ch in (";", "&"):
            flush_pipeline()
            separators.append(ch)
            i += 1
            continue
        if ch == "(":
            depth = 0
            j = i
            while j < n:
                if s[j] == "(":
                    depth += 1
                elif s[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if depth != 0:
                raise ShellParseError("unbalanced parentheses")
            inner = s[i + 1:j]
            cmd = new_command()
            cmd.words.append(Word("(" + inner + ")", "plain"))
            cmd.substitutions.append(Substitution(inner))
            i = j + 1
            continue
        if ch == ")":
            raise ShellParseError("unexpected ')'")

        # Ordinary word (or an assignment prefix).
        cmd = new_command()
        text, i2, subs = _scan_word(s, i)
        if text:
            if ("=" in text and not text.startswith("-")
                    and not cmd.words and not cmd.redirects):
                name, _, value = text.partition("=")
                if _is_assignment_name(name):
                    cmd.assignments.append((name, value))
                    cmd.substitutions.extend(subs)
                    i = i2
                    continue
            cmd.words.append(Word(text, _word_kind(text)))
        cmd.substitutions.extend(subs)
        if i2 == i:  # defensive: never loop in place
            i += 1
        else:
            i = i2

    flush_pipeline()
    trailing = ""
    if len(separators) == len(items) and separators:
        # A separator with no following item is the trailing one.
        trailing = separators.pop()
    while len(separators) > max(len(items) - 1, 0):
        separators.pop()
    return CommandList(items=items, separators=separators, trailing=trailing)
