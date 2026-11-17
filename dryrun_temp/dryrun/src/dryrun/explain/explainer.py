"""Plain-English explanation of parsed shell commands."""
from __future__ import annotations

from typing import List

from dryrun.core.types import Explanation, ExplanationSegment
from dryrun.explain.ast_nodes import CommandList, Pipeline, SimpleCommand
from dryrun.explain.knowledge import lookup
from dryrun.explain.parser import ShellParseError, parse

#: Cap for the composed summary, in characters.
_SUMMARY_CAP = 240

_REDIRECT_TEXT = {
    ">": "writes stdout to {t} (overwrites the file)",
    ">>": "appends stdout to {t}",
    "2>": "writes stderr to {t} (overwrites the file)",
    "2>>": "appends stderr to {t}",
    "2>&1": "merges stderr into stdout",
    "<": "reads stdin from {t}",
    ">&": "redirects stdout to fd {t}",
    "<&": "reads stdin from fd {t}",
    "&>": "writes stdout and stderr to {t} (overwrites)",
    "<<": "reads a heredoc ending at the line {t}",
    "<<<": "passes the string {t} on stdin",
}

_SEPARATOR_TEXT = {
    "&&": "runs the next command only if this one succeeded",
    "||": "runs the next command only if this one failed",
    ";": "then runs the next command",
    "&": "runs the previous command in the background",
}


def _command_name(sc: SimpleCommand) -> str:
    """Return the first non-flag word of a simple command."""
    for word in sc.words:
        if not word.text.startswith("-") and word.text != "":
            return word.text
    return ""


def _flag_key(text: str) -> str:
    """Normalize a flag token for knowledge lookup."""
    if text.startswith("--"):
        return text
    stripped = text.lstrip("-")
    if not stripped:
        return text
    if len(stripped) == 1:
        return "-" + stripped
    return text  # keep combined tokens like -rf for exact lookup first


def explain_simple(
    sc: SimpleCommand, out: List[ExplanationSegment]
) -> None:
    """Append segments describing one simple command."""
    name = _command_name(sc)
    if not name:
        if sc.redirects:
            out.append(ExplanationSegment(
                kind="note",
                text="a redirection with no command (creates or truncates "
                     "the target file)"))
        for assignment in sc.assignments:
            out.append(ExplanationSegment(
                kind="env",
                text=f"sets {assignment[0]}={assignment[1]} (no command runs)"))
        return
    info = lookup(name)
    if info is None:
        out.append(ExplanationSegment(
            kind="command", text=f"{name}: not in the offline knowledge base"))
        out.append(ExplanationSegment(
            kind="note",
            text=f"no offline description for '{name}'; its behavior is not "
                 f"explained here"))
    else:
        out.append(ExplanationSegment(
            kind="command", text=f"{name}: {info.summary}"))
        if info.danger:
            out.append(ExplanationSegment(
                kind="note", text=f"warning: {info.danger}"))
    # Arguments, flags, and everything else in order.
    consumed_first = False
    for word in sc.words:
        if not consumed_first:
            consumed_first = True  # the command name itself was handled
            continue
        text = word.text
        if text.startswith("-") and len(text) > 1:
            _explain_flag(name, text, out)
        else:
            note = ""
            if word.kind == "glob":
                note = " (may expand to multiple files)"
            elif word.kind == "var":
                note = " (value depends on a shell variable)"
            elif word.kind == "tilde":
                note = " (relative to your home directory)"
            out.append(ExplanationSegment(
                kind="arg", text=f"argument: {text}{note}"))
    for assignment in sc.assignments:
        out.append(ExplanationSegment(
            kind="env",
            text=f"sets {assignment[0]}={assignment[1]} for this command"))
    for redirect in sc.redirects:
        template = _REDIRECT_TEXT.get(redirect.op)
        if template is None:
            template = f"redirects fd {redirect.fd} with {redirect.op} to {{t}}"
        out.append(ExplanationSegment(
            kind="redirect",
            text=template.format(t=redirect.target.text)))
    for sub in sc.substitutions:
        out.append(ExplanationSegment(
            kind="substitution",
            text=f"command substitution: runs '{sub.text}' first and inserts "
                 f"its output here"))


def _explain_flag(
    name: str, text: str, out: List[ExplanationSegment]
) -> None:
    """Explain a flag using the knowledge base, then letter fallbacks."""
    info = lookup(name)
    flags = info.flags if info else {}
    key = _flag_key(text)
    if key in flags:
        out.append(ExplanationSegment(
            kind="flag", text=f"{text}: {flags[key]}"))
        return
    # Combined short flags such as -rf: try the whole token, then letters.
    if not text.startswith("--"):
        letters = text.lstrip("-")
        if len(letters) > 1:
            parts: List[str] = []
            for ch in letters:
                meaning = flags.get("-" + ch)
                if meaning:
                    parts.append(f"-{ch} {meaning}")
            if parts:
                out.append(ExplanationSegment(
                    kind="flag", text=f"{text}: " + "; ".join(parts)))
                return
    out.append(ExplanationSegment(
        kind="flag", text=f"{text}: unrecognized flag"))


def _summarize(cl: CommandList) -> str:
    """Compose a one or two sentence summary of the whole line."""
    parts: List[str] = []
    for pipeline in cl.items:
        names: List[str] = []
        key_flags: List[str] = []
        for sc in pipeline.commands:
            name = _command_name(sc)
            if not name:
                continue
            names.append(name)
            info = lookup(name)
            if info is None:
                continue
            for word in sc.words[1:]:
                text = word.text
                if text in ("-r", "-R", "-rf", "-fr", "--force", "-f", "-i"):
                    meaning = info.flags.get(text)
                    if meaning:
                        key_flags.append(f"{name} {text} {meaning}")
        if not names:
            continue
        if len(names) == 1:
            info = lookup(names[0])
            summary = info.summary if info else names[0]
            parts.append(summary)
        else:
            parts.append("pipes " + " into ".join(names))
        parts.extend(key_flags[:2])
    if not parts:
        return "no command to run"
    text = ". ".join(parts[:3])
    if len(text) > _SUMMARY_CAP:
        text = text[:_SUMMARY_CAP - 3].rstrip() + "..."
    return text


def explain(command: str) -> Explanation:
    """Explain a shell command in plain English; never raises."""
    try:
        cl = parse(command)
    except ShellParseError as exc:
        return Explanation(
            command=command,
            summary="could not fully parse this command",
            segments=[
                ExplanationSegment(
                    kind="note",
                    text=f"the parser gave up: {exc}; only the audit layer "
                         f"with raw pattern checks will run"),
            ],
        )
    segments: List[ExplanationSegment] = []
    for pipeline in cl.items:
        if len(pipeline.commands) > 1:
            names = [_command_name(sc) or "?" for sc in pipeline.commands]
            segments.append(ExplanationSegment(
                kind="note",
                text="pipes the output of " + " into ".join(names)))
        for sc in pipeline.commands:
            explain_simple(sc, segments)
    for sep in cl.separators:
        text = _SEPARATOR_TEXT.get(sep, f"then ({sep})")
        segments.append(ExplanationSegment(kind="operator", text=text))
    if cl.trailing == "&":
        segments.append(ExplanationSegment(
            kind="operator", text="runs the previous command in the background"))
    return Explanation(
        command=command, summary=_summarize(cl), segments=segments)
