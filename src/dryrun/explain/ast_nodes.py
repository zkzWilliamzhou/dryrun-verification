"""AST node types for the dryrun shell parser.

The parser covers the POSIX-ish shell subset needed for static analysis:
simple commands with words, flags and environment assignments, pipes,
``&&``/``||``/``;``/``&`` lists, redirects, and command substitution.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple


@dataclass
class Word:
    """One shell word (token) after quote removal."""

    text: str
    kind: str = "plain"
    """One of ``plain``, ``glob`` (contains unquoted ``*``/``?``/``[``),
    ``var`` (contains ``$``), ``tilde`` (starts with ``~``)."""


@dataclass
class Redirect:
    """One redirection attached to a simple command."""

    op: str
    """One of ``>``, ``>>``, ``<``, ``>&``, ``2>``, ``2>>``, ``2>&1``,
    ``&>``, ``<<``, ``<<<``."""

    target: Word
    fd: int = 1


@dataclass
class Substitution:
    """A command substitution ``$(...)`` or ``...`` kept as raw text."""

    text: str


@dataclass
class SimpleCommand:
    """One command with its words, assignments, and redirects."""

    assignments: List[Tuple[str, str]] = field(default_factory=list)
    words: List[Word] = field(default_factory=list)
    redirects: List[Redirect] = field(default_factory=list)
    substitutions: List[Substitution] = field(default_factory=list)


@dataclass
class Pipeline:
    """One pipeline: one or more simple commands joined by ``|``."""

    commands: List[SimpleCommand] = field(default_factory=list)


@dataclass
class CommandList:
    """A whole command line: pipelines joined by separators.

    ``separators[i]`` joins ``items[i]`` and ``items[i + 1]``; ``trailing``
    holds a final separator (``;`` or ``&``) after the last item, which
    carries meaning for the auditor (background jobs).
    """

    items: List[Pipeline] = field(default_factory=list)
    separators: List[str] = field(default_factory=list)
    trailing: str = ""
