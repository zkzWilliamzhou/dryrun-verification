"""Tests for the POSIX-subset shell parser (dryrun/explain/parser.py)."""
from __future__ import annotations

import pytest

from dryrun.explain.ast_nodes import CommandList, Substitution
from dryrun.explain.parser import ShellParseError, parse


def _first(cmdline: str):
    """Parse ``cmdline`` and return its first simple command."""
    cl = parse(cmdline)
    assert cl.items, f"expected at least one pipeline in {cmdline!r}"
    assert cl.items[0].commands, f"expected a command in {cmdline!r}"
    return cl.items[0].commands[0]


def _texts(cmdline: str):
    """Return the word texts of the first simple command."""
    return [w.text for w in _first(cmdline).words]


# ---------------------------------------------------------------------------
# Word splitting and quoting
# ---------------------------------------------------------------------------

def test_simple_command_splits_into_words():
    assert _texts("ls -la /tmp") == ["ls", "-la", "/tmp"]


def test_tabs_also_separate_words():
    assert _texts("ls\t-la\t/tmp") == ["ls", "-la", "/tmp"]


def test_single_quotes_preserve_spaces_literally():
    words = _texts("echo 'hello world'")
    assert words == ["echo", "hello world"]
    # The quoted text is data, not a pattern: plain kind.
    assert _first("echo 'hello world'").words[1].kind == "plain"


def test_double_quotes_keep_dollar_literal():
    # The parser never expands variables: "$VAR" stays the four literal
    # characters (classified as a var word because it contains a $).
    words = _texts('echo "$VAR"')
    assert words == ["echo", "$VAR"]
    assert _first('echo "$VAR"').words[1].kind == "var"


def test_backslash_escapes_dollar():
    # \$ collapses to a literal dollar sign; nothing is expanded.
    assert _texts("echo \\$foo") == ["echo", "$foo"]


def test_backslash_escapes_space():
    # a\ b is a single word containing a space.
    assert _texts("echo a\\ b") == ["echo", "a b"]


def test_line_continuation_joins_words():
    assert _texts("echo a\\\nb") == ["echo", "ab"]


# ---------------------------------------------------------------------------
# Lists and pipelines
# ---------------------------------------------------------------------------

def test_pipe_builds_one_pipeline_with_two_commands():
    cl = parse("cat f | grep x")
    assert len(cl.items) == 1
    assert [c.words[0].text for c in cl.items[0].commands] == ["cat", "grep"]


def test_three_stage_pipeline_stays_one_item():
    cl = parse("cmd1 | cmd2 | cmd3")
    assert len(cl.items) == 1
    assert len(cl.items[0].commands) == 3


def test_and_or_list_separates_commands():
    cl = parse("a && b || c")
    assert len(cl.items) == 3
    assert cl.separators == ["&&", "||"]
    assert cl.trailing == ""


def test_semicolon_separates_commands():
    cl = parse("a; b")
    assert len(cl.items) == 2
    assert cl.separators == [";"]
    assert cl.trailing == ""


def test_trailing_semicolon_is_kept_in_trailing():
    cl = parse("a; b;")
    assert len(cl.items) == 2
    assert cl.separators == [";"]
    assert cl.trailing == ";"


def test_newline_separates_commands():
    cl = parse("ls\necho hi")
    assert len(cl.items) == 2
    assert cl.separators == [";"]
    assert [c.words[0].text for c in cl.items[0].commands] == ["ls"]
    assert [c.words[0].text for c in cl.items[1].commands] == ["echo"]


# ---------------------------------------------------------------------------
# Redirects
# ---------------------------------------------------------------------------

def test_stdout_redirect_overwrite():
    sc = _first("cmd > out")
    assert [(r.op, r.target.text, r.fd) for r in sc.redirects] == [(">", "out", 1)]


def test_stdout_redirect_append():
    sc = _first("cmd >> out")
    assert [(r.op, r.target.text, r.fd) for r in sc.redirects] == [(">>", "out", 1)]


def test_stdin_redirect():
    sc = _first("cmd < in")
    assert [(r.op, r.target.text, r.fd) for r in sc.redirects] == [("<", "in", 1)]


def test_stderr_redirect_has_fd_two():
    sc = _first("cmd 2> err")
    assert [(r.op, r.target.text, r.fd) for r in sc.redirects] == [("2>", "err", 2)]


def test_stderr_redirect_append_has_fd_two():
    sc = _first("cmd 2>> err")
    assert [(r.op, r.target.text, r.fd) for r in sc.redirects] == [("2>>", "err", 2)]


def test_stderr_merged_into_stdout():
    sc = _first("cmd 2>&1")
    assert [(r.op, r.target.text, r.fd) for r in sc.redirects] == [("2>&1", "1", 2)]


def test_both_streams_redirect_operator():
    sc = _first("cmd &> both")
    assert [(r.op, r.target.text) for r in sc.redirects] == [("&>", "both")]


def test_multiple_redirects_keep_order():
    sc = _first("cat < in > out")
    assert [(r.op, r.target.text) for r in sc.redirects] == [("<", "in"), (">", "out")]


def test_fd_redirect_only_matches_at_word_boundary():
    # x2>file is the word "x2" plus a plain ">" redirect, not a 2> redirect.
    sc = _first("echo x2>file")
    assert [w.text for w in sc.words] == ["echo", "x2"]
    assert [(r.op, r.target.text) for r in sc.redirects] == [(">", "file")]


def test_redirect_without_target_raises():
    with pytest.raises(ShellParseError, match="without a target"):
        parse("cmd >")


# ---------------------------------------------------------------------------
# Command substitution
# ---------------------------------------------------------------------------

def test_paren_substitution_is_extracted():
    sc = _first("echo $(date)")
    assert [s.text for s in sc.substitutions] == ["date"]
    # The word keeps the raw $(...) spelling.
    assert sc.words[1].text == "$(date)"


def test_backtick_substitution_is_extracted():
    sc = _first("echo `date`")
    assert [s.text for s in sc.substitutions] == ["date"]


def test_nested_substitution_text_is_preserved():
    sc = _first("echo $(cat $(which gcc))")
    assert [s.text for s in sc.substitutions] == ["cat $(which gcc)"]


def test_arithmetic_substitution_is_extracted():
    # $((...)) is an arithmetic substitution: the inner text is "1+2".
    sc = _first("echo $((1+2))")
    assert [s.text for s in sc.substitutions] == ["1+2"]
    for sub in sc.substitutions:
        assert isinstance(sub, Substitution)
    # The word keeps a $(...) spelling with one paren layer dropped.
    assert sc.words[1].text == "$(1+2)"
    assert sc.words[1].kind == "var"


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------

def test_hash_inside_word_is_not_a_comment():
    # A '#' only starts a comment at a word boundary, so a#b stays one word.
    assert _texts("echo a#b") == ["echo", "a#b"]


def test_comment_at_word_boundary_produces_no_words():
    assert _texts("ls -la # comment") == ["ls", "-la"]


def test_comment_only_line_produces_empty_list():
    assert parse("# just a comment").items == []


def test_comment_runs_to_end_of_line():
    # Everything after the comment marker is dropped, later '#' included.
    assert _texts("echo a # b # c") == ["echo", "a"]


# ---------------------------------------------------------------------------
# Word kinds: glob / var / tilde
# ---------------------------------------------------------------------------

def test_star_word_is_tagged_glob():
    assert _first("ls *.txt").words[1].kind == "glob"


def test_question_mark_word_is_tagged_glob():
    assert _first("rm ?file").words[1].kind == "glob"
    assert _first("ls file?.txt").words[1].kind == "glob"


def test_bracket_word_is_tagged_glob():
    assert _first("ls [a-c].sh").words[1].kind == "glob"


def test_dollar_word_is_tagged_var():
    assert _first("echo $HOME").words[1].kind == "var"


def test_tilde_word_is_tagged_tilde_and_not_expanded():
    word = _first("cd ~/docs").words[1]
    assert word.text == "~/docs"  # tilde expansion is not performed
    assert word.kind == "tilde"


# ---------------------------------------------------------------------------
# Assignment prefixes
# ---------------------------------------------------------------------------

def test_assignment_prefix_is_not_a_word():
    sc = _first("VAR=1 cmd arg")
    assert sc.assignments == [("VAR", "1")]
    assert [w.text for w in sc.words] == ["cmd", "arg"]


def test_multiple_assignment_prefixes_are_collected():
    sc = _first("A=1 B=2 echo hi")
    assert sc.assignments == [("A", "1"), ("B", "2")]
    assert [w.text for w in sc.words] == ["echo", "hi"]


def test_assignment_only_line_keeps_assignment_without_words():
    # An assignment with no command still yields one simple command whose
    # words list is empty and whose assignments carry the pair.
    sc = _first("VAR=1")
    assert sc.assignments == [("VAR", "1")]
    assert sc.words == []


def test_equals_inside_later_word_is_not_an_assignment():
    # Only a leading NAME=value is an assignment.
    sc = _first("echo key=value")
    assert sc.assignments == []
    assert [w.text for w in sc.words] == ["echo", "key=value"]


# ---------------------------------------------------------------------------
# Heredocs and here-strings
# ---------------------------------------------------------------------------

def test_heredoc_redirect_is_parsed():
    sc = _first("cat << EOF")
    assert [(r.op, r.target.text, r.target.kind, r.fd) for r in sc.redirects] == [
        ("<<", "EOF", "plain", 1)]
    assert [w.text for w in sc.words] == ["cat"]


def test_heredoc_delimiter_without_space_is_parsed():
    sc = _first("cat <<EOF")
    assert [(r.op, r.target.text) for r in sc.redirects] == [("<<", "EOF")]


def test_heredoc_body_lines_are_parsed_as_separate_commands():
    # The parser models only the operator and the delimiter; it has no
    # notion of a heredoc body, so following lines parse as ordinary
    # newline-separated commands (current, documented-by-test behavior).
    cl = parse("cat << EOF\nbody line\nEOF")
    assert len(cl.items) == 3
    assert [[w.text for w in c.words] for c in cl.items[0].commands] == [["cat"]]
    assert [[w.text for w in c.words] for c in cl.items[1].commands] == [
        ["body", "line"]]
    assert [[w.text for w in c.words] for c in cl.items[2].commands] == [["EOF"]]
    assert cl.separators == [";", ";"]


def test_herestring_redirect_is_parsed():
    sc = _first("cat <<< hello world")
    # Only the first word after <<< is the operand; the rest stay words.
    assert [(r.op, r.target.text) for r in sc.redirects] == [("<<<", "hello")]
    assert [w.text for w in sc.words] == ["cat", "world"]


# ---------------------------------------------------------------------------
# Trailing separators and multi-command lists
# ---------------------------------------------------------------------------

def test_trailing_ampersand_is_recorded():
    cl = parse("sleep 10 &")
    assert len(cl.items) == 1
    assert cl.trailing == "&"
    assert cl.separators == []


def test_ampersand_between_commands_is_a_separator():
    cl = parse("a & b")
    assert len(cl.items) == 2
    assert cl.separators == ["&"]
    assert cl.trailing == ""


def test_three_commands_separated_by_semicolons():
    cl = parse("cmd1; cmd2; cmd3")
    assert len(cl.items) == 3
    assert cl.separators == [";", ";"]
    assert cl.trailing == ""
    assert [c.words[0].text for c in cl.items[2].commands] == ["cmd3"]


def test_trailing_newline_is_recorded_as_trailing_separator():
    # A final newline flushes the last pipeline; the leftover separator
    # lands in ``trailing`` as ";" rather than staying in ``separators``.
    cl = parse("echo hi\n")
    assert len(cl.items) == 1
    assert cl.separators == []
    assert cl.trailing == ";"


def test_pipe_without_surrounding_spaces():
    cl = parse("cat f|grep x")
    assert len(cl.items) == 1
    assert len(cl.items[0].commands) == 2
    assert [w.text for w in cl.items[0].commands[0].words] == ["cat", "f"]
    assert [w.text for w in cl.items[0].commands[1].words] == ["grep", "x"]


# ---------------------------------------------------------------------------
# Long options, escapes, and unicode
# ---------------------------------------------------------------------------

def test_long_option_with_equals_is_one_word():
    assert _texts("echo --flag=value") == ["echo", "--flag=value"]
    assert _texts("cmd --output=file.txt") == ["cmd", "--output=file.txt"]


def test_escaped_backslash_collapses_to_single_backslash():
    # The command line `echo a\\b` holds two backslashes; \\ escapes to one.
    assert _texts("echo a\\\\b") == ["echo", "a\\b"]
    assert _texts("echo C:\\\\path") == ["echo", "C:\\path"]


def test_unicode_word_is_one_word():
    assert _texts("echo café") == ["echo", "café"]
    assert _texts("echo ▲☃") == ["echo", "▲☃"]


def test_empty_quotes_yield_no_word():
    # Quote removal produces an empty text, and the parser does not emit
    # empty words, so '' contributes no word at all (current behavior).
    assert _texts("echo ''") == ["echo"]
    assert _texts('echo ""') == ["echo"]
    assert _texts("echo '' foo") == ["echo", "foo"]


def test_crlf_line_endings_keep_carriage_return_in_word():
    # \r is not whitespace to this parser: it stays inside the last word
    # of the line, and only the \n separates/terminates the command.
    cl = parse("ls -la\r\n")
    assert [w.text for w in cl.items[0].commands[0].words] == ["ls", "-la\r"]
    assert cl.separators == []
    assert cl.trailing == ";"


# ---------------------------------------------------------------------------
# Empty and malformed input
# ---------------------------------------------------------------------------

def test_empty_input_returns_empty_command_list():
    cl = parse("")
    assert isinstance(cl, CommandList)
    assert cl.items == []
    assert cl.separators == []
    assert cl.trailing == ""


def test_whitespace_only_input_returns_empty_command_list():
    cl = parse("   \t  ")
    assert cl.items == []
    assert cl.separators == []
    assert cl.trailing == ""


def test_newline_only_input_returns_empty_command_list():
    cl = parse("\n\n")
    assert cl.items == []
    assert cl.separators == []
    assert cl.trailing == ""


@pytest.mark.parametrize("cmdline", ['echo "unclosed', "echo 'unclosed"])
def test_unterminated_quote_raises(cmdline):
    with pytest.raises(ShellParseError):
        parse(cmdline)


@pytest.mark.parametrize("cmdline", ["echo $(date", "echo `date"])
def test_unterminated_substitution_raises(cmdline):
    with pytest.raises(ShellParseError):
        parse(cmdline)


def test_unterminated_arithmetic_substitution_raises():
    with pytest.raises(ShellParseError):
        parse("echo $((1+2")


def test_unbalanced_parentheses_raise():
    with pytest.raises(ShellParseError, match="parentheses"):
        parse("echo (foo")


def test_stray_closing_paren_raises():
    with pytest.raises(ShellParseError, match="\\)"):
        parse("echo )")


def test_pipe_without_preceding_command_raises():
    with pytest.raises(ShellParseError, match="pipe"):
        parse("| grep x")


