"""Danger rules for the dryrun auditor.

Every rule is a small declarative object: an id, a severity, a title, a
plain-English detail, and a match function over *normalized* commands.
Normalization strips a leading ``sudo``/``su``/``doas``/``pkexec`` so a
rule written for ``rm`` also fires for ``sudo rm`` - the case where it
matters most.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Set

from dryrun.core.types import Finding
from dryrun.explain.ast_nodes import CommandList, Pipeline, SimpleCommand

#: A rule fires on normalized commands; the payload is the index of the
#: triggering simple command within the whole line.

_ELEVATION = {"sudo", "su", "doas", "pkexec"}
_SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "fish"}
_INTERPRETERS = _SHELLS | {"python", "python3", "perl", "ruby", "node"}
_DOWNLOADERS = {"curl", "wget"}
_PROTECTED_FILES = ("/etc/passwd", "/etc/shadow", "/etc/sudoers",
                    "/etc/fstab")
_SSH_FILES = (".ssh/authorized_keys", ".ssh/config", ".ssh/known_hosts")
_SYSTEM_TREE_PREFIXES = ("/etc", "/usr", "/var", "/boot", "/bin", "/sbin",
                         "/lib", "/lib64", "/opt", "/root", "/dev")


@dataclass
class NormCmd:
    """A simple command with elevation and words normalized for rules."""

    index: int
    name: str
    """The effective command name (after sudo/su)."""

    words: List[str]
    """Words after the effective name, flags included."""

    redirects: List[tuple]
    """(op, target) pairs."""

    assignments: List[tuple]
    """(name, value) pairs."""

    substitutions: List[str]
    """Raw substitution texts."""

    elevated: bool
    """True when the command runs under sudo/su/doas/pkexec."""

    pid: int = 0
    """Pipeline id: commands sharing a pipe share this id."""

    pipeline: List[str] = field(default_factory=list)
    """Effective names of every command in the same pipeline, in order."""

    @property
    def args(self) -> List[str]:
        """Non-flag operands after the command name."""
        return [w for w in self.words if not w.startswith("-")]

    @property
    def flags(self) -> List[str]:
        """Flag tokens after the command name (dash-prefixed)."""
        return [w for w in self.words if w.startswith("-") and w != "-"]

    def has_flag(self, *flags: str) -> bool:
        """True when any exact flag (or combined short cluster) appears.

        A short cluster such as ``-rfv`` satisfies every wanted flag
        whose letters it contains (``rm -rfv`` recurses, forces, and is
        verbose).  Clusters longer than four letters, such as tar's
        ``-delete``, stay inert so they never satisfy ``-d``.
        """
        wanted = set(flags)
        for token in self.flags:
            if token in wanted:
                return True
            if not token.startswith("--"):
                stripped = token.lstrip("-")
                if len(stripped) > 4:
                    continue
                for f in wanted:
                    f_letters = f.lstrip("-")
                    if (f_letters
                            and set(f_letters) <= set(stripped)):
                        return True
        return False

    def has_path(self, predicate) -> bool:
        """True when any operand satisfies ``predicate``."""
        return any(predicate(a) for a in self.args)

    def redirect_writes(self) -> List[str]:
        """Targets of redirects that write files."""
        return [t for op, t in self.redirects
                if op in (">", ">>", "2>", "2>>", "&>")]

    def text_contains(self, *needles: str) -> bool:
        """True when any word or substitution contains a needle."""
        haystacks = self.words + [self.name] + self.substitutions
        return any(n in h for h in haystacks for n in needles)


@dataclass
class Rule:
    """One audit rule."""

    rule_id: str
    severity: str
    title: str
    detail: str
    match: object  # Callable[[List[NormCmd]], List[int]]


# --------------------------------------------------------------------------
# Path helpers
# --------------------------------------------------------------------------

_DEVICE_RE = re.compile(
    r"^/dev/(?:sd[a-z]+\d*|nvme\d+n\d+(?:p\d+)?|hd[a-z]+\d*|vd[a-z]+\d*"
    r"|mmcblk\d+(?:p\d+)?)(?:/.*)?$")


def looks_like_device(text: str) -> bool:
    """Return True when a path refers to a raw block device."""
    return bool(_DEVICE_RE.match(text))


def is_root_level(text: str) -> bool:
    """True for system-level paths (/ itself, /etc, /usr, ~, $HOME...)."""
    if text in ("/", "/*", "~", "$HOME", "~/*", "~/"):
        return True
    for prefix in _SYSTEM_TREE_PREFIXES:
        if text == prefix or text.startswith(prefix + "/"):
            return True
    return False


def is_system_subtree(text: str) -> bool:
    """True under /etc, /boot, /usr, /var/lib (config territory)."""
    for prefix in ("/etc", "/boot", "/usr", "/var/lib"):
        if text == prefix or text.startswith(prefix + "/"):
            return True
    return False


# --------------------------------------------------------------------------
# Normalization
# --------------------------------------------------------------------------

def normalize(cl: CommandList) -> List[NormCmd]:
    """Convert a parsed CommandList into rule-friendly NormCmds."""
    result: List[NormCmd] = []
    index = 0
    for pid, pipeline in enumerate(cl.items):
        pipeline_names: List[str] = []
        made: List[NormCmd] = []
        for sc in pipeline.commands:
            words = [w.text for w in sc.words]
            elevated = bool(words) and words[0] in _ELEVATION and len(
                words) > 1
            if elevated:
                name = words[1]
                rest = words[2:]
            else:
                name = words[0] if words else ""
                rest = words[1:]
            pipeline_names.append(name)
            nc = NormCmd(
                index=index,
                name=name,
                words=rest,
                redirects=[(r.op, r.target.text) for r in sc.redirects],
                assignments=list(sc.assignments),
                substitutions=[s.text for s in sc.substitutions],
                elevated=elevated,
                pid=pid,
            )
            result.append(nc)
            made.append(nc)
            index += 1
        for nc in made:
            nc.pipeline = list(pipeline_names)
    return result


def next_in_pipeline(cmds: List[NormCmd], c: NormCmd) -> Optional[NormCmd]:
    """Return the command that follows ``c`` in the same pipeline."""
    later = [x for x in cmds if x.index > c.index and x.pid == c.pid]
    return later[0] if later else None


# --------------------------------------------------------------------------
# CRITICAL rules
# --------------------------------------------------------------------------

def _rm_root(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name == "rm" and (
        c.has_flag("-r", "-R")
        and c.has_path(is_root_level))]


def _dd_disk(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name == "dd" and any(
        looks_like_device(w.split("=", 1)[-1])
        for w in c.words if w.startswith("of="))]


def _mkfs(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds
            if c.name.startswith("mkfs") or c.name == "mke2fs"]


def _fork_bomb(cmds: List[NormCmd]) -> List[int]:
    blob = " ".join(
        w for c in cmds for w in [c.name] + c.words + c.substitutions)
    compressed = blob.replace(" ", "").replace("\n", "")
    if ":(){:|:&};:" in compressed:
        return [0]
    if re.search(r":\s*\(\)\s*\{[^}]*\|[^}]*&[^}]*\}\s*;", blob):
        return [0]
    return []


def _chmod_777_root(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name == "chmod"
            and c.has_flag("-R")
            and any("777" in w for w in c.words)
            and c.has_path(is_root_level)]


def _overwrite_passwd(cmds: List[NormCmd]) -> List[int]:
    hits = []
    for c in cmds:
        targets = list(c.redirect_writes())
        if ((c.name == "tee" or c.name == "cp" or c.name == "mv")
                and c.args):
            targets.append(c.args[-1])
        if c.name == "sed" and c.has_flag("-i") and c.args:
            targets.append(c.args[-1])
        for t in targets:
            if any(t == p or t.startswith(p) for p in _PROTECTED_FILES):
                hits.append(c.index)
                break
    return hits


def _dev_disk_write(cmds: List[NormCmd]) -> List[int]:
    hits = []
    for c in cmds:
        targets = list(c.redirect_writes())
        if c.name in ("shred", "wipefs", "truncate"):
            targets += c.args
        if c.name == "dd":
            targets += [w.split("=", 1)[-1] for w in c.words
                        if w.startswith("of=")]
        for t in targets:
            if looks_like_device(t):
                hits.append(c.index)
                break
    return hits


def _kill_init(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds
            if c.name in ("kill", "killall", "pkill") and c.has_flag("-9")
            # "-1" reads as a flag by shape but means "every process";
            # scan the raw words so `kill -9 -1` is still caught.
            and any(w in ("-1", "1") for w in c.words)]


# --------------------------------------------------------------------------
# HIGH rules
# --------------------------------------------------------------------------

def _pipe_shell(cmds: List[NormCmd]) -> List[int]:
    hits = []
    for c in cmds:
        if c.name in _DOWNLOADERS:
            nxt = next_in_pipeline(cmds, c)
            if nxt is not None and nxt.name in _INTERPRETERS:
                hits.append(c.index)
    return hits


def _base64_shell(cmds: List[NormCmd]) -> List[int]:
    hits = []
    for c in cmds:
        if c.name == "base64" and c.has_flag("-d", "--decode"):
            nxt = next_in_pipeline(cmds, c)
            if nxt is not None and nxt.name in _INTERPRETERS:
                hits.append(c.index)
    return hits


def _eval_network(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name == "eval"
            and c.text_contains("curl", "wget")]


def _sudo_destructive(cmds: List[NormCmd], target_names: Set[str]) -> List[int]:
    return [c.index for c in cmds
            if c.elevated and c.name in target_names]


def _docker_prune(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name == "docker"
            and "prune" in c.args
            and (c.has_flag("-a", "--all", "-f", "--force"))]


def _shutdown_family(cmds: List[NormCmd]) -> List[int]:
    hits = [c.index for c in cmds
            if c.name in ("shutdown", "reboot", "halt", "poweroff")]
    hits += [c.index for c in cmds
             if c.name == "init" and any(a in ("0", "6") for a in c.args)]
    return hits


def _crontab_remove(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds
            if c.name == "crontab" and c.has_flag("-r")]


def _rm_home(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name == "rm"
            and c.has_flag("-r", "-R", "-rf", "-fr")
            and any(a in ("~", "$HOME", "~/") for a in c.args)]


def _tar_abs(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name == "tar"
            and c.has_flag("-P", "--absolute-names", "--absolute")]


def _find_delete_root(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name == "find" and (
        c.has_flag("-delete")
        or ("-exec" in c.words and any(
            w.startswith("rm") for w in c.words))
    ) and any(is_root_level(a) or a == "/" for a in c.args)]


def _overwrite_ssh(cmds: List[NormCmd]) -> List[int]:
    hits = []
    for c in cmds:
        targets = list(c.redirect_writes())
        if c.name == "tee":
            targets += c.args
        if c.name == "sed" and c.has_flag("-i"):
            targets += c.args
        for t in targets:
            if any(ssh in t for ssh in _SSH_FILES):
                hits.append(c.index)
                break
    return hits


def _download_exec(cmds: List[NormCmd]) -> List[int]:
    """Download a file, chmod +x it, and run it, all in one line."""
    downloaded: Set[str] = set()
    for c in cmds:
        if c.name in _DOWNLOADERS:
            words = c.words
            for i, w in enumerate(words):
                if w in ("-o", "--output") and i + 1 < len(words):
                    downloaded.add(words[i + 1])
                elif w.startswith("-o") and len(w) > 2 and "=" not in w:
                    downloaded.add(w[2:])
                elif w.startswith("--output="):
                    downloaded.add(w.split("=", 1)[1])
    if not downloaded:
        return []
    made_exec = any(
        c.name == "chmod"
        and any(w.lstrip("-").startswith("+x") for w in c.words)
        for c in cmds)
    ran = any(c.name not in _DOWNLOADERS | {"chmod", "echo", "printf", "tee"}
              and any(a in downloaded for a in c.args)
              for c in cmds)
    return [0] if made_exec and ran else []


def _pipe_sudo_tee(cmds: List[NormCmd]) -> List[int]:
    hits = []
    for i, c in enumerate(cmds):
        nxt = [x for x in cmds
               if x.index > c.index and x.pipeline == c.pipeline]
        if (nxt and nxt[0].name == "tee" and nxt[0].elevated):
            hits.append(c.index)
    return hits


# --------------------------------------------------------------------------
# MEDIUM rules
# --------------------------------------------------------------------------

def _sudo_any(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.elevated]


def _rm_multi(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name == "rm"
            and len(c.args) >= 3 and not c.has_flag("-i", "-I")]


def _git_rule(cmds: List[NormCmd], sub: str, flags: Set[str]) -> List[int]:
    return [c.index for c in cmds if c.name == "git" and sub in c.args
            and c.has_flag(*flags)]


def _chmod_recursive(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds
            if c.name == "chmod" and c.has_flag("-R")]


def _chown_recursive(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds
            if c.name in ("chown", "chgrp") and c.has_flag("-R")]


def _find_delete(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name == "find"
            and c.has_flag("-delete")]


def _find_exec_rm(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name == "find" and "-exec" in
            c.words and any(w.startswith("rm") for w in c.words)]


def _sed_inplace(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds
            if c.name == "sed" and c.has_flag("-i")]


def _sed_system(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name == "sed" and c.has_flag("-i")
            and any(is_system_subtree(a) for a in c.args)]


def _path_overwrite(cmds: List[NormCmd]) -> List[int]:
    hits = []
    for c in cmds:
        for name, value in c.assignments:
            if name == "PATH" and not value.startswith(("$", "~", '"')):
                hits.append(c.index)
    return hits


def _source_tmp(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name in ("source", ".") and any(
        a.startswith(("/tmp/", "/var/tmp/")) for a in c.args)]


def _eval_any(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name == "eval"]


def _nc_listen(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds
            if c.name in ("nc", "netcat") and c.has_flag("-l")]


def _kill_by_name(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name in ("pkill", "killall")]


def _pip_sudo(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.elevated
            and (c.name in ("pip", "pip3"))]


def _substitution_network(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if any(
        kw in s for s in c.substitutions for kw in ("curl", "wget", "ssh "))]


def _env_ld(cmds: List[NormCmd]) -> List[int]:
    hits = []
    for c in cmds:
        for name, _value in c.assignments:
            if name in ("LD_PRELOAD", "LD_LIBRARY_PATH"):
                hits.append(c.index)
        if c.name in ("export", "env"):
            for a in c.words:
                if a.startswith(("LD_PRELOAD", "LD_LIBRARY_PATH")):
                    hits.append(c.index)
                    break
    return hits


def _redirect_system(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds
            if any(is_system_subtree(t) for t in c.redirect_writes())]


# --------------------------------------------------------------------------
# LOW rules
# --------------------------------------------------------------------------

def _rm_single(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name == "rm"]


def _mv_absolute(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name == "mv" and c.args
            and c.args[-1].startswith("/")]


def _redirect_project(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds
            if any(op == ">" and not t.startswith("/")
                   for op, t in c.redirects)]


def _make_install(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name == "make"
            and "install" in c.args]


def _npm_global(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name == "npm"
            and c.has_flag("-g", "--global")]


def _chmod_plusx_glob(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name == "chmod"
            and any(w.lstrip("-").startswith("+x") for w in c.words)
            and any("*" in a for a in c.args)]


def _xargs_rm(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name == "xargs"
            and any(w.startswith("rm") for w in c.words)]


def _umask_000(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name == "umask" and any(
        a.startswith("00") for a in c.args)]


def _apt_purge(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name in ("apt", "apt-get") and (
        "purge" in c.args
        or ("remove" in c.args and c.has_flag("--purge")))]


# --------------------------------------------------------------------------
# INFO rules
# --------------------------------------------------------------------------

def _unknown_command(cmds: List[NormCmd]) -> List[int]:
    from dryrun.explain.knowledge import COMMANDS
    return [c.index for c in cmds
            if c.name and c.name not in COMMANDS and "/" not in c.name
            and not c.name.startswith(("$", "("))]


def _network_effects(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name in (
        _DOWNLOADERS | {"ssh", "scp", "rsync", "nc", "ping", "netcat",
                        "sftp"})]


def _env_change(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds
            if c.name in ("export", "unset", "set", "alias", "unalias")]


def _substitution_used(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.substitutions]


def _heredoc(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds
            if any(op in ("<<", "<<<") for op, _t in c.redirects)]


def _cd_out(cmds: List[NormCmd]) -> List[int]:
    return [c.index for c in cmds if c.name == "cd" and c.args
            and c.args[0].startswith(("/", "~"))]


#: Rules that depend on the trailing separator live outside RULES because
#: they need the raw CommandList; the auditor applies them directly.
BACKGROUND_REDIRECT = Rule(
    "BACKGROUND_REDIRECT", "LOW", "background job with redirection",
    "the command runs detached with & while writing files; failures go "
    "unnoticed.", None)

BACKGROUND_JOB = Rule(
    "BACKGROUND_JOB", "INFO", "background job",
    "the line ends with &; the command keeps running after the shell "
    "returns.", None)


# --------------------------------------------------------------------------
# The rule table
# --------------------------------------------------------------------------

RULES: List[Rule] = [
    # ----- CRITICAL -----------------------------------------------------
    Rule("RM_ROOT_RECURSIVE", "CRITICAL",
         "recursive delete of a system path",
         "rm with recursive flags targets a system-level path such as /, "
         "/etc, or /usr; running it can erase the operating system or "
         "every user's data.", _rm_root),
    Rule("DD_TO_DISK", "CRITICAL", "raw write to a disk device",
         "dd writes raw bytes with of= pointing at a whole disk; every "
         "filesystem on that disk is destroyed.", _dd_disk),
    Rule("MKFS_ANY", "CRITICAL", "filesystem creation on a device",
         "mkfs lays down a new empty filesystem; whatever was on the "
         "target device is gone.", _mkfs),
    Rule("FORK_BOMB", "CRITICAL", "fork bomb",
         "this line re-spawns itself forever; it exhausts process limits "
         "and freezes the machine.", _fork_bomb),
    Rule("CHMOD_777_ROOT", "CRITICAL",
         "recursive world-writable on a system path",
         "chmod -R 777 on a system path makes every file writable by "
         "every user; any local process can then replace system files.",
         _chmod_777_root),
    Rule("OVERWRITE_PASSWD", "CRITICAL",
         "overwrite of account database files",
         "a write (redirect, tee, cp, mv, or sed -i) targets /etc/passwd, "
         "/etc/shadow, /etc/sudoers, or /etc/fstab; this can lock you out "
         "or grant blanket access.", _overwrite_passwd),
    Rule("DEV_DISK_REDIRECT", "CRITICAL", "write to a raw disk device",
         "a redirect or a tool such as shred, wipefs, truncate, or dd "
         "targets a /dev/sdX-style device node; the raw disk gets "
         "overwritten.", _dev_disk_write),
    Rule("KILL_INIT", "CRITICAL", "SIGKILL of init or every process",
         "kill -9 aimed at PID 1 or -1 takes down init or every process "
         "you own; the machine locks up.", _kill_init),

    # ----- HIGH ---------------------------------------------------------
    Rule("CURL_PIPE_SHELL", "HIGH", "downloaded bytes piped into a shell",
         "curl or wget feeds whatever the server sends straight into a "
         "shell or interpreter; the bytes execute without inspection.",
         _pipe_shell),
    Rule("BASE64_PIPE_SHELL", "HIGH",
         "base64-decoded bytes piped into a shell",
         "base64 -d hides the real payload; the decoded bytes run in a "
         "shell without ever being shown.", _base64_shell),
    Rule("EVAL_NETWORK", "HIGH", "eval of network-fetched text",
         "eval assembles and executes text that includes curl or wget; "
         "remote content becomes running code.", _eval_network),
    Rule("SUDO_RM", "HIGH", "elevated delete",
         "rm runs under sudo with root privileges; a wrong path deletes "
         "system files that no backup covers.",
         lambda cmds: _sudo_destructive(cmds, {"rm"})),
    Rule("SUDO_CHMOD", "HIGH", "elevated permission change",
         "chmod, chown, or chgrp under sudo applies root privileges to "
         "file metadata across the targets; wrong targets can expose or "
         "break system files.",
         lambda cmds: _sudo_destructive(cmds, {"chmod", "chown", "chgrp"})),
    Rule("DOCKER_PRUNE_ALL", "HIGH", "docker prune with force or all",
         "docker prune with -a or -f deletes images, containers, or "
         "volumes without confirmation; volumes can hold database data.",
         _docker_prune),
    Rule("SHUTDOWN_FAMILY", "HIGH", "machine shutdown or reboot",
         "this takes the machine down for every user and every running "
         "job immediately.", _shutdown_family),
    Rule("CRONTAB_REMOVE", "HIGH", "cron schedule deleted",
         "crontab -r deletes the entire schedule with no confirmation "
         "and no undo.", _crontab_remove),
    Rule("RM_HOME_RECURSIVE", "HIGH",
         "recursive delete of the home directory",
         "rm -rf aimed at ~ or $HOME deletes every file you own.",
         _rm_home),
    Rule("TAR_ABS_EXTRACT", "HIGH", "archive extracted with absolute paths",
         "tar with -P or --absolute-names lets archive entries escape "
         "the current directory and overwrite files anywhere on the "
         "system.", _tar_abs),
    Rule("FIND_DELETE_ROOT", "HIGH",
         "find over system paths with -delete or -exec rm",
         "find starts at a system path and deletes or rm-executes every "
         "match; one unexpected match damages the system.",
         _find_delete_root),
    Rule("OVERWRITE_SSH", "HIGH", "overwrite of ssh configuration",
         "a write targets authorized_keys, ssh config, or known_hosts; "
         "this changes who can log in and from where.", _overwrite_ssh),
    Rule("SCRIPT_DOWNLOAD_EXEC", "HIGH",
         "downloaded script made executable and run",
         "the line downloads a file, marks it executable, and runs it; "
         "the payload never passes through a review.",
         _download_exec),
    Rule("PIPE_TO_SUDO_TEE", "HIGH", "pipe into sudo tee",
         "piping into sudo tee writes the piped text into a root-owned "
         "file; combined with downloads this is remote code execution.",
         _pipe_sudo_tee),

    # ----- MEDIUM -------------------------------------------------------
    Rule("SUDO_ANY", "MEDIUM", "command runs with elevated privileges",
         "sudo runs the rest of the line as root; every effect applies "
         "system-wide and cannot be simulated safely.", _sudo_any),
    Rule("RM_MULTI_NO_CONFIRM", "MEDIUM",
         "many deletions without confirmation",
         "rm receives three or more operands and no -i or -I; one wrong "
         "glob deletes far more than intended.", _rm_multi),
    Rule("GIT_PUSH_FORCE", "MEDIUM", "force push rewrites remote history",
         "push --force replaces remote history; other clones diverge and "
         "lost commits can be unrecoverable.",
         lambda cmds: _git_rule(cmds, "push", {"-f", "--force"})),
    Rule("GIT_RESET_HARD", "MEDIUM", "hard reset discards work",
         "reset --hard throws away uncommitted changes in tracked "
         "files.",
         lambda cmds: _git_rule(cmds, "reset", {"--hard"})),
    Rule("GIT_CLEAN_AGGRESSIVE", "MEDIUM", "clean deletes untracked files",
         "git clean -f removes untracked files; with -x it also removes "
         "ignored files such as local config.",
         lambda cmds: _git_rule(cmds, "clean", {"-f", "-fd", "-fdx"})),
    Rule("CHMOD_RECURSIVE", "MEDIUM", "recursive permission change",
         "chmod -R walks whole trees; the mode change hits every file "
         "including ones you did not mean to touch.", _chmod_recursive),
    Rule("CHOWN_RECURSIVE", "MEDIUM", "recursive ownership change",
         "chown or chgrp -R rewrites ownership across a tree; it needs "
         "root and is easy to point at the wrong base.", _chown_recursive),
    Rule("FIND_DELETE", "MEDIUM", "find with -delete",
         "find -delete removes every match directly, with no prompt and "
         "no trash.", _find_delete),
    Rule("FIND_EXEC_RM", "MEDIUM", "find with -exec rm",
         "find -exec rm runs a delete per match; a broad pattern sweeps "
         "widely.", _find_exec_rm),
    Rule("SED_INPLACE", "MEDIUM", "sed edits files in place",
         "sed -i rewrites the file itself; a wrong pattern mangles "
         "content with no backup.", _sed_inplace),
    Rule("SED_SYSTEM_FILE", "MEDIUM", "in-place edit of a system file",
         "sed -i on files under /etc, /boot, or /usr changes system "
         "configuration directly.", _sed_system),
    Rule("EXPORT_PATH_OVERWRITE", "MEDIUM", "PATH replaced",
         "assigning PATH from scratch drops system directories; "
         "subsequent commands resolve to the wrong binaries.",
         _path_overwrite),
    Rule("SOURCE_TMP", "MEDIUM", "script sourced from /tmp",
         "source or . runs a script from world-writable /tmp inside "
         "your shell; another user can swap the contents.",
         _source_tmp),
    Rule("EVAL_ANY", "MEDIUM", "eval executes assembled text",
         "eval executes its arguments as a command; quoting mistakes "
         "turn into arbitrary code execution.", _eval_any),
    Rule("NC_LISTEN", "MEDIUM", "network listener opened",
         "nc -l waits for an incoming connection; whatever bytes arrive "
         "are handed to the command on the other side.", _nc_listen),
    Rule("KILL_BY_NAME", "MEDIUM", "processes killed by name pattern",
         "pkill and killall match names, not process identity; a broad "
         "pattern stops unrelated processes.", _kill_by_name),
    Rule("PIP_SUDO", "MEDIUM", "pip install with sudo",
         "sudo pip runs package setup code as root; install scripts can "
         "write any file on the system.", _pip_sudo),
    Rule("COMMAND_SUBSTITUTION_NETWORK", "MEDIUM",
         "command substitution includes network commands",
         "the substituted text contains curl, wget, or ssh; the command "
         "that runs depends on remote state.", _substitution_network),
    Rule("ENV_LD_PRELOAD", "MEDIUM", "dynamic loader variables set",
         "LD_PRELOAD or LD_LIBRARY_PATH point the loader at replacement "
         "libraries; every child process loads that code.", _env_ld),
    Rule("REDIRECT_SYSTEM_FILE", "MEDIUM", "redirect targets a system file",
         "a write redirect points under /etc, /usr, /boot, or /var/lib; "
         "system configuration gets overwritten.", _redirect_system),

    # ----- LOW ----------------------------------------------------------
    Rule("RM_SINGLE", "LOW", "file deletion",
         "rm removes files permanently; there is no trash can.",
         _rm_single),
    Rule("MV_OVERWRITE", "LOW", "move onto an absolute path",
         "mv targets an absolute path outside the current directory; a "
         "collision silently replaces the destination.", _mv_absolute),
    Rule("REDIRECT_OVERWRITE_PROJECT", "LOW", "project file truncated",
         "> truncates a file in the current directory before writing.",
         _redirect_project),
    Rule("MAKE_INSTALL", "LOW", "make install writes outside the project",
         "the install target copies built files into system locations.",
         _make_install),
    Rule("NPM_GLOBAL", "LOW", "global npm install",
         "npm -g installs into a shared prefix and runs install scripts "
         "from the registry.", _npm_global),
    Rule("CHMOD_PLUSX_GLOB", "LOW", "chmod +x applied to a glob",
         "marking every file matched by a pattern executable can turn "
         "data files into programs.", _chmod_plusx_glob),
    Rule("XARGS_RM", "LOW", "xargs feeds rm",
         "xargs passes unchecked input straight to rm; spaces and "
         "newlines split arguments.", _xargs_rm),
    Rule("UMASK_000", "LOW", "permissive umask",
         "umask 000 makes every new file world-readable and writable.",
         _umask_000),
    Rule("APT_PURGE", "LOW", "package purge removes configuration",
         "purge deletes the package plus its system-wide configuration "
         "files.", _apt_purge),

    # ----- INFO ---------------------------------------------------------
    Rule("UNKNOWN_COMMAND", "INFO",
         "command not in the offline knowledge base",
         "dryrun has no offline entry for this command; its explanation "
         "is incomplete and its audit is weaker.", _unknown_command),
    Rule("NETWORK_SIDE_EFFECTS", "INFO",
         "network effects cannot be previewed",
         "this command talks to the network; requests it sends cannot "
         "be unsent, so no simulation can honestly preview them.",
         _network_effects),
    Rule("ENV_CHANGE", "INFO", "shell environment changes",
         "export, set, unset, or alias change the environment of the "
         "current shell and every child process.", _env_change),
    Rule("SUBSTITUTION_USED", "INFO", "command substitution in use",
         "command substitution runs inner commands first; the real "
         "behavior depends on their output.", _substitution_used),
    Rule("HEREDOC_USED", "INFO", "heredoc input",
         "a heredoc feeds literal text to the command on stdin.",
         _heredoc),
    Rule("CD_OUT", "INFO", "directory change to an absolute path",
         "cd moves to a path outside the current directory.", _cd_out),
]


def raw_fork_bomb(command: str) -> Optional[Finding]:
    """Detect a fork bomb in raw text before parsing.

    Shell function definitions (``:(){ :|:& };:``) are outside the
    parser's POSIX subset, so this scan runs on the command string as
    the user typed it. Returns a CRITICAL finding or ``None``.
    """
    if (
        ":(){:|:&};:" in command.replace(" ", "")
        or re.search(r":\s*\(\)\s*\{[^}]*\|[^}]*&[^}]*\}\s*;", command)
    ):
        return Finding(
            rule_id="FORK_BOMB",
            severity="CRITICAL",
            title="fork bomb",
            detail="this line re-spawns itself forever; it exhausts "
                   "process limits and freezes the machine.",
            command_index=0,
        )
    return None
