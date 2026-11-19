"""Offline knowledge base of shell commands for the explainer.

Entries are deliberately conservative: a flag is listed only when it is
part of standard GNU/coreutils or the tool's own documented interface.
When unsure, the flag is omitted - the explainer then says so honestly.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class CommandInfo:
    """What dryrun knows about one shell command."""

    name: str
    summary: str
    category: str
    flags: Dict[str, str] = field(default_factory=dict)
    danger: str = ""


def _c(name: str, summary: str, category: str, flags=None, danger: str = "") -> CommandInfo:
    return CommandInfo(name=name, summary=summary, category=category,
                       flags=dict(flags or {}), danger=danger)


COMMON_LS = {
    "-l": "long listing with sizes and permissions",
    "-a": "include hidden entries",
    "-h": "human-readable sizes",
    "-R": "recurse into subdirectories",
    "-t": "sort by modification time",
    "-r": "reverse the sort order",
    "-S": "sort by file size",
    "-1": "one entry per line",
    "-d": "list directories themselves, not contents",
    "-i": "show inode numbers",
}

COMMANDS: Dict[str, CommandInfo] = {info.name: info for info in [
    # --- files -----------------------------------------------------------
    _c("ls", "list directory contents", "files", COMMON_LS),
    _c("pwd", "print the current working directory", "files"),
    _c("cd", "change the current directory", "files", {
        "..": "go up one directory", "-": "return to the previous directory"}),
    _c("cp", "copy files and directories", "files", {
        "-r": "recurse into directories (required for directories)",
        "-R": "recurse into directories (required for directories)",
        "-a": "archive mode: preserve everything, recurse",
        "-i": "prompt before overwriting",
        "-f": "force: remove destination and retry",
        "-n": "never overwrite an existing file",
        "-p": "preserve mode, ownership, timestamps",
        "-v": "show what is copied",
        "-u": "copy only when the source is newer",
        "--reflink": "copy-on-write clone where the filesystem supports it"}),
    _c("mv", "move or rename files", "files", {
        "-i": "prompt before overwriting",
        "-f": "force overwrite without prompting",
        "-n": "never overwrite an existing file",
        "-v": "show what is moved",
        "-u": "move only when the source is newer"}),
    _c("rm", "remove files or directories", "files", {
        "-r": "recurse into directories (deletes whole trees)",
        "-R": "recurse into directories (deletes whole trees)",
        "-f": "force: ignore missing files, never prompt",
        "-i": "prompt before every removal",
        "-I": "prompt once before removing more than 3 files",
        "-d": "remove empty directories",
        "-v": "show what is removed"},
        danger="can delete data permanently; with -r and -f it deletes whole "
               "trees without asking"),
    _c("mkdir", "create directories", "files", {
        "-p": "create parent directories as needed",
        "-m": "set the permission mode",
        "-v": "show each directory created"}),
    _c("rmdir", "remove empty directories", "files", {
        "-p": "remove parent directories that become empty"}),
    _c("ln", "create links between files", "files", {
        "-s": "create a symbolic link (default is a hard link)",
        "-f": "replace existing destination",
        "-i": "prompt before replacing",
        "-v": "show each link created"}),
    _c("touch", "create empty files or update timestamps", "files", {
        "-a": "change only the access time",
        "-m": "change only the modification time",
        "-c": "do not create the file, only update times if it exists",
        "-d": "set the time from a string",
        "-t": "set the time from a timestamp"}),
    _c("cat", "print file contents to stdout", "text", {
        "-n": "number all output lines",
        "-A": "show non-printing characters and line ends",
        "-s": "squeeze repeated blank lines"}),
    _c("less", "page through a file one screen at a time", "text"),
    _c("more", "page through a file one screen at a time", "text"),
    _c("head", "show the first lines of a file", "text", {
        "-n": "show N lines instead of 10",
        "-c": "show N bytes"}),
    _c("tail", "show the last lines of a file", "text", {
        "-n": "show N lines instead of 10",
        "-c": "show N bytes",
        "-f": "keep watching the file as it grows"}),
    _c("echo", "print arguments to stdout", "text", {
        "-n": "do not print the trailing newline",
        "-e": "interpret backslash escapes"}),
    _c("printf", "format and print text", "text"),
    _c("stat", "show file metadata (size, times, mode)", "files", {
        "-c": "use a custom format string",
        "-f": "show filesystem status instead"}),
    _c("file", "identify a file's type by its contents", "files"),
    _c("du", "show disk usage of files and directories", "files", {
        "-s": "print only the total",
        "-h": "human-readable sizes",
        "-a": "include files, not just directories",
        "-d": "limit the depth shown",
        "--max-depth": "limit the depth shown"}),
    _c("df", "show free space on filesystems", "files", {
        "-h": "human-readable sizes",
        "-i": "show inode usage",
        "-T": "show the filesystem type"}),
    _c("chmod", "change file permissions", "files", {
        "-R": "recurse into directories",
        "-v": "show each change",
        "-c": "report only changes",
        "+x": "make executable",
        "777": "world-readable, writable, and executable"},
        danger="wrong modes can open files to every user or break tools"),
    _c("chown", "change file owner and group", "files", {
        "-R": "recurse into directories",
        "-v": "show each change"},
        danger="needs root; wrong ownership can lock out users or services"),
    _c("chgrp", "change file group", "files", {"-R": "recurse into directories"}),
    _c("umask", "show or set the default permission mask", "files"),
    _c("readlink", "show where a symlink points", "files", {
        "-f": "resolve every component to an absolute path"}),
    _c("realpath", "print the absolute path with symlinks resolved", "files"),
    _c("basename", "strip directories from a path", "files"),
    _c("dirname", "strip the last component from a path", "files"),
    _c("tree", "show a directory tree", "files", {
        "-a": "include hidden entries",
        "-d": "directories only",
        "-L": "limit depth"}),
    _c("lsblk", "list block devices and their mount points", "system"),
    _c("mount", "mount a filesystem", "system", danger="needs root"),
    _c("umount", "unmount a filesystem", "system", danger="needs root"),
    _c("chattr", "change file attributes on a filesystem", "files", danger="needs root"),
    _c("mkfs", "create a filesystem on a device", "system", danger="destroys all data on the device"),
    _c("dd", "copy raw data between files and devices", "system", {
        "if=": "input file or device",
        "of=": "output file or device",
        "bs=": "block size",
        "count=": "copy only N blocks",
        "conv=": "apply conversions such as notrunc or sync"},
        danger="writing to a device with of= erases it completely"),
    _c("shred", "overwrite a file to destroy its contents", "files", danger="irreversibly destroys the file's data"),
    _c("truncate", "shrink or extend a file to a given size", "files", {
        "-s": "target size, e.g. 0 or +100M"},
        danger="can destroy file contents instantly"),

    # --- text ------------------------------------------------------------
    _c("grep", "search text with patterns", "search", {
        "-r": "recurse into directories",
        "-R": "recurse into directories, follow symlinks",
        "-i": "ignore case",
        "-n": "show line numbers",
        "-v": "invert: show non-matching lines",
        "-l": "list only file names with matches",
        "-c": "count matches per file",
        "-w": "match whole words only",
        "-E": "extended regular expressions",
        "-F": "fixed strings, no regex",
        "-A": "show N lines after a match",
        "-B": "show N lines before a match",
        "-C": "show N lines around a match",
        "-o": "print only the matched parts",
        "-H": "print the file name with each match"}),
    _c("sed", "stream editor for filtering and transforming text", "text", {
        "-i": "edit files in place (default writes to stdout)",
        "-n": "suppress automatic printing",
        "-e": "add a script to apply",
        "-E": "extended regular expressions",
        "-f": "read the script from a file"},
        danger="with -i it rewrites the file directly; a bad pattern can mangle it"),
    _c("awk", "pattern scanning and processing language", "text", {
        "-F": "set the field separator",
        "-f": "read the program from a file",
        "-v": "set a variable"}),
    _c("perl", "run perl programs or one-liners", "text", {
        "-e": "run the program given on the command line",
        "-i": "edit files in place",
        "-p": "loop over lines, print them",
        "-n": "loop over lines, do not print",
        "-w": "enable warnings"}),
    _c("ruby", "run ruby programs or one-liners", "text", {"-e": "run the program given on the command line"}),
    _c("find", "search for files in a directory tree", "search", {
        "-name": "match the file name against a pattern",
        "-iname": "case-insensitive name match",
        "-type": "match by type: f files, d directories, l symlinks",
        "-size": "match by size",
        "-mtime": "match by modification time in days",
        "-mmin": "match by modification time in minutes",
        "-exec": "run a command on each match",
        "-delete": "delete every match",
        "-maxdepth": "limit the search depth",
        "-path": "match the whole path against a pattern"},
        danger="-delete removes matches directly; -exec rm runs a delete per match"),
    _c("xargs", "build command lines from stdin and run them", "search", {
        "-I": "replace occurrences of a placeholder in the command",
        "-n": "pass at most N arguments per invocation",
        "-0": "separate input items by NUL bytes",
        "-r": "do not run the command when input is empty",
        "-P": "run up to N commands in parallel"},
        danger="feeds unchecked input straight into the command it runs"),
    _c("sort", "sort lines of text", "text", {
        "-n": "sort numerically",
        "-r": "reverse the order",
        "-u": "drop duplicate lines",
        "-k": "sort by a key field",
        "-h": "sort human-readable sizes",
        "-t": "set the field separator"}),
    _c("uniq", "drop or report repeated adjacent lines", "text", {
        "-c": "prefix lines with a repeat count",
        "-d": "print only repeated lines",
        "-u": "print only unique lines"}),
    _c("wc", "count lines, words, and bytes", "text", {
        "-l": "count lines",
        "-w": "count words",
        "-c": "count bytes",
        "-m": "count characters"}),
    _c("cut", "remove sections from each line", "text", {
        "-d": "set the field delimiter",
        "-f": "select fields",
        "-c": "select characters by position"}),
    _c("tr", "translate or delete characters", "text", {
        "-d": "delete the given characters",
        "-s": "squeeze repeated characters",
        "-c": "complement the character set"}),
    _c("tee", "write stdin to files and pass it through", "text", {
        "-a": "append to the files instead of overwriting"},
        danger="overwrites the target files unless -a is given"),
    _c("which", "locate a command in the PATH", "text"),
    _c("whereis", "locate a command's binary, source, and manual", "text"),
    _c("diff", "compare two files line by line", "text", {
        "-u": "unified output format",
        "-r": "recurse into directories",
        "-q": "report only whether files differ"}),
    _c("cmp", "compare two files byte by byte", "text"),
    _c("patch", "apply a diff to files", "text"),
    _c("split", "split a file into pieces", "text", {
        "-b": "split by byte count",
        "-l": "split by line count",
        "-d": "use numeric suffixes"}),
    _c("csplit", "split a file by context patterns", "text"),
    _c("column", "format input into aligned columns", "text", {"-t": "auto-size columns", "-s": "set the delimiter"}),
    _c("base64", "encode or decode base64", "text", {
        "-d": "decode instead of encode",
        "-w": "set the wrap width"}),
    _c("md5sum", "compute MD5 checksums", "text"),
    _c("sha256sum", "compute SHA-256 checksums", "text"),
    _c("sha1sum", "compute SHA-1 checksums", "text"),
    _c("jq", "process JSON with a query language", "text", {
        ".": "identity filter, pretty-print",
        "-r": "raw string output",
        "-c": "compact output",
        "-n": "start with null input",
        "-e": "set exit code from the output",
        "-s": "slurp the whole input into an array"}),
    _c("bc", "arbitrary-precision calculator", "text"),
    _c("seq", "print a sequence of numbers", "text"),
    _c("shuf", "generate random permutations of input lines", "text"),
    _c("yes", "print a string repeatedly until killed", "text"),
    _c("tput", "query terminal capabilities", "text"),
    _c("clear", "clear the terminal screen", "text"),
    _c("reset", "reset the terminal to a sane state", "text"),

    # --- archive ---------------------------------------------------------
    _c("tar", "archive and extract files", "archive", {
        "-c": "create an archive",
        "-x": "extract from an archive",
        "-t": "list archive contents",
        "-f": "use the given archive file",
        "-z": "filter through gzip",
        "-j": "filter through bzip2",
        "-J": "filter through xz",
        "-v": "show files as they are processed",
        "-p": "preserve permissions on extract",
        "-P": "keep absolute paths (strip nothing)",
        "--absolute-names": "keep absolute paths on extract",
        "--strip-components": "drop N leading path components on extract",
        "-C": "change to a directory first"},
        danger="extracting archives that contain absolute paths or .. can overwrite system files"),
    _c("gzip", "compress files in place", "archive", {
        "-d": "decompress", "-k": "keep the original", "-9": "maximum compression"}),
    _c("gunzip", "decompress gzip files", "archive", {"-k": "keep the compressed file"}),
    _c("zcat", "print gzip-compressed files without extracting to disk", "archive"),
    _c("bzip2", "compress files with bzip2", "archive", {"-d": "decompress", "-k": "keep the original"}),
    _c("bunzip2", "decompress bzip2 files", "archive"),
    _c("xz", "compress files with xz", "archive", {"-d": "decompress", "-k": "keep the original", "-T": "use N threads"}),
    _c("zip", "create zip archives", "archive", {"-r": "recurse into directories"}),
    _c("unzip", "extract zip archives", "archive", {"-o": "overwrite without prompting", "-d": "extract into a directory"}),

    # --- network ---------------------------------------------------------
    _c("curl", "transfer data from or to a URL", "network", {
        "-s": "silent: hide the progress meter",
        "-S": "show errors even when silent",
        "-L": "follow redirects",
        "-o": "write output to a file",
        "-O": "write output to a file named from the URL",
        "-I": "fetch headers only",
        "-X": "use the given HTTP method",
        "-d": "send the given data (POST body)",
        "-H": "send an extra HTTP header",
        "-k": "skip TLS certificate verification",
        "-u": "use user and password authentication",
        "-F": "send multipart form data",
        "--data": "send the given data (POST body)"},
        danger="network effects cannot be previewed; piped into a shell it executes remote bytes"),
    _c("wget", "download files from the web", "network", {
        "-O": "write output to a given file",
        "-q": "quiet",
        "-c": "continue a partial download",
        "--no-check-certificate": "skip TLS verification",
        "-P": "save into a directory",
        "-r": "download recursively"},
        danger="network effects cannot be previewed; piped into a shell it executes remote bytes"),
    _c("ssh", "log into or run commands on a remote machine", "network", {
        "-p": "remote port",
        "-i": "identity (private key) file",
        "-L": "forward a local port",
        "-R": "forward a remote port",
        "-N": "do not run a remote command",
        "-t": "force pseudo-terminal allocation",
        "-A": "forward the local ssh agent"},
        danger="runs commands on another machine; effects there cannot be previewed"),
    _c("scp", "copy files over ssh", "network", {
        "-r": "recurse into directories",
        "-P": "remote port",
        "-i": "identity (private key) file"}),
    _c("sftp", "secure file transfer interactive client", "network"),
    _c("rsync", "fast incremental file transfer", "network", {
        "-a": "archive mode: recurse and preserve attributes",
        "-v": "show what is transferred",
        "-z": "compress during transfer",
        "-P": "show progress and keep partial files",
        "--delete": "delete files at the destination that are gone from the source",
        "-n": "dry run: show what would happen",
        "-e": "choose the remote shell"},
        danger="--delete removes destination files; combined with a wrong path it eats data"),
    _c("nc", "read and write raw TCP or UDP streams", "network", {
        "-l": "listen for an incoming connection",
        "-p": "local port",
        "-z": "scan without sending data",
        "-k": "keep listening after a connection closes"},
        danger="an open listener accepts whatever bytes arrive and a piped shell executes them"),
    _c("netcat", "read and write raw TCP or UDP streams", "network", {
        "-l": "listen for an incoming connection"},
        danger="an open listener accepts whatever bytes arrive"),
    _c("ping", "send ICMP echo requests to a host", "network", {
        "-c": "stop after N packets"}),
    _c("traceroute", "show the network path to a host", "network"),
    _c("tracepath", "show the network path and MTU to a host", "network"),
    _c("dig", "query DNS records", "network", {"+short": "print only the answer", "-x": "reverse lookup"}),
    _c("nslookup", "query DNS records", "network"),
    _c("host", "simple DNS lookup", "network"),
    _c("ip", "show or configure network interfaces and routes", "network", {
        "addr": "show addresses",
        "link": "show link state",
        "route": "show the routing table",
        "-br": "brief output"}),
    _c("ifconfig", "show or configure network interfaces (legacy)", "network"),
    _c("netstat", "show network connections and sockets (legacy)", "network", {"-t": "TCP sockets", "-l": "listening sockets", "-p": "show owning processes", "-n": "numeric addresses"}),
    _c("ss", "show network sockets", "network", {"-t": "TCP sockets", "-l": "listening sockets", "-p": "show owning processes", "-n": "numeric addresses"}),
    _c("lsof", "list open files and the processes holding them", "system", {"-i": "internet sockets", "+D": "all files under a directory"}),
    _c("openssl", "crypto toolkit: TLS, certs, hashing", "system", {
        "enc": "encrypt or decrypt data",
        "genrsa": "generate an RSA key",
        "req": "build a certificate request",
        "x509": "inspect or sign certificates"}),
    _c("gpg", "encrypt, sign, and manage keys with OpenPGP", "system"),

    # --- packages --------------------------------------------------------
    _c("apt", "Debian/Ubuntu package manager", "packages", {
        "update": "refresh the package index",
        "upgrade": "install available upgrades",
        "install": "install packages",
        "remove": "remove packages",
        "purge": "remove packages and their config files",
        "autoremove": "remove unneeded dependencies",
        "search": "search package names and descriptions",
        "list": "list packages",
        "-y": "assume yes for every prompt"},
        danger="changes system-wide state; needs root"),
    _c("apt-get", "Debian/Ubuntu package manager (scripting interface)", "packages", {
        "update": "refresh the package index",
        "upgrade": "install available upgrades",
        "install": "install packages",
        "remove": "remove packages",
        "purge": "remove packages and their config files",
        "dist-upgrade": "upgrade even if packages must be removed",
        "-y": "assume yes for every prompt",
        "-f": "fix broken dependencies"},
        danger="changes system-wide state; needs root"),
    _c("yum", "RHEL/CentOS package manager", "packages", {
        "install": "install packages",
        "remove": "remove packages",
        "update": "upgrade packages",
        "-y": "assume yes"}, danger="changes system-wide state"),
    _c("dnf", "Fedora/RHEL package manager", "packages", {
        "install": "install packages",
        "remove": "remove packages",
        "upgrade": "upgrade packages",
        "-y": "assume yes"}, danger="changes system-wide state"),
    _c("pacman", "Arch package manager", "packages", {
        "-S": "install packages",
        "-R": "remove packages",
        "-Syu": "refresh index and upgrade the system",
        "-Syyu": "force-refresh index and upgrade"}, danger="changes system-wide state"),
    _c("brew", "Homebrew package manager (macOS/Linux)", "packages", {
        "install": "install packages",
        "uninstall": "remove packages",
        "upgrade": "upgrade installed packages",
        "update": "refresh the index"}, danger="changes user-wide state"),
    _c("pip", "Python package installer", "packages", {
        "install": "install packages",
        "uninstall": "remove packages",
        "freeze": "print installed versions",
        "-r": "install from a requirements file",
        "--user": "install into the user site"},
        danger="runs setup code from packages; with sudo it can touch system files"),
    _c("pip3", "Python 3 package installer", "packages", {
        "install": "install packages",
        "uninstall": "remove packages",
        "-r": "install from a requirements file"},
        danger="runs setup code from packages; with sudo it can touch system files"),
    _c("npm", "Node.js package manager", "packages", {
        "install": "install packages",
        "i": "install packages",
        "uninstall": "remove packages",
        "run": "run a script defined in package.json",
        "test": "run the test script",
        "publish": "publish the package to the registry",
        "-g": "install globally",
        "--force": "force actions, skip safety checks"},
        danger="runs install scripts from the registry; --force skips confirmations"),
    _c("npx", "run a package binary without installing it", "packages", {
        "-y": "assume yes when downloading"}),
    _c("yarn", "JavaScript package manager", "packages", {
        "install": "install dependencies",
        "add": "add a package",
        "remove": "remove a package",
        "run": "run a script",
        "global": "operate on global packages"}),
    _c("pnpm", "fast JavaScript package manager", "packages", {
        "install": "install dependencies",
        "add": "add a package",
        "remove": "remove a package",
        "run": "run a script"}),

    # --- processes -------------------------------------------------------
    _c("ps", "report running processes", "processes", {
        "aux": "show every process with details (BSD style)",
        "-e": "show every process",
        "-f": "full-format listing",
        "-u": "filter by user"}),
    _c("top", "show live process activity", "processes"),
    _c("htop", "interactive process viewer", "processes"),
    _c("kill", "send a signal to a process by PID", "processes", {
        "-9": "SIGKILL: kill immediately, no cleanup",
        "-15": "SIGTERM: ask the process to exit (default)",
        "-1": "SIGHUP: reload configuration, or signal all processes you own",
        "-l": "list signal names"},
        danger="SIGKILL loses unsaved data; kill -1 targets every process you own"),
    _c("killall", "kill processes by exact name", "processes", {
        "-9": "kill immediately, no cleanup",
        "-i": "prompt before killing"},
        danger="kills every process with that name, not just one"),
    _c("pkill", "kill processes matching a pattern", "processes", {
        "-9": "kill immediately, no cleanup",
        "-f": "match the full command line",
        "-i": "ignore case"},
        danger="a broad pattern kills unrelated processes"),
    _c("pgrep", "list processes matching a pattern", "processes", {"-f": "match the full command line", "-l": "show names"}),
    _c("nohup", "run a command immune to hangups, output to nohup.out", "processes"),
    _c("time", "report how long a command takes", "processes"),
    _c("timeout", "run a command with a time limit", "processes", {
        "-k": "also send SIGKILL after a grace period"}),
    _c("watch", "run a command repeatedly and show its output", "processes", {"-n": "seconds between runs"}),
    _c("stdbuf", "run a command with adjusted stream buffering", "processes"),
    _c("strace", "trace system calls of a process", "system", {
        "-f": "follow child processes",
        "-e": "filter which calls to trace",
        "-p": "attach to a running PID"}),
    _c("ltrace", "trace library calls of a process", "system"),

    # --- system ----------------------------------------------------------
    _c("sudo", "run a command as another user (usually root)", "system", {
        "-i": "start a login shell",
        "-u": "run as a given user",
        "-E": "keep the environment"},
        danger="the command runs with full system privileges; simulation is refused"),
    _c("su", "switch user, default to root", "system", danger="opens a privileged shell; simulation is refused"),
    _c("doas", "run a command as another user (OpenBSD style)", "system", danger="the command runs with elevated privileges"),
    _c("pkexec", "run a command as administrator via polkit", "system", danger="the command runs with elevated privileges"),
    _c("newgrp", "log in to a new group", "system"),
    _c("systemctl", "control the systemd init system", "system", {
        "status": "show unit status",
        "start": "start a unit",
        "stop": "stop a unit",
        "restart": "restart a unit",
        "enable": "start at boot",
        "disable": "do not start at boot",
        "--now": "also start or stop immediately",
        "daemon-reload": "reload unit files"},
        danger="stops or restarts live services; needs root"),
    _c("service", "run a System V init script", "system", danger="stops or restarts live services; needs root"),
    _c("journalctl", "read systemd logs", "system", {
        "-u": "filter by unit",
        "-f": "follow new entries",
        "-n": "show the last N entries",
        "--since": "show entries since a time"}),
    _c("dmesg", "show kernel ring buffer messages", "system"),
    _c("uname", "print system information", "system", {"-a": "print everything"}),
    _c("hostname", "show or set the host name", "system"),
    _c("whoami", "print the current user name", "system"),
    _c("id", "print user and group identities", "system"),
    _c("groups", "print group memberships", "system"),
    _c("free", "show memory usage", "system", {"-h": "human-readable sizes"}),
    _c("uptime", "show how long the system has been up", "system"),
    _c("env", "run a command with a modified environment, or print it", "shell", {
        "-i": "start with an empty environment",
        "-u": "remove a variable"}),
    _c("export", "mark variables for export to child processes", "shell"),
    _c("unset", "remove variables or functions", "shell"),
    _c("alias", "create or list command aliases", "shell"),
    _c("unalias", "remove command aliases", "shell"),
    _c("source", "run a script in the current shell", "shell", danger="executes the file's contents in your shell with your permissions"),
    _c("history", "show command history", "shell"),
    _c("man", "show the manual page for a command", "shell"),
    _c("eval", "concatenate arguments and run the result as a command", "shell",
        danger="executes assembled text; combined with untrusted input it runs arbitrary code"),
    _c("exec", "replace the shell with a command", "shell"),
    _c("trap", "run a command when a signal arrives", "shell"),
    _c("set", "set shell options and positional parameters", "shell", {
        "-e": "exit on any command failure",
        "-x": "print each command before running it",
        "-u": "error on undefined variables"}),
    _c("test", "evaluate an expression, set exit status", "shell"),
    _c("[", "evaluate an expression (same as test)", "shell"),
    _c("getconf", "query system configuration values", "system"),
    _c("locale", "show locale settings", "system"),
    _c("shutdown", "power off or reboot the machine", "system", {
        "-h": "halt", "-r": "reboot", "now": "act immediately"},
        danger="takes the machine down for every user"),
    _c("reboot", "restart the machine immediately", "system", danger="takes the machine down for every user"),
    _c("halt", "stop the machine", "system", danger="takes the machine down for every user"),
    _c("poweroff", "power the machine down", "system", danger="takes the machine down for every user"),
    _c("init", "change the system runlevel or state", "system", danger="0 powers off and 6 reboots the machine"),
    _c("crontab", "edit or replace the user's cron schedule", "system", {
        "-l": "list the schedule",
        "-e": "edit the schedule",
        "-r": "remove the schedule entirely",
        "-u": "operate on another user's schedule"},
        danger="-r silently deletes the whole schedule with no confirmation"),
    _c("useradd", "create a user account (needs root)", "system"),
    _c("usermod", "modify a user account (needs root)", "system"),
    _c("groupadd", "create a group (needs root)", "system"),
    _c("passwd", "change a user password", "system"),

    # --- vcs / build -----------------------------------------------------
    _c("git", "distributed version control", "vcs", {
        "status": "show the working tree state",
        "clone": "copy a repository",
        "pull": "fetch and merge from a remote",
        "push": "publish commits to a remote",
        "commit": "record changes",
        "add": "stage changes",
        "checkout": "switch branches or restore files",
        "reset": "move the current branch pointer",
        "--hard": "reset the working tree too, discarding changes",
        "clean": "delete untracked files",
        "rebase": "replay commits on a new base",
        "stash": "shelve changes temporarily",
        "merge": "join two lines of history",
        "restore": "restore working tree files",
        "switch": "switch branches",
        "-f": "force the action, skip safety checks",
        "--force": "force the action, skip safety checks"},
        danger="reset --hard and clean -fd discard uncommitted work; push --force rewrites remote history"),
    _c("make", "run build tasks from a Makefile", "build", {
        "-j": "run N jobs in parallel",
        "-n": "dry run: print commands without running them",
        "clean": "usually removes build outputs",
        "install": "copy built files into system locations"},
        danger="the install target writes outside the project; rules can run any command"),
    _c("cmake", "generate build files", "build", {"-S": "source directory", "-B": "build directory"}),
    _c("gcc", "compile C and C++ programs", "build", {
        "-o": "write the output to this file",
        "-c": "compile to an object file, do not link",
        "-O2": "optimize for speed",
        "-Wall": "enable most warnings",
        "-Wextra": "enable extra warnings",
        "-shared": "build a shared library",
        "-fPIC": "generate position-independent code"}),
    _c("cc", "compile C programs (system compiler)", "build", {"-o": "write the output to this file"}),
    _c("cargo", "Rust build tool and package manager", "build", {
        "build": "compile the project",
        "run": "build and run",
        "test": "run tests",
        "install": "install a binary into ~/.cargo/bin",
        "--release": "build with optimizations"}),
    _c("rustc", "compile Rust programs", "build", {"-o": "write the output to this file"}),
    _c("go", "Go toolchain: build, test, install", "build", {
        "build": "compile the project",
        "run": "compile and run",
        "test": "run tests",
        "install": "install binaries into GOPATH/bin",
        "mod": "module maintenance"}),
    _c("java", "run a Java program", "build", {"-jar": "run an executable jar"}),
    _c("mvn", "Maven build tool for Java", "build", {"clean": "delete build outputs", "install": "install artifacts locally", "-D": "define a property"}),
    _c("gradle", "Gradle build tool", "build", {"build": "assemble the project", "clean": "delete build outputs"}),

    # --- languages / shells ---------------------------------------------
    _c("python3", "run the Python 3 interpreter", "misc", {
        "-c": "run the program given as a string",
        "-m": "run a module as a script",
        "-i": "drop into a REPL after running",
        "-V": "print the version"}),
    _c("python", "run the Python interpreter", "misc", {
        "-c": "run the program given as a string",
        "-m": "run a module as a script"}),
    _c("node", "run the Node.js JavaScript runtime", "misc", {
        "-e": "run the program given as a string",
        "-i": "start the REPL"}),
    _c("bash", "the GNU Bourne-Again shell", "shell", {
        "-c": "run the argument as a command string",
        "-e": "exit on the first failing command",
        "-x": "print each command before running it",
        "-s": "read commands from stdin"},
        danger="as a pipe target it executes whatever bytes arrive on stdin"),
    _c("sh", "the POSIX shell", "shell", {
        "-c": "run the argument as a command string"},
        danger="as a pipe target it executes whatever bytes arrive on stdin"),
    _c("dash", "the Debian Almquist shell", "shell", danger="as a pipe target it executes whatever bytes arrive on stdin"),
    _c("zsh", "the Z shell", "shell", danger="as a pipe target it executes whatever bytes arrive on stdin"),
    _c("fish", "the friendly interactive shell", "shell"),
    _c("ksh", "the Korn shell", "shell", danger="as a pipe target it executes whatever bytes arrive on stdin"),
    _c("vim", "the Vim text editor", "misc", {"-u": "use a different vimrc"}),
    _c("nano", "a small friendly text editor", "misc"),
    _c("w", "show who is logged in and what they run", "system"),
    _c("who", "show who is logged in", "system"),
    _c("last", "show recent logins", "system"),
    _c("date", "print or set the date", "system", {"-u": "use UTC", "-d": "format a given date string"}),
]}


def lookup(name: str) -> CommandInfo:
    """Return CommandInfo for a command name, or None when unknown."""
    return COMMANDS.get(name)
