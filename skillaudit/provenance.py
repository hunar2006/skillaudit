"""Provenance from install records: the lock file `npx skills add` keeps at ~/.agents/.skill-lock.json.

Each entry stores `skillFolderHash`, the git tree SHA of the skill folder at the commit it was installed
from. Recomputing that hash locally says, offline and for any source repo, whether the skill is still
exactly what was installed.
"""
import hashlib
import json
from pathlib import Path


def _blob(data: bytes) -> bytes:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).digest()


def tree_hash(files: dict, executable=frozenset()) -> str:
    """Git tree SHA for {posix path: bytes}; equals `git rev-parse <commit>:<folder>`."""
    def tree(prefix):
        entries = {}  # name -> (mode, sha, sort key)
        for path, data in files.items():
            if not path.startswith(prefix):
                continue
            name, sep, _ = path[len(prefix):].partition("/")
            if sep:
                if name not in entries:
                    entries[name] = (b"40000", tree(prefix + name + "/"), name + "/")
            else:
                entries[name] = (b"100755" if path in executable else b"100644", _blob(data), name)
        # git orders entries by name, comparing a directory as if it ended in "/"
        body = b"".join(m + b" " + n.encode() + b"\0" + sha
                        for n, (m, sha, key) in sorted(entries.items(), key=lambda kv: kv[1][2].encode()))
        return hashlib.sha1(b"tree %d\0" % len(body) + body).digest()
    return tree("").hex()


def candidate_hashes(skill) -> list[str]:
    """Tree hashes under each plausible guess of which files are executable.

    Windows has no executable bit, so besides the real mode bits (POSIX) we try "files starting with #!"
    (matches every executable script in anthropics/skills) and "nothing executable".
    """
    shebang = frozenset(p for p, d in skill.files.items() if d.startswith(b"#!"))
    guesses = [frozenset(skill.executable), shebang, frozenset()]
    return list(dict.fromkeys(tree_hash(skill.files, g) for g in guesses))


def load_lock(home: Path) -> dict:
    """Entries of the global skills CLI lock file; {} when it is missing or unreadable."""
    agents = (home.parent if home.name == ".claude" else Path.home()) / ".agents"
    try:
        data = json.loads((agents / ".skill-lock.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    skills = data.get("skills") if isinstance(data, dict) else None
    return skills if isinstance(skills, dict) else {}


def check(skill, lock: dict):
    """Install record for a personal skill, with whether its files still match what was installed."""
    entry = lock.get(skill.path.name)
    # shortcut: only the global lock is read, so only personal skills get a record; project lock files
    # (skills-lock.json) are not documented yet, add them when the skills CLI settles the format
    if skill.scope != "personal" or not isinstance(entry, dict) or not entry.get("skillFolderHash"):
        return None
    local = candidate_hashes(skill)
    recorded = str(entry["skillFolderHash"])
    return {
        "source": entry.get("source") or entry.get("sourceUrl"),
        "source_url": entry.get("sourceUrl"),
        "installed_at": entry.get("installedAt"),
        "updated_at": entry.get("updatedAt"),
        "recorded_hash": recorded,
        "local_hash": recorded if recorded in local else local[0],
        "intact": recorded in local,
    }
