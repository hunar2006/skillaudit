"""Provenance from install records: the lock file `npx skills add` keeps at ~/.agents/.skill-lock.json.

Each entry stores `skillFolderHash`, the git tree SHA of the skill folder at the commit it was installed
from. Recomputing that hash locally says, offline and for any source repo, whether the skill is still
exactly what was installed.
"""
import hashlib
import json
import re
import urllib.request
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
    (matches every executable script in anthropics/skills) and "nothing executable", for both byte variants.
    """
    shebang = frozenset(p for p, d in skill.files.items() if d.startswith(b"#!"))
    guesses = [frozenset(skill.executable), shebang, frozenset()]
    # Bytes as on disk first (upstream files may legitimately contain CRLF), then LF normalized
    # (a Windows git checkout with autocrlf rewrites line endings without anyone editing anything).
    return list(dict.fromkeys(tree_hash(files, g) for files in (skill.raw, skill.files) for g in guesses))


def load_lock(home: Path) -> dict:
    """Entries of the global skills CLI lock file; {} when it is missing or unreadable."""
    agents = (home.parent if home.name == ".claude" else Path.home()) / ".agents"
    try:
        data = json.loads((agents / ".skill-lock.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    skills = data.get("skills") if isinstance(data, dict) else None
    return skills if isinstance(skills, dict) else {}


def _crlf_rewritten(skill) -> bool:
    """Some text file has CRLF on disk: a Windows git checkout may have rewritten line endings."""
    return any(b"\r\n" in d and b"\0" not in d for d in skill.raw.values())


def check(skill, lock: dict):
    """Install record for a personal skill. status: intact | edited | unverified.

    unverified: the tree does not match, but line endings were rewritten on disk, and upstream may
    itself commit some files with CRLF. Offline there is no way to tell which files were converted
    (2^n combinations), so the honest answer is "cannot tell"; --online settles it file by file.
    """
    entry = lock.get(skill.path.name)
    # shortcut: only the global lock is read, so only personal skills get a record; project lock files
    # (skills-lock.json) are not documented yet, add them when the skills CLI settles the format
    if skill.scope != "personal" or not isinstance(entry, dict) or not entry.get("skillFolderHash"):
        return None
    local = candidate_hashes(skill)
    recorded = str(entry["skillFolderHash"])
    intact = recorded in local
    return {
        "source": entry.get("source") or entry.get("sourceUrl"),
        "source_type": entry.get("sourceType"),
        "source_url": entry.get("sourceUrl"),
        "installed_at": entry.get("installedAt"),
        "updated_at": entry.get("updatedAt"),
        "recorded_hash": recorded,
        "local_hash": recorded if intact else local[0],
        "intact": intact,
        "status": "intact" if intact else ("unverified" if _crlf_rewritten(skill) else "edited"),
        "verified": "offline",
    }


GITHUB_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
HEX_SHA = re.compile(r"^[0-9a-f]{40}$")


def github_tree(source: str, tree_sha: str) -> dict:
    """{path: blob sha} of a tree on GitHub, one unauthenticated API call."""
    # The lock file is input we do not control, so only a plain owner/repo and a hex sha reach the URL.
    if not GITHUB_REPO.match(source or "") or not HEX_SHA.match(tree_sha or ""):
        raise ValueError(f"not a GitHub owner/repo and tree sha: {source!r} {tree_sha!r}")
    req = urllib.request.Request(f"https://api.github.com/repos/{source}/git/trees/{tree_sha}?recursive=1",
                                 headers={"Accept": "application/vnd.github+json", "User-Agent": "skillaudit"})
    with urllib.request.urlopen(req, timeout=20) as r:
        data = json.load(r)
    if data.get("truncated"):
        raise ValueError("tree too large for a single API call")
    return {e["path"]: e["sha"] for e in data.get("tree", []) if e.get("type") == "blob"}


def verify_online(skill, rec: dict, fetch=github_tree) -> dict:
    """Compare every file with the recorded upstream tree, ignoring line endings. Fills in what changed."""
    try:
        upstream = fetch(rec["source"], rec["recorded_hash"])
    except (OSError, ValueError, KeyError) as e:  # urllib errors are OSErrors
        return {**rec, "online_error": str(e)}

    def same(data, sha):
        lf = data.replace(b"\r\n", b"\n")
        return sha in {_blob(v).hex() for v in (data, lf, lf.replace(b"\n", b"\r\n"))}

    local = skill.raw
    changed = sorted(p for p in local.keys() & upstream.keys() if not same(local[p], upstream[p]))
    added, removed = sorted(local.keys() - upstream.keys()), sorted(upstream.keys() - local.keys())
    ok = not (changed or added or removed)
    return {**rec, "intact": ok, "status": "intact" if ok else "edited", "verified": "online",
            "changed": changed, "added": added, "removed": removed}
