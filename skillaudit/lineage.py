"""Correlate a local skill with the vendored anthropics/skills catalog."""
import difflib
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from .discover import Skill, load_skill

CATALOG_DIR = Path(__file__).parent / "catalog"
FORK_THRESHOLD = 0.5  # tuned on the demo fixtures; see README


@dataclass
class Lineage:
    state: str  # unmodified | renamed | modified | custom
    upstream: Skill | None = None
    similarity: float = 0.0
    added: list = field(default_factory=list)
    removed: list = field(default_factory=list)
    changed: list = field(default_factory=list)
    unchanged: list = field(default_factory=list)
    frontmatter_changes: dict = field(default_factory=dict)  # key -> (upstream, local)


def load_catalog():
    manifest = json.loads((CATALOG_DIR / "manifest.json").read_text())
    return manifest, [load_skill(CATALOG_DIR / n, "catalog") for n in manifest["skills"]]


def _hashes(skill):
    return {k: hashlib.sha256(v).hexdigest() for k, v in skill.files.items()}


def _is_license(path):
    # Many unrelated skills ship the same Apache LICENSE, so it must not count as shared ancestry.
    return Path(path).name.upper().startswith(("LICENSE", "COPYING", "NOTICE"))


def body_similarity(a: Skill, b: Skill) -> float:
    return difflib.SequenceMatcher(None, a.body.splitlines(), b.body.splitlines(), autojunk=False).ratio()


def compare(local: Skill, up: Skill) -> Lineage:
    lh, uh = _hashes(local), _hashes(up)
    added = sorted(lh.keys() - uh.keys())
    removed = sorted(uh.keys() - lh.keys())
    common = lh.keys() & uh.keys()
    changed = sorted(k for k in common if lh[k] != uh[k])
    unchanged = sorted(k for k in common if lh[k] == uh[k])
    keys = local.frontmatter.keys() | up.frontmatter.keys()
    fm = {k: (up.frontmatter.get(k), local.frontmatter.get(k))
          for k in sorted(keys) if up.frontmatter.get(k) != local.frontmatter.get(k)}
    lin = Lineage("custom", up, 0.0, added, removed, changed, unchanged, fm)

    same_name = local.name == up.name and local.path.name == up.path.name
    if not (added or removed or changed):
        lin.state, lin.similarity = ("unmodified" if same_name else "renamed"), 1.0
        return lin
    # Renamed: only the name field (and folder) differ, everything else is byte identical.
    if not (added or removed) and changed == ["SKILL.md"] and set(fm) <= {"name"} and local.body == up.body:
        lin.state, lin.similarity = "renamed", 1.0
        return lin

    # Share of upstream that survives: each functional file counts 1 if byte identical,
    # SKILL.md counts by how much of its body is still there.
    functional = [k for k in uh if not _is_license(k) and k != "SKILL.md"]
    kept = sum(1 for k in functional if lh.get(k) == uh[k]) + body_similarity(local, up)
    lin.similarity = round(kept / (len(functional) + 1), 3)
    if lin.similarity >= FORK_THRESHOLD:
        lin.state = "modified"
    return lin


RANK = {"unmodified": 3, "renamed": 2, "modified": 1, "custom": 0}


def correlate(local: Skill, catalog) -> Lineage:
    best = max((compare(local, up) for up in catalog), key=lambda l: (RANK[l.state], l.similarity))
    if best.state == "custom":
        best.upstream = None
    return best


def unified_diff(local: Skill, up: Skill, rel: str, context=2) -> list[str]:
    a = up.files.get(rel, b"").decode("utf-8", "replace").splitlines()
    b = local.files.get(rel, b"").decode("utf-8", "replace").splitlines()
    return list(difflib.unified_diff(a, b, f"upstream/{rel}", f"local/{rel}", n=context, lineterm=""))
