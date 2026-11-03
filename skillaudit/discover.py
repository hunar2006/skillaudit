"""Find Claude skills on this machine and load them into memory."""
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# Precedence from code.claude.com/docs/en/skills: enterprise > personal > project.
PRIORITY = {"managed": 0, "personal": 1, "project": 2}
PRUNE_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".trash", ".tox", "dist", "build"}
JUNK_FILES = {".DS_Store", "Thumbs.db"}
MAX_FILE_BYTES = 2_000_000  # shortcut: big files are truncated before hashing, fine for skills, revisit if skills ship large assets


@dataclass
class Skill:
    name: str
    scope: str
    path: Path
    frontmatter: dict
    text: str  # full SKILL.md
    body: str  # SKILL.md without frontmatter
    files: dict  # relative posix path -> bytes (CRLF normalized)
    warnings: list = field(default_factory=list)
    shadowed_by: str | None = None


def split_frontmatter(text):
    """Return (frontmatter dict, body, warning). Frontmatter only counts if '---' is on line 1."""
    if not text.startswith("---"):
        return {}, text, None
    end = text.find("\n---", 3)
    if end == -1:
        return {}, text, "frontmatter is never closed"
    raw = text[3:end]
    rest = text[end + 4:]
    body = rest.split("\n", 1)[1] if "\n" in rest else ""
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        return {}, body, f"malformed frontmatter YAML: {str(e).splitlines()[0]}"
    if data is None:
        return {}, body, None
    if not isinstance(data, dict):
        return {}, body, "frontmatter is not a mapping"
    return data, body, None


def load_skill(d: Path, scope: str) -> Skill:
    files, warnings = {}, []
    for root, dirs, names in os.walk(d):
        dirs[:] = sorted(x for x in dirs if x not in PRUNE_DIRS)
        for n in sorted(names):
            if n in JUNK_FILES or n.endswith(".pyc"):
                continue
            p = Path(root, n)
            try:
                with open(p, "rb") as f:
                    data = f.read(MAX_FILE_BYTES)
            except OSError as e:
                warnings.append(f"cannot read {p}: {e.strerror}")
                continue
            # Normalize line endings so a Windows checkout still matches upstream byte for byte.
            files[p.relative_to(d).as_posix()] = data.replace(b"\r\n", b"\n")
    text = files.get("SKILL.md", b"").decode("utf-8", "replace")
    fm, body, warn = split_frontmatter(text)
    if warn:
        warnings.append(warn)
    name = str(fm.get("name") or d.name)
    return Skill(name, scope, d, fm, text, body, files, warnings)


def managed_dir() -> Path:
    if sys.platform == "darwin":
        return Path("/Library/Application Support/ClaudeCode")
    if sys.platform == "win32":
        return Path(r"C:\Program Files\ClaudeCode")
    return Path("/etc/claude-code")


def _skill_dirs(base: Path, scope: str):
    if base.is_dir():
        for d in sorted(base.iterdir()):
            if (d / "SKILL.md").is_file():
                yield d, scope


def _project_skill_bases(root: Path):
    """Skill folders above root (up to the git root, like Claude Code) and anywhere below it."""
    home = Path.home().resolve()
    for p in [root, *root.parents]:
        if p == home:  # ~/.claude/skills is personal, never project
            break
        yield p / ".claude" / "skills"
        if (p / ".git").exists():
            break
    for cur, dirs, _ in os.walk(root):
        dirs[:] = sorted(x for x in dirs if x not in PRUNE_DIRS)
        if ".claude" in dirs:
            yield Path(cur) / ".claude" / "skills"


def candidates(home: Path, roots):
    yield from _skill_dirs(managed_dir() / ".claude" / "skills", "managed")
    yield from _skill_dirs(home / "skills", "personal")
    yield from _skill_dirs(home / "skills" / "synced", "synced")
    plugins = home / "plugins"
    if plugins.is_dir():
        for md in sorted(plugins.rglob("SKILL.md")):
            parts = md.relative_to(plugins).parts
            # shortcut: skips marketplaces/ (repo clones, not installed) and hidden dirs (.trash, other agents'
            # copies like .openclaw/), revisit if Claude Code changes its plugin layout
            if "marketplaces" not in parts and not any(x.startswith(".") for x in parts):
                yield md.parent, "plugin"
    for r in roots:
        for base in _project_skill_bases(Path(r).resolve()):
            yield from _skill_dirs(base, "project")


def discover(home: Path, roots) -> list[Skill]:
    seen, skills = set(), []
    for d, scope in candidates(home, roots):
        key = d.resolve()  # symlinked skill folders are the same skill
        if key in seen:
            continue
        seen.add(key)
        skills.append(load_skill(d, scope))
    _mark_shadowing(skills)
    return skills


def _mark_shadowing(skills):
    for s in skills:
        if s.scope not in PRIORITY:
            continue
        stronger = [o for o in skills if o.name == s.name and PRIORITY.get(o.scope, 99) < PRIORITY[s.scope]]
        if stronger:
            w = min(stronger, key=lambda o: PRIORITY[o.scope])
            s.shadowed_by = f"{w.scope}:{w.path}"
