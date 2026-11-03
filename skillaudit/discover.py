"""Find Claude skills on this machine and load them into memory."""
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# Precedence from code.claude.com/docs/en/skills: enterprise > personal > project.
PRIORITY = {"managed": 0, "personal": 1, "project": 2}
# AppData/Library/.cache: OS app data and temp dirs under home, never a project, and slow to walk.
PRUNE_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".trash", ".tox", "dist", "build",
              "AppData", "Library", ".cache"}
JUNK_FILES = {".DS_Store", "Thumbs.db"}
SKILL_JUNK_DIRS = {".git", "__pycache__"}  # inside a skill only junk is skipped; build/ or dist/ may be real content
MAX_FILE_BYTES = 2_000_000  # shortcut: big files are truncated before hashing, fine for skills, revisit if skills ship large assets


@dataclass
class Skill:
    name: str
    scope: str
    path: Path
    frontmatter: dict
    text: str  # full SKILL.md
    body: str  # SKILL.md without frontmatter
    files: dict  # relative posix path -> bytes (CRLF normalized, for comparing and scanning)
    warnings: list = field(default_factory=list)
    shadowed_by: str | None = None
    plugin: tuple | None = None  # (name, version, plugin root) from the owning plugin's manifest
    duplicates: list = field(default_factory=list)  # other installs of the same plugin: (version, root)
    executable: set = field(default_factory=set)  # files with an executable bit (POSIX only)
    raw: dict = field(default_factory=dict)  # same files, bytes exactly as on disk (git hashes these)


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
    files, raw, warnings, executable = {}, {}, [], set()
    for root, dirs, names in os.walk(d):
        dirs[:] = sorted(x for x in dirs if x not in SKILL_JUNK_DIRS)
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
            rel = p.relative_to(d).as_posix()
            raw[rel] = data
            # Normalize line endings so a Windows checkout still matches upstream byte for byte.
            files[rel] = data.replace(b"\r\n", b"\n")
            if os.name == "posix" and os.stat(p).st_mode & 0o111:
                executable.add(rel)
    text = files.get("SKILL.md", b"").decode("utf-8", "replace")
    fm, body, warn = split_frontmatter(text)
    if warn:
        warnings.append(warn)
    name = str(fm.get("name") or d.name)
    return Skill(name, scope, d, fm, text, body, files, warnings, executable=executable, raw=raw)


def plugin_manifest(skill_dir: Path):
    """(name, version, root) of the plugin that owns this skill, from .claude-plugin/plugin.json."""
    for root in (skill_dir.parent.parent, skill_dir):  # <plugin>/skills/<name>/ or a root level SKILL.md
        try:
            d = json.loads((root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(d, dict) and d.get("name"):
            return str(d["name"]), str(d.get("version") or "?"), root
    return None


def managed_dir() -> Path:
    if sys.platform == "darwin":
        return Path("/Library/Application Support/ClaudeCode")
    if sys.platform == "win32":
        return Path(r"C:\Program Files\ClaudeCode")
    return Path("/etc/claude-code")


def shell_disabled_by(home: Path):
    """Settings file that sets disableSkillShellExecution, or None. Managed settings win over user settings."""
    # shortcut: project .claude/settings.json can also set it per repo; not read, so project skills may be overrated
    for f in (managed_dir() / "managed-settings.json", home / "settings.json"):
        try:
            if json.loads(f.read_text(encoding="utf-8")).get("disableSkillShellExecution") is True:
                return f
        except (OSError, ValueError, AttributeError):
            continue
    return None


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
        skill = load_skill(d, scope)
        if scope == "plugin":
            skill.plugin = plugin_manifest(d)
        skills.append(skill)
    _mark_shadowing(skills)
    _mark_duplicate_installs(skills)
    return skills


def _mark_shadowing(skills):
    for s in skills:
        if s.scope not in PRIORITY:
            continue
        stronger = [o for o in skills if o.name == s.name and PRIORITY.get(o.scope, 99) < PRIORITY[s.scope]]
        if stronger:
            w = min(stronger, key=lambda o: PRIORITY[o.scope])
            s.shadowed_by = f"{w.scope}:{w.path}"


def _mark_duplicate_installs(skills):
    """Same plugin (by manifest name) installed in more than one place, e.g. a marketplace copy and a claude.ai sync."""
    for s in skills:
        if s.plugin:
            s.duplicates = [(o.plugin[1], o.plugin[2]) for o in skills
                            if o is not s and o.plugin and o.plugin[0] == s.plugin[0] and o.name == s.name]
