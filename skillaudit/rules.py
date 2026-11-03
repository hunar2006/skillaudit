"""Security rules, plus the risk drift step that compares a fork's findings against upstream."""
import re
from dataclasses import dataclass, replace

from .discover import Skill

SEVERITY = {"low": 0, "medium": 1, "high": 2, "critical": 3}
INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩\U000e0000-\U000e007f]")


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    evidence: str
    why: str
    inherited: bool = False  # also present in the upstream skill this one was forked from

    @property
    def key(self):  # line numbers shift in forks, so match on content, not position
        return (self.rule, self.file, self.evidence)


# (rule id, severity, where it applies, pattern, why it matters)
# where: "skill_md" = SKILL.md only, "code" = non markdown files, "text" = every text file
LINE_RULES = [
    ("SHELL_INJECTION", "critical", "skill_md",
     re.compile(r"(?:^|(?<=\s))!`[^`\n]+`|^\s*```!"),
     "dynamic context: Claude Code runs this shell command when the skill loads, before the model sees it"),
    ("DOWNLOAD_EXEC", "critical", "text",
     re.compile(r"\b(curl|wget|iwr|Invoke-WebRequest)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b"
                r"|base64\s+(-d|--decode)[^|\n]*\|\s*(ba|z)?sh\b|\bexec\s*\(.*b64decode", re.I),
     "downloads or decodes code and executes it in one step"),
    ("NETWORK_CALL", "medium", "code",
     re.compile(r"\burllib\.request\.\w+\s*\(|\burlopen\s*\(|\brequests\.(get|post|put|patch)\s*\(|\bhttp\.client\b"
                r"|\bsocket\.socket\s*\(|\bfetch\s*\(\s*['\"]https?://|\b(curl|wget)\s+\S"),
     "script talks to the network"),
    ("PROCESS_SPAWN", "low", "code",
     re.compile(r"\bsubprocess\.(run|Popen|call|check_output)\b|\bos\.system\s*\(|\bchild_process\b|\beval\s*\("),
     "script spawns processes or evaluates code"),
    ("HIDDEN_UNICODE", "high", "text", INVISIBLE,
     "invisible or bidi control characters can hide instructions from a human reviewer"),
]
BROAD_TOOLS = {"Bash", "Bash(*)", "Bash(:*)", "Write", "Edit", "WebFetch"}


def _is_text(data: bytes):
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _show(line: str) -> str:
    line = INVISIBLE.sub(lambda m: f"<U+{ord(m.group()):04X}>", line.strip())
    return line if len(line) <= 110 else line[:107] + "..."


def _line_of(text: str, key: str) -> int:
    for i, l in enumerate(text.splitlines(), 1):
        if l.startswith(key + ":"):
            return i
    return 1


def _tools(value) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value]
    # "Bash(git add *) Read" -> ["Bash(git add *)", "Read"]
    return re.findall(r"[\w.-]+(?:\([^)]*\))?", str(value or ""))


def scan(skill: Skill) -> list[Finding]:
    out = []
    for rel, data in skill.files.items():
        text = _is_text(data)
        if text is None:
            continue
        is_md = rel.lower().endswith(".md")
        for rule, sev, where, pat, why in LINE_RULES:
            if (where == "skill_md" and rel != "SKILL.md") or (where == "code" and is_md):
                continue
            for n, line in enumerate(text.splitlines(), 1):
                if pat.search(line):
                    out.append(Finding(rule, sev, rel, n, _show(line), why))

    fm = skill.frontmatter
    broad = [t for t in _tools(fm.get("allowed-tools")) if t in BROAD_TOOLS]
    if broad:
        out.append(Finding("BROAD_ALLOWED_TOOLS", "high", "SKILL.md", _line_of(skill.text, "allowed-tools"),
                           f"allowed-tools: {' '.join(broad)}",
                           "these tools run without a permission prompt, even in untrusted repos"))
    if fm.get("hooks"):
        out.append(Finding("SKILL_HOOKS", "high", "SKILL.md", _line_of(skill.text, "hooks"),
                           "hooks: " + _show(str(fm["hooks"])),
                           "skill registers lifecycle hooks that run shell commands"))
    return out


def drift(local: list[Finding], upstream: list[Finding]) -> list[Finding]:
    """Mark findings that already exist upstream as inherited, so only what the fork added stands out."""
    base = {f.key for f in upstream}
    return [replace(f, inherited=f.key in base) for f in local]


def max_severity(findings) -> str | None:
    live = [f.severity for f in findings if not f.inherited]
    return max(live, key=SEVERITY.get) if live else None
