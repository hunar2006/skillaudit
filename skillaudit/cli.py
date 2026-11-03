"""skillaudit: inventory, lineage and risk drift for Claude skills."""
import argparse
import json
import os
import signal
import sys
from pathlib import Path

from . import discover, lineage, rules

COLORS = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "clean": "32",
          "unmodified": "32", "renamed": "36", "modified": "33", "custom": "35", "dim": "2", "bold": "1"}
USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def c(text, style):
    return f"\033[{COLORS[style]}m{text}\033[0m" if USE_COLOR and style in COLORS else text


def audit(home, roots):
    manifest, catalog = lineage.load_catalog()
    by_name = {s.name: s for s in catalog}
    upstream_findings = {s.name: rules.scan(s) for s in catalog}
    results = []
    for s in discover.discover(home, roots):
        lin = lineage.correlate(s, catalog)
        found = rules.scan(s)
        if lin.upstream:
            found = rules.drift(found, upstream_findings[lin.upstream.name])
        results.append((s, lin, found))
    return manifest, results, by_name


def to_json(manifest, results):
    out = []
    for s, lin, found in results:
        out.append({
            "name": s.name, "scope": s.scope, "path": str(s.path), "shadowed_by": s.shadowed_by,
            "warnings": s.warnings,
            "lineage": {
                "state": lin.state,
                "upstream": lin.upstream.name if lin.upstream else None,
                "upstream_ref": f"{manifest['repo']}@{manifest['sha']}" if lin.upstream else None,
                "similarity": lin.similarity,
                "added": lin.added, "removed": lin.removed, "changed": lin.changed,
                "frontmatter_changes": {k: {"upstream": a, "local": b} for k, (a, b) in lin.frontmatter_changes.items()},
            } ,
            "risk": rules.max_severity(found) or "clean",
            "findings": [{"rule": f.rule, "severity": f.severity, "file": f.file, "line": f.line,
                          "evidence": f.evidence, "why": f.why, "inherited": f.inherited} for f in found],
        })
    return {"catalog": {"repo": manifest["repo"], "sha": manifest["sha"]}, "skills": out}


def lineage_label(lin):
    if lin.state == "custom":
        return c("custom", "custom"), len("custom")
    pct = f" {lin.similarity:.1%}" if lin.state == "modified" else ""
    plain = f"{lin.state} <- {lin.upstream.name}{pct}"
    return c(lin.state, lin.state) + plain[len(lin.state):], len(plain)


def print_table(manifest, results, show_all):
    sha = manifest["sha"][:7]
    print(c("skillaudit", "bold"), c(f"  catalog anthropics/skills@{sha}  |  {len(results)} skills found", "dim"))
    if not results:
        print("\nNo skills found. Try --root <project dir> or --home <claude config dir>.")
        return
    rows = []
    for s, lin, found in results:
        risk = rules.max_severity(found) or "clean"
        new = sum(1 for f in found if not f.inherited)
        notes = []
        if new:
            notes.append(f"{new} finding{'s' * (new > 1)}" + (" added in fork" if lin.state == "modified" else ""))
        if s.shadowed_by:
            notes.append(f"shadowed by {s.shadowed_by.split(':')[0]} copy")
        weaker = sorted({o.scope for o, _, _ in results if o.shadowed_by == f"{s.scope}:{s.path}"})
        if weaker:
            notes.append(f"shadows {'/'.join(weaker)} copy: bare /{s.name} runs this one")
        notes += s.warnings
        rows.append((s.scope, s.name, lineage_label(lin), risk, "; ".join(notes)))

    w_scope = max(5, *(len(r[0]) for r in rows))
    w_name = max(5, *(len(r[1]) for r in rows))
    w_lin = max(7, *(r[2][1] for r in rows))
    print()
    print(c(f"{'SCOPE':<{w_scope}}  {'SKILL':<{w_name}}  {'LINEAGE':<{w_lin}}  {'RISK':<8}  NOTES", "dim"))
    for scope, name, (lin_txt, lin_len), risk, notes in rows:
        pad = " " * (w_lin - lin_len)
        print(f"{scope:<{w_scope}}  {name:<{w_name}}  {lin_txt}{pad}  {c(f'{risk.upper():<8}', risk)}  {notes}")

    findings = [(s, lin, f) for s, lin, found in results for f in found if show_all or not f.inherited]
    inherited = sum(1 for _, _, found in results for f in found if f.inherited)
    if findings or inherited:
        print()
        hidden = f"; {inherited} inherited from upstream hidden, --all to show" if inherited and not show_all else ""
        print(c(f"FINDINGS  (only what is new relative to upstream{hidden})", "dim"))
    findings.sort(key=lambda t: -rules.SEVERITY[t[2].severity])
    for s, lin, f in findings:
        tag = "inherited" if f.inherited else ("added in fork" if lin.state == "modified" else "")
        print(f"  {c(f'{f.severity.upper():<8}', f.severity)}  {f.rule:<19}  {s.scope}/{s.name}  {f.file}:{f.line}"
              + (c(f"  [{tag}]", "dim") if tag else ""))
        print(f"            {f.evidence}")
        print(c(f"            {f.why}", "dim"))


def print_show(manifest, s, lin, found):
    print(c(s.name, "bold"), c(f"({s.scope})", "dim"), s.path)
    if s.shadowed_by:
        print(c(f"  shadowed by {s.shadowed_by}: a bare /{s.name} runs that copy instead", "high"))
    if not lin.upstream:
        print(f"  lineage      {c('custom', 'custom')}: no catalog skill is similar enough")
    else:
        print(f"  lineage      {c(lin.state, lin.state)} of {lin.upstream.name} "
              f"@ {manifest['sha'][:7]}  (similarity {lin.similarity:.1%})")
        for rel in lin.added:
            print(c(f"               + {rel}", "clean"))
        for rel in lin.removed:
            print(c(f"               - {rel}", "critical"))
        for rel in lin.changed:
            d = lineage.unified_diff(s, lin.upstream, rel, 0)
            plus = sum(1 for l in d if l.startswith("+") and not l.startswith("+++"))
            minus = sum(1 for l in d if l.startswith("-") and not l.startswith("---"))
            print(c(f"               ~ {rel} (+{plus} -{minus})", "medium"))
        if lin.unchanged:
            print(c(f"               = {len(lin.unchanged)} files unchanged", "dim"))
        for k, (a, b) in lin.frontmatter_changes.items():
            print(f"  frontmatter  {k}: {a if a is not None else '(none)'} -> {b if b is not None else '(removed)'}")
    for f in sorted(found, key=lambda f: (f.inherited, -rules.SEVERITY[f.severity])):
        tag = c("  [inherited]", "dim") if f.inherited else ""
        print(f"  {c(f'{f.severity.upper():<8}', f.severity)}   {f.rule} {f.file}:{f.line}{tag}\n               {f.evidence}")
    if lin.upstream and lin.state == "modified":
        for rel in lin.changed:
            print()
            for l in lineage.unified_diff(s, lin.upstream, rel)[:60]:
                style = "clean" if l.startswith("+") else "critical" if l.startswith("-") else "dim"
                print("  " + c(l, style))


def default_home():
    return Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")


def main(argv=None):
    if hasattr(signal, "SIGPIPE"):  # quiet exit when piped into head/less
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    p = argparse.ArgumentParser(prog="skillaudit", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--home", type=Path, default=default_home(),
                        help="Claude config dir (default: $CLAUDE_CONFIG_DIR or ~/.claude)")
    common.add_argument("--root", action="append", type=Path,
                        help="project dir to search for .claude/skills, repeatable (default: cwd)")
    common.add_argument("--json", action="store_true", help="machine readable output")
    scan_p = sub.add_parser("scan", parents=[common], help="inventory every skill with lineage and findings")
    scan_p.add_argument("--all", action="store_true", help="also list findings inherited from upstream")
    scan_p.add_argument("--fail-on", choices=list(rules.SEVERITY), help="exit 1 if a new finding is this severe or worse")
    show_p = sub.add_parser("show", parents=[common], help="lineage card and diff vs upstream for one skill")
    show_p.add_argument("name")
    sub.add_parser("catalog", help="list the vendored upstream catalog")
    a = p.parse_args(argv)

    if a.cmd == "catalog":
        manifest, catalog = lineage.load_catalog()
        print(f"{manifest['repo']} @ {manifest['sha']}")
        for s in catalog:
            print(f"  {s.name:<24} {len(s.files):>3} files  license: {s.frontmatter.get('license', '?')}")
        return 0

    manifest, results, _ = audit(a.home.expanduser(), a.root or [Path.cwd()])

    if a.cmd == "show":
        hits = [r for r in results if a.name in (r[0].name, r[0].path.name)]
        if not hits:
            print(f"no skill named {a.name!r} found", file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(to_json(manifest, hits), indent=2, default=str))
        for i, r in enumerate(hits if not a.json else []):
            if i:
                print()
            print_show(manifest, *r)
        return 0

    if a.json:
        print(json.dumps(to_json(manifest, results), indent=2, default=str))
    else:
        print_table(manifest, results, a.all)
    if a.fail_on:
        bar = rules.SEVERITY[a.fail_on]
        if any(not f.inherited and rules.SEVERITY[f.severity] >= bar for _, _, found in results for f in found):
            return 1
    return 0
