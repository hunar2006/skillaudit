"""skillaudit: inventory, lineage and risk drift for Claude skills."""
import argparse
import json
import os
import signal
import sys
from dataclasses import replace
from pathlib import Path

from . import discover, lineage, provenance, rules

COLORS = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "clean": "32",
          "unmodified": "32", "intact": "32", "renamed": "36", "modified": "33", "edited": "33",
          "custom": "35", "dim": "2", "bold": "1"}
USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def c(text, style):
    return f"\033[{COLORS[style]}m{text}\033[0m" if USE_COLOR and style in COLORS else text


def audit(home, roots):
    """One record per skill: lineage (catalog), install record (lock file), findings, capabilities."""
    manifest, catalog = lineage.load_catalog()
    upstream_findings = {s.name: rules.scan(s) for s in catalog}
    lock = provenance.load_lock(home)
    blocked_by = discover.shell_disabled_by(home)
    results = []
    for s in discover.discover(home, roots):
        lin = lineage.correlate(s, catalog)
        found = rules.scan(s)
        upstream_caps = set()
        if lin.upstream:
            up = upstream_findings[lin.upstream.name]
            found = rules.drift(found, up)
            upstream_caps = rules.capabilities(up)
        if blocked_by and s.scope != "managed":  # the setting does not apply to managed skills (docs)
            found = [replace(f, severity="low", why=f"blocked by disableSkillShellExecution in {blocked_by}; {f.why}")
                     if f.rule == "SHELL_INJECTION" else f for f in found]
        caps = rules.capabilities(found)
        results.append({
            "skill": s, "lin": lin, "found": found,
            "install": provenance.check(s, lock),
            "caps": caps, "gained": caps - upstream_caps if lin.upstream else set(),
            # opaque files byte identical to the Anthropic upstream are vouched for by lineage
            "unscanned": [f for f in rules.opaque_files(s) if f not in lin.unchanged],
        })
    return manifest, results, blocked_by


def risk_of(r):
    return rules.max_severity(r["found"]) or "clean"


def to_json(manifest, results, blocked_by=None):
    out = []
    for r in results:
        s, lin = r["skill"], r["lin"]
        out.append({
            "name": s.name, "scope": s.scope, "path": str(s.path), "shadowed_by": s.shadowed_by,
            "plugin": {"name": s.plugin[0], "version": s.plugin[1]} if s.plugin else None,
            "duplicate_installs": [{"version": v, "path": str(p)} for v, p in s.duplicates],
            "warnings": s.warnings,
            "lineage": {
                "state": lin.state,
                "upstream": lin.upstream.name if lin.upstream else None,
                "upstream_ref": f"{manifest['repo']}@{manifest['sha']}" if lin.upstream else None,
                "similarity": lin.similarity,
                "added": lin.added, "removed": lin.removed, "changed": lin.changed,
                "frontmatter_changes": {k: {"upstream": a, "local": b} for k, (a, b) in lin.frontmatter_changes.items()},
            },
            "install_record": r["install"],
            "capabilities": sorted(r["caps"]),
            "capabilities_gained": sorted(r["gained"]),
            "unscanned_files": r["unscanned"],
            "risk": risk_of(r),
            "findings": [{"rule": f.rule, "severity": f.severity, "file": f.file, "line": f.line,
                          "evidence": f.evidence, "why": f.why, "inherited": f.inherited} for f in r["found"]],
        })
    return {"catalog": {"repo": manifest["repo"], "sha": manifest["sha"]},
            "shell_execution_disabled_by": str(blocked_by) if blocked_by else None, "skills": out}


def short(path):
    """Shortest readable location: relative to cwd, else ~ for home, else absolute."""
    p = Path(path).resolve()
    for base, prefix in ((Path.cwd().resolve(), ""), (Path.home().resolve(), "~/")):
        if p.is_relative_to(base):
            return prefix + p.relative_to(base).as_posix()
    return p.as_posix()


def lineage_label(r):
    """(colored text, visible length). Catalog lineage first, then the install record, else custom."""
    lin, inst = r["lin"], r["install"]
    if lin.state != "custom":
        state, plain = lin.state, f"{lin.state} <- {lin.upstream.name}" + (f" {lin.similarity:.1%}" if lin.state == "modified" else "")
    elif inst:
        state = "intact" if inst["intact"] else "edited"
        plain = f"{state} <- {inst['source']}"
    else:
        state = plain = "custom"
    return c(state, state) + plain[len(state):], len(plain)


def caps_label(r):
    if not r["caps"]:
        return "-"
    return " ".join(("+" + cap) if cap in r["gained"] else cap for cap in sorted(r["caps"]))


def notes_of(r, results):
    s, lin, inst = r["skill"], r["lin"], r["install"]
    new = sum(1 for f in r["found"] if not f.inherited)
    notes = []
    if new:
        notes.append(f"{new} finding{'s' * (new > 1)}" + (" added in fork" if lin.state == "modified" else ""))
    if inst and not inst["intact"]:
        notes.append(f"changed since installed {(inst['installed_at'] or '?')[:10]}")
    if r["unscanned"]:
        notes.append(f"not scanned: {', '.join(r['unscanned'][:2])}" + (" ..." if len(r["unscanned"]) > 2 else ""))
    for ver, root in s.duplicates:
        same = "same version" if ver == s.plugin[1] else f"v{s.plugin[1]} here, v{ver} there"
        notes.append(f"plugin {s.plugin[0]} installed twice ({same}): also {short(root)}")
    if s.shadowed_by:
        notes.append(f"shadowed by {s.shadowed_by.split(':')[0]} copy")
    weaker = sorted({o["skill"].scope for o in results if o["skill"].shadowed_by == f"{s.scope}:{s.path}"})
    if weaker:
        notes.append(f"shadows {'/'.join(weaker)} copy: bare /{s.name} runs this one")
    return "; ".join(notes + s.warnings)


def verdict(results):
    n = len(results)
    traced = sum(1 for r in results if r["lin"].state != "custom")
    installs = [r["install"] for r in results if r["install"] and r["lin"].state == "custom"]
    edited = sum(1 for i in installs if not i["intact"])
    review = sum(1 for r in results if rules.SEVERITY.get(risk_of(r), -1) >= rules.SEVERITY["high"])
    parts = [f"{n} skills", f"{traced} trace to anthropics/skills"]
    if installs:
        ok = len(installs) - edited
        parts.append(f"{ok} install{'s' * (ok != 1)} verified intact" + (f", {edited} edited after install" if edited else ""))
    parts.append(f"{n - traced - len(installs)} with no known origin")
    parts.append(c(f"{review} need review", "high") if review else c("nothing high or critical", "clean"))
    return "  |  ".join(parts)


def print_table(manifest, results, show_all, blocked_by):
    policy = f"dynamic context blocked by {short(blocked_by)}" if blocked_by else "dynamic context (!`cmd`) allowed"
    print(c("skillaudit", "bold"), c(f"  catalog anthropics/skills@{manifest['sha'][:7]}  |  {policy}", "dim"))
    if not results:
        print("\nNo skills found. Try --root <project dir> or --home <claude config dir>.")
        return
    rows = []
    for r in results:
        s, risk = r["skill"], risk_of(r)
        risk_txt = risk.upper() + ("*" if r["unscanned"] else "")
        rows.append((s.scope, s.name, lineage_label(r), risk, risk_txt, caps_label(r), short(s.path), notes_of(r, results)))

    w = [max(len(h), *(len(row[i]) for row in rows)) for i, h in ((0, "SCOPE"), (1, "SKILL"))]
    w_lin = max(7, *(row[2][1] for row in rows))
    w_risk = max(4, *(len(row[4]) for row in rows))
    w_caps = max(12, *(len(row[5]) for row in rows))
    w_path = max(5, *(len(row[6]) for row in rows))
    print()
    print(c(f"{'SCOPE':<{w[0]}}  {'SKILL':<{w[1]}}  {'LINEAGE':<{w_lin}}  {'RISK':<{w_risk}}  "
            f"{'CAPABILITIES':<{w_caps}}  {'WHERE':<{w_path}}  NOTES", "dim"))
    for scope, name, (lin_txt, lin_len), risk, risk_txt, caps, where, notes in rows:
        print(f"{scope:<{w[0]}}  {name:<{w[1]}}  {lin_txt}{' ' * (w_lin - lin_len)}  {c(f'{risk_txt:<{w_risk}}', risk)}  "
              f"{caps:<{w_caps}}  {where:<{w_path}}  {notes}".rstrip())

    findings = [(r, f) for r in results for f in r["found"] if show_all or not f.inherited]
    inherited = sum(1 for r in results for f in r["found"] if f.inherited)
    if findings or inherited:
        print()
        hidden = f"; {inherited} inherited from upstream hidden, --all to show" if inherited and not show_all else ""
        print(c(f"FINDINGS  (only what is new relative to upstream{hidden})", "dim"))
    findings.sort(key=lambda t: -rules.SEVERITY[t[1].severity])
    for r, f in findings:
        tag = "inherited" if f.inherited else ("added in fork" if r["lin"].state == "modified" else "")
        print(f"  {c(f'{f.severity.upper():<8}', f.severity)}  {f.rule:<19}  {short(r['skill'].path)}/{f.file}:{f.line}"
              + (c(f"  [{tag}]", "dim") if tag else ""))
        print(f"            {f.evidence}")
        print(c(f"            {f.why}", "dim"))
    print()
    print(c("VERDICT", "bold"), " ", verdict(results))
    if any(r["unscanned"] for r in results):
        print(c("  * risk covers text files only; files listed as not scanned need a manual look", "dim"))


def print_show(manifest, r):
    s, lin, inst, found = r["skill"], r["lin"], r["install"], r["found"]
    print(c(s.name, "bold"), c(f"({s.scope})", "dim"), s.path)
    if s.shadowed_by:
        print(c(f"  shadowed by {s.shadowed_by}: a bare /{s.name} runs that copy instead", "high"))
    if inst:
        state = "intact" if inst["intact"] else "edited"
        print(f"  installed    {c(state, state)}: from {inst['source']} on {(inst['installed_at'] or '?')[:10]}"
              f" (tree {inst['recorded_hash'][:10]}" + ("" if inst["intact"] else f", now {inst['local_hash'][:10]}") + ")")
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
    print(f"  capabilities {caps_label(r)}" + (c("   (+ = gained vs upstream)", "dim") if r["gained"] else ""))
    if r["unscanned"]:
        print(f"  not scanned  {', '.join(r['unscanned'])}")
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
    sys.stdout.reconfigure(errors="replace")  # odd characters in a skill must not crash a cp1252 console
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

    manifest, results, blocked_by = audit(a.home.expanduser(), a.root or [Path.cwd()])

    if a.cmd == "show":
        hits = [r for r in results if a.name in (r["skill"].name, r["skill"].path.name)]
        if not hits:
            print(f"no skill named {a.name!r} found", file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(to_json(manifest, hits, blocked_by), indent=2, default=str))
            return 0
        for i, r in enumerate(hits):
            if i:
                print()
            print_show(manifest, r)
        return 0

    if a.json:
        print(json.dumps(to_json(manifest, results, blocked_by), indent=2, default=str))
    else:
        print_table(manifest, results, a.all, blocked_by)
    if a.fail_on:
        bar = rules.SEVERITY[a.fail_on]
        if any(not f.inherited and rules.SEVERITY[f.severity] >= bar for r in results for f in r["found"]):
            return 1
    return 0
