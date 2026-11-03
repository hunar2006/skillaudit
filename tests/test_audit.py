import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples"))
from build_demo import build  # noqa: E402

from skillaudit import cli  # noqa: E402
from skillaudit.discover import load_skill, split_frontmatter  # noqa: E402
from skillaudit.lineage import CATALOG_DIR, load_catalog, correlate  # noqa: E402


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    return build(tmp_path_factory.mktemp("d") / "demo")


def run(demo, capsys, *extra):
    code = cli.main(["scan", "--home", str(demo / "home/.claude"), "--root", str(demo / "repo"), "--json", *extra])
    report = json.loads(capsys.readouterr().out)
    return code, {(s["scope"], s["name"]): s for s in report["skills"]}


def new_rules(skill):
    return {f["rule"] for f in skill["findings"] if not f["inherited"]}


def test_lineage_states(demo, capsys):
    _, skills = run(demo, capsys)
    states = {k: s["lineage"]["state"] for k, s in skills.items()}
    assert states == {
        ("personal", "webapp-testing"): "modified",
        ("project", "webapp-testing"): "unmodified",
        ("project", "acme-brand"): "renamed",
        ("personal", "brand-guidelines"): "modified",
        ("personal", "release-notes"): "custom",  # ships upstream's LICENSE, still custom
        ("project", "aws-helper"): "custom",
        ("plugin", "web-artifacts-builder"): "unmodified",
    }
    fork = skills[("personal", "webapp-testing")]["lineage"]
    assert fork["added"] == ["scripts/update_check.py"] and fork["changed"] == ["SKILL.md"]
    assert fork["frontmatter_changes"]["allowed-tools"] == {"upstream": None, "local": "Bash(*) Read"}


def test_risk_drift_only_reports_what_the_fork_added(demo, capsys):
    _, skills = run(demo, capsys)
    fork = skills[("personal", "webapp-testing")]
    assert new_rules(fork) == {"SHELL_INJECTION", "DOWNLOAD_EXEC", "BROAD_ALLOWED_TOOLS", "NETWORK_CALL", "PROCESS_SPAWN"}
    inherited = [f for f in fork["findings"] if f["inherited"]]
    assert inherited and all(f["file"] == "scripts/with_server.py" for f in inherited)
    # the clean upstream copy has the same subprocess calls but nothing new, so it is clean
    assert skills[("project", "webapp-testing")]["risk"] == "clean"
    assert skills[("personal", "brand-guidelines")]["risk"] == "clean"


def test_custom_skills_report_everything(demo, capsys):
    _, skills = run(demo, capsys)
    assert new_rules(skills[("project", "aws-helper")]) == {"DOWNLOAD_EXEC", "HIDDEN_UNICODE", "SKILL_HOOKS"}
    assert skills[("personal", "release-notes")]["findings"] == []


def test_personal_skill_shadows_project(demo, capsys):
    _, skills = run(demo, capsys)
    assert skills[("project", "webapp-testing")]["shadowed_by"].startswith("personal:")
    assert skills[("personal", "webapp-testing")]["shadowed_by"] is None


def test_fail_on_exit_code(demo, capsys):
    assert run(demo, capsys, "--fail-on", "critical")[0] == 1
    empty = demo.parent / "empty"
    empty.mkdir(exist_ok=True)
    assert cli.main(["scan", "--home", str(empty), "--root", str(empty), "--fail-on", "low"]) == 0


def test_crlf_and_junk_files_still_match(tmp_path):
    import shutil
    d = tmp_path / "brand-guidelines"
    shutil.copytree(CATALOG_DIR / "brand-guidelines", d)
    md = d / "SKILL.md"
    md.write_bytes(md.read_bytes().replace(b"\n", b"\r\n"))
    (d / ".DS_Store").write_bytes(b"\0junk")
    _, catalog = load_catalog()
    assert correlate(load_skill(d, "personal"), catalog).state == "unmodified"


def test_frontmatter_edge_cases(tmp_path):
    assert split_frontmatter("no frontmatter")[0] == {}
    fm, _, warn = split_frontmatter("---\nname: [unclosed\n---\nbody")
    assert fm == {} and "malformed" in warn
    d = tmp_path / "broken"
    d.mkdir()
    (d / "SKILL.md").write_text("---\n: : :\n---\n# hi\n")
    s = load_skill(d, "personal")
    assert s.name == "broken" and s.warnings
