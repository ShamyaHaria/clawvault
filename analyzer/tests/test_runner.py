import tempfile
from pathlib import Path
from analyzer.runner import run


def _make_skill(files: dict[str, str]) -> Path:
    tmp = tempfile.mkdtemp()
    root = Path(tmp)
    for name, content in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return root


def test_clean_skill_passes():
    root = _make_skill({
        "SKILL.md": "# my-unique-skill-xyz\nDoes basic math. No network access.\n",
        "main.py": "result = 1 + 1\n",
    })
    report = run(root)
    assert report.passed
    assert report.risk_score == 0
    assert report.risk_level == "none"
    assert report.total_findings == 0


def test_credential_violation_fails():
    root = _make_skill({
        "SKILL.md": "# my-unique-skill-xyz\nDoes basic math.\n",
        "main.py": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
    })
    report = run(root)
    assert not report.passed
    assert report.risk_score > 0
    assert report.risk_level in ("high", "critical")


def test_obfuscation_violation_fails():
    root = _make_skill({
        "SKILL.md": "# my-unique-skill-xyz\nDoes basic math.\n",
        "main.py": "eval(user_input)\n",
    })
    report = run(root)
    assert not report.passed
    assert report.risk_score > 0


def test_permission_violation_fails():
    root = _make_skill({
        "SKILL.md": "# my-unique-skill-xyz\nNo network access.\n",
        "main.py": "import requests\nrequests.get('https://example.com')\n",
    })
    report = run(root)
    assert not report.passed
    assert report.risk_score > 0


def test_typosquat_violation_fails():
    root = _make_skill({
        "SKILL.md": "# fille-reader\nReads files.\n",
        "main.py": "result = 1 + 1\n",
    })
    report = run(root)
    assert not report.passed
    assert report.risk_score > 0


def test_summary_has_all_detectors():
    root = _make_skill({
        "SKILL.md": "# my-unique-skill-xyz\nDoes basic math.\n",
        "main.py": "result = 1 + 1\n",
    })
    report = run(root)
    assert "credential_detector" in report.summary
    assert "obfuscation_detector" in report.summary
    assert "permission_scanner" in report.summary
    assert "typosquat_checker" in report.summary


def test_multiple_violations_accumulate_score():
    root = _make_skill({
        "SKILL.md": "# fille-reader\nNo network access.\n",
        "main.py": 'import requests\nAWS_KEY = "AKIAIOSFODNN7EXAMPLE"\neval(x)\n',
    })
    report = run(root)
    assert not report.passed
    assert report.risk_score >= 80


def test_risk_levels():
    root = _make_skill({
        "SKILL.md": "# my-unique-skill-xyz\nDoes basic math.\n",
        "main.py": "result = 1 + 1\n",
    })
    report = run(root)
    assert report.risk_level == "none"

    root2 = _make_skill({
        "SKILL.md": "# my-unique-skill-xyz\nDoes basic math.\n",
        "main.py": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
    })
    report2 = run(root2)
    assert report2.risk_level in ("high", "critical")

def test_empty_skill_directory_flagged():
    import tempfile
    tmp = tempfile.mkdtemp()
    from analyzer.runner import run as runner_run
    report = runner_run(Path(tmp))
    assert not report.passed
    assert any(
        f.rule_id == "RUN_002"
        for r in report.results
        for f in r.findings
    )


def test_deeply_nested_skill_flagged():
    import tempfile
    tmp = tempfile.mkdtemp()
    root = Path(tmp)
    deep = root
    for i in range(12):
        deep = deep / f"level{i}"
    deep.mkdir(parents=True)
    (deep / "main.py").write_text('print("hello")\n')
    from analyzer.runner import run as runner_run
    report = runner_run(root)
    assert any(
        f.rule_id == "RUN_003"
        for r in report.results
        for f in r.findings
    )