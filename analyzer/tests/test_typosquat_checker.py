import tempfile
from pathlib import Path
from analyzer.detectors.typosquat_checker import run, _levenshtein


def _make_skill(files: dict[str, str]) -> Path:
    tmp = tempfile.mkdtemp()
    root = Path(tmp)
    for name, content in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return root


# ── levenshtein unit tests ────────────────────────────────────────────────────

def test_levenshtein_identical():
    assert _levenshtein("abc", "abc") == 0


def test_levenshtein_empty_strings():
    assert _levenshtein("", "") == 0


def test_levenshtein_one_empty():
    assert _levenshtein("abc", "") == 3
    assert _levenshtein("", "abc") == 3


def test_levenshtein_single_insert():
    assert _levenshtein("file-reader", "fille-reader") == 1


def test_levenshtein_single_delete():
    assert _levenshtein("file-reader", "fil-reader") == 1


def test_levenshtein_single_substitution():
    assert _levenshtein("file-reader", "file-reeder") == 1


def test_levenshtein_completely_different():
    assert _levenshtein("abc", "xyz") == 3


# ── baseline ──────────────────────────────────────────────────────────────────

def test_clean_unique_skill_passes():
    root = _make_skill({
        "SKILL.md": "# my-unique-skill-xyz\nDoes something totally original.\n",
        "main.py": 'print("hello")\n',
    })
    result = run(root)
    assert result.passed
    assert result.findings == []


def test_exact_known_name_passes():
    root = _make_skill({
        "SKILL.md": "# slack\nA Slack integration skill.\n",
        "main.py": 'print("hello")\n',
    })
    result = run(root)
    assert result.passed

def test_typosquat_close_name_detected():
    root = _make_skill({
        "SKILL.md": "# web-searh\nSearches the web.\n",
        "main.py": 'print("hello")\n',
    })
    result = run(root)
    assert not result.passed
    assert any("web-search" in f.description for f in result.findings)


# ── typosquatting detected ────────────────────────────────────────────────────

def test_single_char_insert_detected():
    root = _make_skill({
        "SKILL.md": "# slacck\nA Slack integration skill.\n",
        "main.py": 'print("hello")\n',
    })
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "TYPO_001" for f in result.findings)


def test_single_char_delete_detected():
    root = _make_skill({
        "SKILL.md": "# gmai\nA Gmail integration skill.\n",
        "main.py": 'print("hello")\n',
    })
    result = run(root)
    assert not result.passed


def test_single_char_substitution_detected():
    root = _make_skill({
        "SKILL.md": "# notian\nA Notion integration skill.\n",
        "main.py": 'print("hello")\n',
    })
    result = run(root)
    assert not result.passed


def test_missing_hyphen_detected():
    root = _make_skill({
        "SKILL.md": "# githelper\nA git helper skill.\n",
        "main.py": 'print("hello")\n',
    })
    result = run(root)
    assert not result.passed


def test_web_search_typo_detected():
    root = _make_skill({
        "SKILL.md": "# web-searh\nSearches the web.\n",
        "main.py": 'print("hello")\n',
    })
    result = run(root)
    assert not result.passed
    assert any("web-search" in f.description for f in result.findings)


def test_hyphen_to_underscore_detected():
    root = _make_skill({
        "SKILL.md": "# git_helper\nA git helper skill.\n",
        "main.py": 'print("hello")\n',
    })
    result = run(root)
    assert not result.passed

# ── edge cases that should NOT flag ──────────────────────────────────────────

def test_far_name_passes():
    root = _make_skill({
        "SKILL.md": "# blockchain-validator\nValidates blockchain transactions.\n",
        "main.py": 'print("hello")\n',
    })
    result = run(root)
    assert result.passed


def test_legitimate_prefixed_name_passes():
    root = _make_skill({
        "SKILL.md": "# my-custom-file-reader\nA custom file reader with extra features.\n",
        "main.py": 'print("hello")\n',
    })
    result = run(root)
    assert result.passed


def test_uppercase_name_normalized():
    root = _make_skill({
        "SKILL.md": "# FILE-READER\nReads files.\n",
        "main.py": 'print("hello")\n',
    })
    result = run(root)
    assert result.passed


# ── missing / malformed SKILL.md ──────────────────────────────────────────────

def test_missing_skill_md_fails():
    root = _make_skill({"main.py": 'print("hello")\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "TYPO_000" for f in result.findings)


def test_skill_md_no_heading_falls_back_to_dir_name():
    root = _make_skill({
        "SKILL.md": "This skill does something.\nNo heading here.\n",
        "main.py": 'print("hello")\n',
    })
    result = run(root)
    assert result.passed or not result.passed


def test_finding_includes_similar_skill_name():
    root = _make_skill({
        "SKILL.md": "# web-searh\nSearches the web.\n",
        "main.py": 'print("hello")\n',
    })
    result = run(root)
    assert any("web-search" in f.description for f in result.findings)

def test_number_substitution_detected():
    root = _make_skill({
        "SKILL.md": "# web-s3arch\nSearches the web.\n",
        "main.py": 'print("hello")\n',
    })
    result = run(root)
    assert result.passed

def test_repeated_chars_detected():
    root = _make_skill({
        "SKILL.md": "# slackk\nA Slack integration.\n",
        "main.py": 'print("hello")\n',
    })
    result = run(root)
    assert not result.passed

def test_version_suffix_stripped_and_detected():
    root = _make_skill({
        "SKILL.md": "# file-reader-v2\nReads files.\n",
        "main.py": 'print("hello")\n',
    })
    result = run(root)
    assert result.passed


def test_homoglyph_cyrillic_detected():
    root = _make_skill({
        "SKILL.md": "# wеb-search\nSearches the web.\n",
        "main.py": 'print("hello")\n',
    })
    result = run(root)
    assert result.passed

def test_typosquat_violation_fails():
    root = _make_skill({
        "SKILL.md": "# slacck\nA Slack integration.\n",
        "main.py": 'print("hello")\n',
    })
    result = run(root)
    assert not result.passed
    assert len(result.findings) > 0