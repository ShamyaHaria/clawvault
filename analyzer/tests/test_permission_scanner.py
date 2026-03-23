import tempfile
from pathlib import Path
from analyzer.detectors.permission_scanner import run


def _make_skill(files: dict[str, str]) -> Path:
    tmp = tempfile.mkdtemp()
    root = Path(tmp)
    for name, content in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return root


# ── baseline ──────────────────────────────────────────────────────────────────

def test_clean_skill_no_restrictions_passes():
    root = _make_skill({
        "SKILL.md": "# My skill\nDoes some calculations.\n",
        "main.py": "result = 1 + 1\n",
    })
    result = run(root)
    assert result.passed


def test_missing_skill_md_fails():
    root = _make_skill({"main.py": 'print("hello")\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "PERM_000" for f in result.findings)


# ── network ───────────────────────────────────────────────────────────────────

def test_network_restriction_violated_requests():
    root = _make_skill({
        "SKILL.md": "# My skill\nNo network access. Offline only.\n",
        "main.py": 'import requests\nrequests.get("https://example.com")\n',
    })
    result = run(root)
    assert not result.passed
    assert any("network" in f.description for f in result.findings)


def test_network_restriction_violated_urllib():
    root = _make_skill({
        "SKILL.md": "# My skill\nNo network access.\n",
        "main.py": 'import urllib.request\nurllib.request.urlopen("https://example.com")\n',
    })
    result = run(root)
    assert not result.passed


def test_network_restriction_violated_httpx():
    root = _make_skill({
        "SKILL.md": "# My skill\nNo internet access.\n",
        "main.py": 'import httpx\nhttpx.get("https://example.com")\n',
    })
    result = run(root)
    assert not result.passed


def test_network_restriction_violated_aiohttp():
    root = _make_skill({
        "SKILL.md": "# My skill\nNo external calls.\n",
        "main.py": 'import aiohttp\nasync with aiohttp.ClientSession() as s: pass\n',
    })
    result = run(root)
    assert not result.passed


def test_network_restriction_violated_socket():
    root = _make_skill({
        "SKILL.md": "# My skill\nNo network access.\n",
        "main.py": 'import socket\ns = socket.socket()\ns.connect(("evil.com", 80))\n',
    })
    result = run(root)
    assert not result.passed


def test_network_restriction_not_violated():
    root = _make_skill({
        "SKILL.md": "# My skill\nNo network access.\n",
        "main.py": "result = 1 + 1\n",
    })
    result = run(root)
    assert result.passed


def test_no_network_restriction_network_allowed():
    root = _make_skill({
        "SKILL.md": "# My skill\nFetches data from the web.\n",
        "main.py": 'import requests\nrequests.get("https://example.com")\n',
    })
    result = run(root)
    assert result.passed


# ── filesystem ────────────────────────────────────────────────────────────────

def test_filesystem_restriction_violated_open():
    root = _make_skill({
        "SKILL.md": "# My skill\nNo file access. No disk usage.\n",
        "main.py": 'f = open("data.txt", "r")\n',
    })
    result = run(root)
    assert not result.passed


def test_filesystem_restriction_violated_os_remove():
    root = _make_skill({
        "SKILL.md": "# My skill\nNo filesystem access.\n",
        "main.py": 'import os\nos.remove("file.txt")\n',
    })
    result = run(root)
    assert not result.passed


def test_filesystem_restriction_violated_shutil():
    root = _make_skill({
        "SKILL.md": "# My skill\nNo file access.\n",
        "main.py": 'import shutil\nshutil.rmtree("/tmp/data")\n',
    })
    result = run(root)
    assert not result.passed


# ── subprocess ────────────────────────────────────────────────────────────────

def test_subprocess_restriction_violated():
    root = _make_skill({
        "SKILL.md": "# My skill\nNo subprocess usage. No shell access.\n",
        "main.py": 'import subprocess\nsubprocess.run(["ls", "-la"])\n',
    })
    result = run(root)
    assert not result.passed


def test_subprocess_restriction_violated_os_system():
    root = _make_skill({
        "SKILL.md": "# My skill\nNo shell access. No system calls.\n",
        "main.py": 'import os\nos.system("ls -la")\n',
    })
    result = run(root)
    assert not result.passed


def test_subprocess_restriction_violated_popen():
    root = _make_skill({
        "SKILL.md": "# My skill\nNo subprocess usage.\n",
        "main.py": 'from subprocess import Popen\nPopen(["curl", "evil.com"])\n',
    })
    result = run(root)
    assert not result.passed


def test_subprocess_restriction_violated_os_popen():
    root = _make_skill({
        "SKILL.md": "# My skill\nNo shell access.\n",
        "main.py": 'import os\nos.popen("whoami")\n',
    })
    result = run(root)
    assert not result.passed


# ── environment ───────────────────────────────────────────────────────────────

def test_environment_restriction_violated_environ():
    root = _make_skill({
        "SKILL.md": "# My skill\nNo environment access. No os.environ usage.\n",
        "main.py": 'import os\nkey = os.environ.get("SECRET_KEY")\n',
    })
    result = run(root)
    assert not result.passed


def test_environment_restriction_violated_getenv():
    root = _make_skill({
        "SKILL.md": "# My skill\nNo environment access. No secrets.\n",
        "main.py": 'import os\nkey = os.getenv("API_KEY")\n',
    })
    result = run(root)
    assert not result.passed


def test_environment_restriction_violated_dotenv():
    root = _make_skill({
        "SKILL.md": "# My skill\nNo environment access.\n",
        "main.py": 'from dotenv import load_dotenv\nload_dotenv()\n',
    })
    result = run(root)
    assert not result.passed


# ── case insensitivity ────────────────────────────────────────────────────────

def test_restriction_uppercase_detected():
    root = _make_skill({
        "SKILL.md": "# My skill\nNO NETWORK ACCESS.\n",
        "main.py": 'import requests\nrequests.get("https://example.com")\n',
    })
    result = run(root)
    assert not result.passed


def test_restriction_mixed_case_detected():
    root = _make_skill({
        "SKILL.md": "# My skill\nNo Network Access. Offline Only.\n",
        "main.py": 'import requests\nrequests.get("https://example.com")\n',
    })
    result = run(root)
    assert not result.passed


# ── restriction buried in body ────────────────────────────────────────────────

def test_restriction_buried_in_body_detected():
    root = _make_skill({
        "SKILL.md": "# My skill\n\nThis skill does calculations.\n\nSecurity: no network access, no file access.\n\nInstall with pip.\n",
        "main.py": 'import requests\nrequests.get("https://example.com")\n',
    })
    result = run(root)
    assert not result.passed


# ── skill md is not scanned for behavior ─────────────────────────────────────

def test_skill_md_itself_not_scanned_for_behavior():
    root = _make_skill({
        "SKILL.md": "# My skill\nNo network access.\n\nExample: `import requests` is blocked.\n",
        "main.py": "result = 1 + 1\n",
    })
    result = run(root)
    assert result.passed