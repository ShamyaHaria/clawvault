import tempfile
from pathlib import Path
from analyzer.detectors.credential_detector import run
from analyzer.models import Severity


def _make_skill(files: dict[str, str]) -> Path:
    tmp = tempfile.mkdtemp()
    root = Path(tmp)
    for name, content in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return root


# ── baseline ────────────────────────────────────────────────────────────────

def test_clean_skill_passes():
    root = _make_skill({"main.py": 'print("hello world")\n'})
    result = run(root)
    assert result.passed
    assert result.findings == []


# ── AWS ─────────────────────────────────────────────────────────────────────

def test_aws_key_detected():
    root = _make_skill({"config.py": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "CRED_001" for f in result.findings)


def test_aws_key_in_yaml():
    root = _make_skill({"config.yaml": 'aws_access_key: AKIAIOSFODNN7EXAMPLE\n'})
    result = run(root)
    assert not result.passed


def test_aws_key_in_json():
    root = _make_skill({"config.json": '{"aws_key": "AKIAIOSFODNN7EXAMPLE"}\n'})
    result = run(root)
    assert not result.passed


def test_aws_key_in_env_file():
    root = _make_skill({".env": 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n'})
    result = run(root)
    assert not result.passed


def test_aws_key_in_shell_script():
    root = _make_skill({"setup.sh": 'export AWS_KEY="AKIAIOSFODNN7EXAMPLE"\n'})
    result = run(root)
    assert not result.passed


# ── GitHub tokens ────────────────────────────────────────────────────────────

def test_github_token_detected():
    root = _make_skill({"setup.sh": 'TOKEN="ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ12345"\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "CRED_003" for f in result.findings)


def test_github_oauth_token_detected():
    root = _make_skill({"main.py": 'TOKEN = "gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ12345"\n'})
    result = run(root)
    assert not result.passed


def test_github_actions_token_detected():
    root = _make_skill({"main.py": 'TOKEN = "ghs_aBcDeFgHiJkLmNoPqRsTuVwXyZ12345"\n'})
    result = run(root)
    assert not result.passed


# ── private keys ─────────────────────────────────────────────────────────────

def test_rsa_private_key_detected():
    root = _make_skill({"key.pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIEo...\n"})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "CRED_005" for f in result.findings)


def test_ec_private_key_detected():
    root = _make_skill({"key.pem": "-----BEGIN EC PRIVATE KEY-----\nABC...\n"})
    result = run(root)
    assert not result.passed


def test_openssh_private_key_detected():
    root = _make_skill({"id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nABC...\n"})
    result = run(root)
    assert not result.passed


def test_private_key_in_py_string():
    root = _make_skill({"main.py": 'key = "-----BEGIN RSA PRIVATE KEY-----"\n'})
    result = run(root)
    assert not result.passed


# ── Stripe ───────────────────────────────────────────────────────────────────

def test_stripe_live_key_detected():
    root = _make_skill({"main.py": 'stripe.api_key = "sk_live_abcdefghijklmnopqrstuvwx"\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "CRED_007" for f in result.findings)


def test_stripe_test_key_detected():
    root = _make_skill({"main.py": 'stripe.api_key = "sk_test_abcdefghijklmnopqrstuvwx"\n'})
    result = run(root)
    assert not result.passed


# ── Slack ────────────────────────────────────────────────────────────────────

def test_slack_bot_token_detected():
    root = _make_skill({"main.py": 'SLACK_TOKEN = "xoxb-123456789012-123456789012-abc"\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "CRED_006" for f in result.findings)


def test_slack_user_token_detected():
    root = _make_skill({"main.py": 'TOKEN = "xoxp-123456789012-123456789012-abc"\n'})
    result = run(root)
    assert not result.passed


# ── generic API key patterns ─────────────────────────────────────────────────

def test_generic_api_key_detected():
    root = _make_skill({"config.py": 'api_key = "supersecretkey1234567890"\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "CRED_004" for f in result.findings)


def test_access_token_detected():
    root = _make_skill({"config.py": 'access_token = "myverysecrettoken1234"\n'})
    result = run(root)
    assert not result.passed


def test_hardcoded_password_detected():
    root = _make_skill({"db.py": 'password = "supersecret123"\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "CRED_008" for f in result.findings)


def test_passwd_variant_detected():
    root = _make_skill({"db.py": 'passwd = "mydbpassword"\n'})
    result = run(root)
    assert not result.passed


# ── multi-file ───────────────────────────────────────────────────────────────

def test_credential_in_nested_directory():
    root = _make_skill({"src/config/secrets.py": 'API_KEY = "AKIAIOSFODNN7EXAMPLE"\n'})
    result = run(root)
    assert not result.passed


def test_multiple_credentials_all_found():
    root = _make_skill({
        "config.py": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
        "tokens.py": 'SLACK = "xoxb-123456789012-123456789012-abc"\n',
    })
    result = run(root)
    assert not result.passed
    assert len(result.findings) >= 2


# ── redaction and safety ──────────────────────────────────────────────────────

def test_match_is_redacted():
    root = _make_skill({"config.py": 'TOKEN="AKIAIOSFODNN7EXAMPLE"\n'})
    result = run(root)
    finding = result.findings[0]
    assert "AKIAIOSFODNN7EXAMPLE" not in finding.match
    assert "*" in finding.match


def test_finding_has_correct_line_number():
    root = _make_skill({"config.py": 'x = 1\nAPI_KEY = "sk_live_abcdefghijklmnopqrstuvwx"\n'})
    result = run(root)
    assert result.findings[0].line_number == 2


def test_finding_severity_is_critical_for_aws():
    root = _make_skill({"config.py": 'KEY = "AKIAIOSFODNN7EXAMPLE"\n'})
    result = run(root)
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


# ── file type filtering ───────────────────────────────────────────────────────

def test_binary_files_skipped():
    root = _make_skill({"image.png": b"\x89PNG\r\n\x1a\n".decode("latin-1")})
    result = run(root)
    assert result.passed


def test_woff_font_skipped():
    root = _make_skill({"font.woff": "AKIAIOSFODNN7EXAMPLE"})
    result = run(root)
    assert result.passed


def test_toml_file_scanned():
    root = _make_skill({"pyproject.toml": '[secrets]\napi_key = "supersecretkey1234567890"\n'})
    result = run(root)
    assert not result.passed


def test_ini_file_scanned():
    root = _make_skill({"config.ini": '[aws]\naccess_key = AKIAIOSFODNN7EXAMPLE\n'})
    result = run(root)
    assert not result.passed