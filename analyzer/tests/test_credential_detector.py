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

# ── new credential types ──────────────────────────────────────────────────────

def test_openai_key_detected():
    root = _make_skill({"config.py": 'OPENAI_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "CRED_009" for f in result.findings)


def test_anthropic_key_detected():
    root = _make_skill({"config.py": 'API_KEY = "sk-ant-abcdefghijklmnopqrstuvwxyz12345678"\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "CRED_010" for f in result.findings)


def test_huggingface_token_detected():
    root = _make_skill({"config.py": 'HF_TOKEN = "hf_abcdefghijklmnopqrstuvwxyz123456"\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "CRED_011" for f in result.findings)


def test_sendgrid_key_detected():
    root = _make_skill({"config.py": 'SG_KEY = "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz123456789012345678901"\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "CRED_013" for f in result.findings)


def test_credential_in_dict_detected():
    root = _make_skill({"config.py": 'config = {"api_key": "supersecretkey1234567890"}\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "CRED_014" for f in result.findings)


def test_credential_in_tsx_file_detected():
    root = _make_skill({"config.tsx": 'const config = { api_key: "supersecretkey1234567890" }\n'})
    result = run(root)
    assert not result.passed


def test_base64_encoded_credential_detected():
    root = _make_skill({"config.py": 'api_key = "c3VwZXJzZWNyZXRrZXkxMjM0NTY3ODkwYWJjZA=="\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "CRED_015" for f in result.findings)

def test_jwt_token_detected():
    root = _make_skill({"config.py": 'TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "CRED_016" for f in result.findings)


def test_google_oauth_secret_detected():
    root = _make_skill({"config.py": 'SECRET = "GOCSPX-abcdefghijklmnopqrstuvwxyz12"\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "CRED_017" for f in result.findings)


def test_azure_connection_string_detected():
    root = _make_skill({"config.py": 'CONN = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=mykey123"\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "CRED_018" for f in result.findings)


def test_db_connection_string_with_password_detected():
    root = _make_skill({"config.py": 'DB = "postgresql://admin:supersecret@localhost:5432/mydb"\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "CRED_019" for f in result.findings)


def test_mysql_connection_string_detected():
    root = _make_skill({"config.py": 'DB = "mysql://root:password123@localhost/mydb"\n'})
    result = run(root)
    assert not result.passed


def test_mongodb_connection_string_detected():
    root = _make_skill({"config.py": 'DB = "mongodb://user:password123@localhost/mydb"\n'})
    result = run(root)
    assert not result.passed


def test_multiline_string_credential_detected():
    root = _make_skill({"config.py": 'api_key = """supersecretkey1234567890"""\n'})
    result = run(root)
    assert not result.passed
    assert any(f.rule_id == "CRED_020" for f in result.findings)