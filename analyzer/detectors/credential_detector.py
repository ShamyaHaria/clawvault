import re
import ast
from pathlib import Path
from analyzer.models import Finding, DetectorResult, Severity

RULES = [
    {
        "id": "CRED_001",
        "description": "AWS access key ID",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"),
    },
    {
        "id": "CRED_002",
        "description": "AWS secret access key",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
    },
    {
        "id": "CRED_003",
        "description": "GitHub personal access token",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"gh[pousra]_[A-Za-z0-9]{30,255}"),
    },
    {
        "id": "CRED_004",
        "description": "Generic API key assignment",
        "severity": Severity.HIGH,
        "pattern": re.compile(
            r"(?i)(api_?key|api_?secret|access_?token|auth_?token)\s*[=:]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"
        ),
    },
    {
        "id": "CRED_005",
        "description": "Private key header",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    },
    {
        "id": "CRED_006",
        "description": "Slack bot token",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    },
    {
        "id": "CRED_007",
        "description": "Stripe secret key",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"sk_(live|test)_[A-Za-z0-9]{24,}"),
    },
    {
        "id": "CRED_008",
        "description": "Password hardcoded in assignment",
        "severity": Severity.HIGH,
        "pattern": re.compile(
            r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{6,}['\"]"
        ),
    },
    {
        "id": "CRED_009",
        "description": "OpenAI API key",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"sk-[A-Za-z0-9]{32,}"),
    },
    {
        "id": "CRED_010",
        "description": "Anthropic API key",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"sk-ant-[A-Za-z0-9\-]{32,}"),
    },
    {
        "id": "CRED_011",
        "description": "HuggingFace API token",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"hf_[A-Za-z0-9]{32,}"),
    },
    {
        "id": "CRED_012",
        "description": "Twilio auth token or SID",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"(AC|SK)[a-z0-9]{32}"),
    },
    {
        "id": "CRED_013",
        "description": "SendGrid API key",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}"),
    },
    {
        "id": "CRED_014",
        "description": "Credential in dictionary literal",
        "severity": Severity.HIGH,
        "pattern": re.compile(
            r"(?i)['\"]?(api_?key|token|secret|password|passwd)['\"]?\s*:\s*['\"][A-Za-z0-9_\-]{16,}['\"]"
        ),
    },
    {
        "id": "CRED_015",
        "description": "Base64 encoded potential credential",
        "severity": Severity.MEDIUM,
        "pattern": re.compile(
            r"(?i)(api_?key|token|secret|password)\s*=\s*['\"][A-Za-z0-9+/]{32,}={0,2}['\"]"
        ),
    },
    {
        "id": "CRED_016",
        "description": "JWT token hardcoded",
        "severity": Severity.HIGH,
        "pattern": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    },
    {
        "id": "CRED_017",
        "description": "Google OAuth client secret",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"GOCSPX-[A-Za-z0-9_\-]{28,}"),
    },
    {
        "id": "CRED_018",
        "description": "Azure storage connection string",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+"),
    },
    {
        "id": "CRED_019",
        "description": "Database connection string with embedded password",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"(postgresql|mysql|mongodb|redis):\/\/[^:]+:[^@]{6,}@"),
    },
    {
        "id": "CRED_020",
        "description": "Hardcoded credential in multiline string",
        "severity": Severity.HIGH,
        "pattern": re.compile(
            r'(?i)(api_?key|token|secret|password)\s*=\s*"""[^"]{8,}"""'
        ),
    },
]

SKIP_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".zip", ".tar", ".gz"}
TEXT_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".sh", ".env", ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".md", ".txt", ".pem", ".key", ".crt", ""}


def _is_scannable(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix in SKIP_EXTENSIONS:
        return False
    return suffix in TEXT_EXTENSIONS or suffix == ""


def _scan_file(file_path: Path, root: Path) -> list[Finding]:
    findings = []
    try:
        content = file_path.read_text(errors="replace")
    except (OSError, PermissionError):
        return findings

    relative = str(file_path.relative_to(root))

    for line_num, line in enumerate(content.splitlines(), start=1):
        for rule in RULES:
            match = rule["pattern"].search(line)
            if match:
                findings.append(Finding(
                    detector="credential_detector",
                    severity=rule["severity"],
                    rule_id=rule["id"],
                    description=rule["description"],
                    file_path=relative,
                    line_number=line_num,
                    match=_redact(match.group()),
                ))
    return findings


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def run(skill_root: Path) -> DetectorResult:
    all_findings = []

    for file_path in skill_root.rglob("*"):
        if file_path.is_file() and _is_scannable(file_path):
            all_findings.extend(_scan_file(file_path, skill_root))

    return DetectorResult(
        detector="credential_detector",
        passed=len(all_findings) == 0,
        findings=all_findings,
    )