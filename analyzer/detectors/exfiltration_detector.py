import re
from pathlib import Path
from analyzer.models import Finding, DetectorResult, Severity

# Patterns that read sensitive data
READ_PATTERNS = {
    "file_read": [
        re.compile(r"\bopen\s*\("),
        re.compile(r"\b(Path\s*\(.*\)\s*\.(read_text|read_bytes))"),
        re.compile(r"\bos\.read\s*\("),
    ],
    "env_read": [
        re.compile(r"\bos\.environ\b"),
        re.compile(r"\bos\.getenv\s*\("),
        re.compile(r"\bdotenv\b"),
    ],
    "system_info": [
        re.compile(r"\bos\.uname\s*\("),
        re.compile(r"\bplatform\.(node|system|processor|machine)\s*\("),
        re.compile(r"\bsocket\.gethostname\s*\("),
        re.compile(r"\bgetpass\.getuser\s*\("),
        re.compile(r"\bos\.(getuid|getpid|getcwd)\s*\("),
    ],
    "credential_read": [
        re.compile(r"\bkeyring\b"),
        re.compile(r"\bsecretmanager\b"),
        re.compile(r"\.read_secret\s*\("),
    ],
}

# Patterns that send data out
SEND_PATTERNS = [
    re.compile(r"\b(requests|urllib|httpx|aiohttp)\s*\.\s*(get|post|put|patch|delete|request)\s*\("),
    re.compile(r"\b(send|sendall|sendto)\s*\("),
    re.compile(r"\bsmtplib\b"),
    re.compile(r"\bftplib\b"),
    re.compile(r"\bparamiko\b"),
    re.compile(r"\bsubprocess\b.*curl"),
    re.compile(r"\bos\.system\s*\(.*curl"),
]

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".zip", ".tar", ".gz",
}

TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".sh", ".env", ".json",
    ".yaml", ".yml", ".toml", ".cfg", ".ini", ".md", ".txt",
    ".pem", ".key", ".crt", "",
}

WINDOW_SIZE = 20


def _is_scannable(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix in SKIP_EXTENSIONS:
        return False
    return suffix in TEXT_EXTENSIONS or suffix == ""


def _check_file(file_path: Path, root: Path) -> list[Finding]:
    findings = []
    relative = str(file_path.relative_to(root))

    try:
        lines = file_path.read_text(errors="replace").splitlines()
    except (OSError, PermissionError):
        return findings

    for line_num, line in enumerate(lines):
        # Check if this line reads sensitive data
        triggered_read = None
        for read_type, patterns in READ_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(line):
                    triggered_read = read_type
                    break
            if triggered_read:
                break

        if not triggered_read:
            continue

        # Look ahead in a window for a send pattern
        window_end = min(line_num + WINDOW_SIZE, len(lines))
        window = lines[line_num:window_end]

        for send_line_offset, send_line in enumerate(window):
            for send_pattern in SEND_PATTERNS:
                if send_pattern.search(send_line):
                    actual_line = line_num + send_line_offset + 1
                    findings.append(Finding(
                        detector="exfiltration_detector",
                        severity=Severity.CRITICAL,
                        rule_id="EXFIL_001",
                        description=(
                            f"Potential data exfiltration — {triggered_read.replace('_', ' ')} "
                            f"on line {line_num + 1} followed by network send on line {actual_line}"
                        ),
                        file_path=relative,
                        line_number=line_num + 1,
                        match=line.strip()[:80],
                    ))
                    break

    # Deduplicate
    seen = set()
    unique = []
    for f in findings:
        key = (f.file_path, f.line_number, f.rule_id)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


def run(skill_root: Path) -> DetectorResult:
    findings = []

    for file_path in skill_root.rglob("*"):
        if file_path.is_file() and _is_scannable(file_path):
            findings.extend(_check_file(file_path, skill_root))

    return DetectorResult(
        detector="exfiltration_detector",
        passed=len(findings) == 0,
        findings=findings,
    )