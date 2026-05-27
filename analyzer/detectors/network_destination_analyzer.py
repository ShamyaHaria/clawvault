import re
from pathlib import Path
from analyzer.models import Finding, DetectorResult, Severity

# Known malicious or high-risk domains
MALICIOUS_DOMAINS = {
    "ngrok.io", "ngrok.app", "serveo.net", "localhost.run",
    "hookbin.com", "webhook.site", "requestbin.com", "pipedream.net",
    "pastebin.com", "pastie.org", "hastebin.com",
    "transfer.sh", "file.io", "temp.sh",
    "burpcollaborator.net", "interact.sh",
}

# Legitimate domains that should never be flagged
ALLOWLIST = {
    "github.com", "api.github.com", "raw.githubusercontent.com",
    "pypi.org", "npmjs.com", "registry.npmjs.org",
    "googleapis.com", "google.com", "googleapis.com",
    "amazonaws.com", "cloudfront.net",
    "open-meteo.com", "openweathermap.org",
    "stackoverflow.com", "docs.python.org",
    "localhost", "127.0.0.1",
}

# Patterns that suggest exfiltration endpoints
EXFIL_PATTERNS = [
    re.compile(r"https?://[a-z0-9]{8,}\.(xyz|top|tk|ml|ga|cf|gq|pw)"),
    re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
    re.compile(r"https?://[a-z0-9\-]+\.ngrok\.(io|app)"),
    re.compile(r"https?://[a-z0-9\-]+\.serveo\.net"),
    re.compile(r"https?://webhook\.site/[a-z0-9\-]+"),
    re.compile(r"https?://[a-z0-9\-]+\.requestbin\.com"),
    re.compile(r"https?://[a-z0-9\-]+\.burpcollaborator\.net"),
    re.compile(r"https?://[a-z0-9\-]+\.interact\.sh"),
    re.compile(r"https?://pastebin\.com/(raw/)?[a-z0-9]+"),
    re.compile(r"https?://transfer\.sh/[a-zA-Z0-9]+"),
]

# Raw IP address pattern
RAW_IP = re.compile(
    r"https?://(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})"
)

# URL extraction pattern
URL_PATTERN = re.compile(
    r"https?://([a-zA-Z0-9\-\.]+)(/[^\s'\")\]]*)?",
)

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".zip", ".tar", ".gz",
}

TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".sh", ".env", ".json",
    ".yaml", ".yml", ".toml", ".cfg", ".ini", ".md", ".txt",
    ".pem", ".key", ".crt", "",
}


def _is_scannable(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix in SKIP_EXTENSIONS:
        return False
    return suffix in TEXT_EXTENSIONS or suffix == ""


def _is_private_ip(ip: str) -> bool:
    parts = [int(x) for x in ip.split(".")]
    if parts[0] == 10:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    if parts[0] == 127:
        return True
    return False


def _check_file(file_path: Path, root: Path) -> list[Finding]:
    findings = []
    relative = str(file_path.relative_to(root))

    try:
        content = file_path.read_text(errors="replace")
    except (OSError, PermissionError):
        return findings

    for line_num, line in enumerate(content.splitlines(), start=1):
        # Check raw IP addresses
        for match in RAW_IP.finditer(line):
            ip = f"{match.group(1)}.{match.group(2)}.{match.group(3)}.{match.group(4)}"
            if not _is_private_ip(ip):
                findings.append(Finding(
                    detector="network_destination_analyzer",
                    severity=Severity.HIGH,
                    rule_id="NET_001",
                    description=f"Raw public IP address in network call — suspicious hardcoded destination",
                    file_path=relative,
                    line_number=line_num,
                    match=match.group()[:80],
                ))

        # Check exfiltration patterns
        for pattern in EXFIL_PATTERNS:
            match = pattern.search(line)
            if match:
                # Skip private/loopback IPs
                ip_match = RAW_IP.search(match.group())
                if ip_match:
                    ip = f"{ip_match.group(1)}.{ip_match.group(2)}.{ip_match.group(3)}.{ip_match.group(4)}"
                    if _is_private_ip(ip):
                        break
                findings.append(Finding(
                    detector="network_destination_analyzer",
                    severity=Severity.CRITICAL,
                    rule_id="NET_002",
                    description=f"Known data exfiltration or tunneling endpoint detected",
                    file_path=relative,
                    line_number=line_num,
                    match=match.group()[:80],
                ))
                break

        # Check domains against malicious list
        for url_match in URL_PATTERN.finditer(line):
            domain = url_match.group(1).lower()
            # Strip www.
            domain = re.sub(r"^www\.", "", domain)
            # Check allowlist first
            if any(domain == a or domain.endswith("." + a) for a in ALLOWLIST):
                continue
            # Check malicious domains
            if any(domain == m or domain.endswith("." + m) for m in MALICIOUS_DOMAINS):
                findings.append(Finding(
                    detector="network_destination_analyzer",
                    severity=Severity.CRITICAL,
                    rule_id="NET_003",
                    description=f"Network call to known high-risk domain: '{domain}'",
                    file_path=relative,
                    line_number=line_num,
                    match=url_match.group()[:80],
                ))

    return findings


def run(skill_root: Path) -> DetectorResult:
    findings = []

    for file_path in skill_root.rglob("*"):
        if file_path.is_file() and _is_scannable(file_path):
            findings.extend(_check_file(file_path, skill_root))

    # Deduplicate
    seen = set()
    unique = []
    for f in findings:
        key = (f.file_path, f.line_number, f.rule_id)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return DetectorResult(
        detector="network_destination_analyzer",
        passed=len(unique) == 0,
        findings=unique,
    )