import re
import ast
from pathlib import Path
from analyzer.models import Finding, DetectorResult, Severity


PERMISSION_FLAGS = {
    "network":     ["no network", "no http", "no internet", "no external calls", "offline only"],
    "filesystem":  ["no file", "no disk", "no filesystem", "read only", "no write"],
    "subprocess":  ["no subprocess", "no shell", "no exec", "no system calls"],
    "environment": ["no env", "no environment", "no os.environ", "no secrets"],
}

BEHAVIOR_PATTERNS = {
    "network": [
        re.compile(r"\b(requests|urllib|httpx|aiohttp|fetch|http\.client|socket)\b"),
        re.compile(r"\bopen\s*\(\s*['\"]https?://"),
    ],
    "filesystem": [
        re.compile(r"\bopen\s*\("),
        re.compile(r"\b(os\.remove|os\.unlink|os\.rename|shutil\.(copy|move|rmtree))\b"),
        re.compile(r"\b(Path\s*\(.*\)\s*\.(write|read|unlink|mkdir))\b"),
    ],
    "subprocess": [
        re.compile(r"\b(subprocess|os\.system|os\.popen|os\.popen|commands\.getoutput)\b"),
        re.compile(r"\bPopen\s*\("),
    ],
    "environment": [
        re.compile(r"\bos\.environ\b"),
        re.compile(r"\bos\.getenv\s*\("),
        re.compile(r"\bdotenv\b"),
    ],
}

SKIP_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".zip", ".tar", ".gz"}
TEXT_EXTENSIONS = {".py", ".js", ".ts", ".sh", ".env", ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".md", ".txt", ".pem", ".key", ".crt", ""}


def _is_scannable(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix in SKIP_EXTENSIONS:
        return False
    return suffix in TEXT_EXTENSIONS or suffix == ""


def _parse_declared_restrictions(skill_md: Path) -> set[str]:
    restrictions = set()
    try:
        content = skill_md.read_text(errors="replace").lower()
    except (OSError, PermissionError):
        return restrictions

    for permission, phrases in PERMISSION_FLAGS.items():
        for phrase in phrases:
            if phrase in content:
                restrictions.add(permission)
                break

    return restrictions


def _scan_code_behavior(skill_root: Path) -> dict[str, list[tuple[str, int]]]:
    detected = {key: [] for key in BEHAVIOR_PATTERNS}

    for file_path in skill_root.rglob("*"):
        if not file_path.is_file():
            continue
        if not _is_scannable(file_path):
            continue
        if file_path.name == "SKILL.md":
            continue

        try:
            content = file_path.read_text(errors="replace")
        except (OSError, PermissionError):
            continue

        relative = str(file_path.relative_to(skill_root))

        for line_num, line in enumerate(content.splitlines(), start=1):
            for permission, patterns in BEHAVIOR_PATTERNS.items():
                for pattern in patterns:
                    if pattern.search(line):
                        detected[permission].append((relative, line_num))
                        break

    return detected


def run(skill_root: Path) -> DetectorResult:
    findings = []

    skill_md = skill_root / "SKILL.md"

    if not skill_md.exists():
        findings.append(Finding(
            detector="permission_scanner",
            severity=Severity.HIGH,
            rule_id="PERM_000",
            description="SKILL.md not found — cannot verify declared permissions",
            file_path="SKILL.md",
            line_number=0,
            match="missing",
        ))
        return DetectorResult(
            detector="permission_scanner",
            passed=False,
            findings=findings,
        )

    restrictions = _parse_declared_restrictions(skill_md)
    behavior = _scan_code_behavior(skill_root)

    for permission, locations in behavior.items():
        if permission in restrictions and locations:
            for file_path, line_num in locations:
                findings.append(Finding(
                    detector="permission_scanner",
                    severity=Severity.CRITICAL,
                    rule_id=f"PERM_{permission.upper()[:3]}_001",
                    description=f"Skill declares no {permission} access but code exhibits {permission} behavior",
                    file_path=file_path,
                    line_number=line_num,
                    match=f"undeclared {permission} usage",
                ))

    return DetectorResult(
        detector="permission_scanner",
        passed=len(findings) == 0,
        findings=findings,
    )