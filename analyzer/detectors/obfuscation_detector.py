import re
import ast
from pathlib import Path
from analyzer.models import Finding, DetectorResult, Severity

REGEX_RULES = [
    {
        "id": "OBFS_001",
        "description": "Dynamic eval() call",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"\beval\s*\("),
    },
    {
        "id": "OBFS_001b",
        "description": "Shell eval call",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r'\beval\s+["\$`]'),
    },
    {
        "id": "OBFS_002",
        "description": "Dynamic exec() call",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"\bexec\s*\("),
    },
    {
        "id": "OBFS_003",
        "description": "Base64 decode call",
        "severity": Severity.HIGH,
        "pattern": re.compile(r"base64\s*\.\s*(b64decode|decodebytes|decodestring)\s*\("),
    },
    {
        "id": "OBFS_004",
        "description": "Dynamic __import__ call",
        "severity": Severity.HIGH,
        "pattern": re.compile(r"__import__\s*\("),
    },
    {
        "id": "OBFS_005",
        "description": "compile() used with exec()",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"compile\s*\(.*exec", re.DOTALL),
    },
    {
        "id": "OBFS_006",
        "description": "Suspicious long encoded string literal",
        "severity": Severity.MEDIUM,
        "pattern": re.compile(r"['\"][A-Za-z0-9+/=]{200,}['\"]"),
    },
    {
        "id": "OBFS_007",
        "description": "importlib dynamic import",
        "severity": Severity.HIGH,
        "pattern": re.compile(r"importlib\s*\.\s*import_module\s*\("),
    },
    {
        "id": "OBFS_008",
        "description": "compile() call",
        "severity": Severity.HIGH,
        "pattern": re.compile(r"\bcompile\s*\("),
    },
    {
        "id": "OBFS_009",
        "description": "getattr builtins eval evasion",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"getattr\s*\(\s*__builtins__"),
    },
    {
        "id": "OBFS_010",
        "description": "builtins dict eval evasion",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r'__builtins__\s*\['),
    },
    {
        "id": "OBFS_011",
        "description": "hex-encoded string obfuscation",
        "severity": Severity.HIGH,
        "pattern": re.compile(r'(\\x[0-9a-fA-F]{2}){6,}'),
    },
    {
        "id": "OBFS_012",
        "description": "JavaScript Function constructor evasion",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"new\s+Function\s*\("),
    },
    {
        "id": "OBFS_013",
        "description": "JavaScript setTimeout with string argument",
        "severity": Severity.HIGH,
        "pattern": re.compile(r'setTimeout\s*\(\s*["\']'),
    },
    {
        "id": "OBFS_014",
        "description": "Shell base64 decode pipe to shell",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"base64\s+--decode.*\|\s*(sh|bash|zsh)"),
    },
]

SKIP_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".zip", ".tar", ".gz"}
TEXT_EXTENSIONS = {".py", ".js", ".ts", ".sh", ".env", ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".md", ".txt", ".pem", ".key", ".crt", ""}


def _is_scannable(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix in SKIP_EXTENSIONS:
        return False
    return suffix in TEXT_EXTENSIONS or suffix == ""


def _check_ast(file_path: Path, root: Path) -> list[Finding]:
    findings = []
    if file_path.suffix.lower() != ".py":
        return findings

    relative = str(file_path.relative_to(root))

    try:
        source = file_path.read_text(errors="replace")
        tree = ast.parse(source)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func

            if isinstance(func, ast.Name) and func.id in ("eval", "exec"):
                findings.append(Finding(
                    detector="obfuscation_detector",
                    severity=Severity.CRITICAL,
                    rule_id="OBFS_AST_001",
                    description=f"AST confirmed: {func.id}() call",
                    file_path=relative,
                    line_number=node.lineno,
                    match=f"{func.id}(...)",
                ))

            if isinstance(func, ast.Name) and func.id == "__import__":
                findings.append(Finding(
                    detector="obfuscation_detector",
                    severity=Severity.HIGH,
                    rule_id="OBFS_AST_002",
                    description="AST confirmed: dynamic __import__() call",
                    file_path=relative,
                    line_number=node.lineno,
                    match="__import__(...)",
                ))

            if isinstance(func, ast.Attribute) and func.attr in ("b64decode", "decodebytes"):
                findings.append(Finding(
                    detector="obfuscation_detector",
                    severity=Severity.HIGH,
                    rule_id="OBFS_AST_003",
                    description=f"AST confirmed: base64.{func.attr}() call",
                    file_path=relative,
                    line_number=node.lineno,
                    match=f"base64.{func.attr}(...)",
                ))

    return findings


def _scan_file(file_path: Path, root: Path) -> list[Finding]:
    findings = []
    try:
        content = file_path.read_text(errors="replace")
    except (OSError, PermissionError):
        return findings

    relative = str(file_path.relative_to(root))

    for line_num, line in enumerate(content.splitlines(), start=1):
        for rule in REGEX_RULES:
            match = rule["pattern"].search(line)
            if match:
                findings.append(Finding(
                    detector="obfuscation_detector",
                    severity=rule["severity"],
                    rule_id=rule["id"],
                    description=rule["description"],
                    file_path=relative,
                    line_number=line_num,
                    match=match.group()[:80],
                ))

    return findings


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    seen = set()
    unique = []
    for f in findings:
        key = (f.file_path, f.line_number, f.rule_id)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def run(skill_root: Path) -> DetectorResult:
    all_findings = []

    for file_path in skill_root.rglob("*"):
        if file_path.is_file() and _is_scannable(file_path):
            all_findings.extend(_scan_file(file_path, skill_root))
            all_findings.extend(_check_ast(file_path, skill_root))

    all_findings = _deduplicate(all_findings)

    return DetectorResult(
        detector="obfuscation_detector",
        passed=len(all_findings) == 0,
        findings=all_findings,
    )