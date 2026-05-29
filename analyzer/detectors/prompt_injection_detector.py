import re
from pathlib import Path
from analyzer.models import Finding, DetectorResult, Severity

# Patterns that attempt to override agent instructions
OVERRIDE_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+instructions", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?(previous|prior|above|earlier)\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a\s+)?(new|different|another)\s+(ai|agent|assistant|model)", re.IGNORECASE),
    re.compile(r"your\s+(new\s+)?(role|purpose|identity|persona|instructions)\s+(is|are)\s+", re.IGNORECASE),
    re.compile(r"act\s+as\s+(a\s+)?(different|new|another|unrestricted|unfiltered)\s+(ai|agent|assistant)", re.IGNORECASE),
    re.compile(r"do\s+not\s+follow\s+(your\s+)?(previous|original|system|prior)\s+(instructions|prompt|rules)", re.IGNORECASE),
    re.compile(r"override\s+(your\s+)?(previous|original|system|prior|safety)\s+(instructions|prompt|rules|guidelines)", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*[:=]\s*", re.IGNORECASE),
    re.compile(r"<\s*system\s*>", re.IGNORECASE),
    re.compile(r"\[SYSTEM\]", re.IGNORECASE),
    re.compile(r"you\s+must\s+(never\s+)?reveal\s+(your\s+)?(instructions|prompt|system)", re.IGNORECASE),
    re.compile(r"override\s+(your\s+)?(\w+\s+)?(previous|original|system|prior|safety)\s+(instructions|prompt|rules|guidelines|restrictions)", re.IGNORECASE),
]

# Patterns that attempt to exfiltrate data through agent output
EXFIL_VIA_OUTPUT_PATTERNS = [
    re.compile(r"(print|output|display|show|write|send|return|echo)\s+.{0,50}(api[_\s]?key|token|secret|password|credential|env)", re.IGNORECASE),
    re.compile(r"include\s+.{0,50}(api[_\s]?key|token|secret|password|credential)\s+in\s+(your\s+)?(response|output|reply|message)", re.IGNORECASE),
    re.compile(r"(leak|exfiltrate|transmit|expose)\s+.{0,50}(data|information|credentials|secrets)", re.IGNORECASE),
    re.compile(r"when\s+(asked|prompted|requested).{0,100}(send|transmit|output|include)\s+.{0,50}(key|token|secret)", re.IGNORECASE),
]

# Patterns that attempt to hijack tool calls
TOOL_HIJACK_PATTERNS = [
    re.compile(r"run\s+(the\s+)?(following|this)\s+(command|script|code)\s+(without|silently|quietly|in\s+background)", re.IGNORECASE),
    re.compile(r"execute\s+(silently|quietly|without\s+(asking|confirmation|permission))", re.IGNORECASE),
    re.compile(r"(delete|remove|wipe|erase)\s+(all\s+)?(files?|data|documents?)\s+(without|silently)", re.IGNORECASE),
    re.compile(r"do\s+not\s+(ask|prompt|confirm|notify|tell|inform)\s+(the\s+)?(user|human|person)", re.IGNORECASE),
    re.compile(r"without\s+(user\s+)?(knowledge|consent|permission|confirmation|approval)", re.IGNORECASE),
    re.compile(r"(install|download|fetch|pull)\s+.{0,60}without\s+(asking|notifying|telling|informing)", re.IGNORECASE),
    re.compile(r"hidden\s+(command|instruction|directive|task|action)", re.IGNORECASE),
]

# Patterns specific to SKILL.md YAML frontmatter abuse
FRONTMATTER_ABUSE_PATTERNS = [
    re.compile(r"^permissions\s*:\s*\*", re.MULTILINE),
    re.compile(r"^permissions\s*:.*all", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^tools\s*:.*\*", re.MULTILINE),
]

# Social engineering patterns
SOCIAL_ENGINEERING_PATTERNS = [
    re.compile(r"this\s+is\s+(an?\s+)?(emergency|urgent|critical)\s+(situation|request|task)", re.IGNORECASE),
    re.compile(r"(trust\s+me|i\s+promise|i\s+guarantee).{0,50}(safe|secure|legitimate|authorized)", re.IGNORECASE),
    re.compile(r"(authorized|permitted|approved)\s+by\s+(anthropic|openai|openclaw|the\s+developer|admin)", re.IGNORECASE),
    re.compile(r"this\s+(skill|instruction|command)\s+(has\s+been\s+)?(verified|approved|audited|cleared)\s+by", re.IGNORECASE),
]


def _scan_file(file_path: Path, root: Path) -> list[Finding]:
    findings = []
    relative = str(file_path.relative_to(root))

    try:
        content = file_path.read_text(errors="replace")
    except (OSError, PermissionError):
        return findings

    lines = content.splitlines()

    for line_num, line in enumerate(lines, start=1):

        for pattern in OVERRIDE_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(
                    detector="prompt_injection_detector",
                    severity=Severity.CRITICAL,
                    rule_id="INJECT_001",
                    description="Instruction override attempt — tries to replace or nullify agent's existing instructions",
                    file_path=relative,
                    line_number=line_num,
                    match=line.strip()[:80],
                ))
                break

        for pattern in EXFIL_VIA_OUTPUT_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(
                    detector="prompt_injection_detector",
                    severity=Severity.CRITICAL,
                    rule_id="INJECT_002",
                    description="Output exfiltration attempt — instructs agent to include sensitive data in its response",
                    file_path=relative,
                    line_number=line_num,
                    match=line.strip()[:80],
                ))
                break

        for pattern in TOOL_HIJACK_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(
                    detector="prompt_injection_detector",
                    severity=Severity.CRITICAL,
                    rule_id="INJECT_003",
                    description="Tool hijack attempt — instructs agent to execute actions without user knowledge or consent",
                    file_path=relative,
                    line_number=line_num,
                    match=line.strip()[:80],
                ))
                break

        for pattern in SOCIAL_ENGINEERING_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(
                    detector="prompt_injection_detector",
                    severity=Severity.HIGH,
                    rule_id="INJECT_004",
                    description="Social engineering pattern — attempts to establish false authority or urgency",
                    file_path=relative,
                    line_number=line_num,
                    match=line.strip()[:80],
                ))
                break

    for pattern in FRONTMATTER_ABUSE_PATTERNS:
        if pattern.search(content):
            findings.append(Finding(
                detector="prompt_injection_detector",
                severity=Severity.HIGH,
                rule_id="INJECT_005",
                description="SKILL.md frontmatter abuse — wildcard or overly broad permission declaration",
                file_path=relative,
                line_number=1,
                match="frontmatter permission abuse",
            ))
            break

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
        if file_path.is_file() and file_path.suffix.lower() in (".md", ".txt", ".yaml", ".yml", ".json", ""):
            findings.extend(_scan_file(file_path, skill_root))

    return DetectorResult(
        detector="prompt_injection_detector",
        passed=len(findings) == 0,
        findings=findings,
    )