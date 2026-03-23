from pathlib import Path
from analyzer.models import Finding, DetectorResult, Severity


KNOWN_SKILLS = [
    "file-reader", "web-search", "code-runner", "image-analyzer",
    "pdf-parser", "data-visualizer", "markdown-renderer", "csv-processor",
    "json-formatter", "git-helper", "docker-manager", "sql-query",
    "api-tester", "text-summarizer", "language-translator", "math-solver",
    "calendar-manager", "email-composer", "slack-notifier", "github-browser",
]

TYPOSQUAT_THRESHOLD = 2


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)

    matrix = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]

    for i in range(len(a) + 1):
        matrix[i][0] = i
    for j in range(len(b) + 1):
        matrix[0][j] = j

    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            matrix[i][j] = min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + cost,
            )

    return matrix[len(a)][len(b)]


def _extract_skill_name(skill_root: Path) -> str | None:
    skill_md = skill_root / "SKILL.md"
    if not skill_md.exists():
        return None

    try:
        for line in skill_md.read_text(errors="replace").splitlines():
            line = line.strip()
            if line.startswith("#"):
                return line.lstrip("#").strip().lower().replace(" ", "-")
    except (OSError, PermissionError):
        return None

    return skill_root.name.lower()


def run(skill_root: Path) -> DetectorResult:
    findings = []

    skill_name = _extract_skill_name(skill_root)

    if skill_name is None:
        findings.append(Finding(
            detector="typosquat_checker",
            severity=Severity.MEDIUM,
            rule_id="TYPO_000",
            description="Could not determine skill name — SKILL.md missing or has no heading",
            file_path="SKILL.md",
            line_number=0,
            match="unknown",
        ))
        return DetectorResult(
            detector="typosquat_checker",
            passed=False,
            findings=findings,
        )

    for known in KNOWN_SKILLS:
        if skill_name == known:
            break
        distance = _levenshtein(skill_name, known)
        if 0 < distance <= TYPOSQUAT_THRESHOLD:
            findings.append(Finding(
                detector="typosquat_checker",
                severity=Severity.HIGH,
                rule_id="TYPO_001",
                description=f"Skill name '{skill_name}' is suspiciously similar to known skill '{known}' (edit distance {distance})",
                file_path="SKILL.md",
                line_number=1,
                match=skill_name,
            ))

    return DetectorResult(
        detector="typosquat_checker",
        passed=len(findings) == 0,
        findings=findings,
    )