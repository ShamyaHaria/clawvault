import re
from pathlib import Path
from analyzer.models import Finding, DetectorResult, Severity


KNOWN_SKILLS = [
    # productivity
    "gmail", "slack", "notion", "calendar", "email-manager",
    "ms-todo", "postfast", "publora", "clipboard", "personal-plans",
    # development
    "github", "git-helper", "code-reviewer", "test-generator",
    "neo-github-readme-generator", "claude-usage", "cli-worker",
    # data and documents
    "pdf-parser", "md2pdf-converter", "ai-pdf-builder", "csv-processor",
    "json-formatter", "beautiful-mermaid", "ppt-ooxml-tool",
    # devops and cloud
    "docker-manager", "elasticsearch-skill", "email-processor",
    "encrypted-docs", "expanso-pii-redact", "expanso-text-summarize",
    # ai and agents
    "human-like-memory", "hivemind", "hyperstack", "agent-soul-crafter",
    "deepclaw", "openclaws",
    # utilities
    "web-search", "image-analyzer", "language-translator", "math-solver",
    "weather-fetcher", "apikiss", "fd-find", "clipboard",
    # security
    "agent-skills-tools",
]

TYPOSQUAT_THRESHOLD = 2

HOMOGLYPH_MAP = {
    ord('а'): 'a', ord('е'): 'e', ord('о'): 'o', ord('р'): 'p', ord('с'): 'c',
    ord('х'): 'x', ord('ᵉ'): 'e', ord('ℯ'): 'e', ord('０'): '0', ord('１'): '1',
    ord('２'): '2', ord('３'): '3', ord('４'): '4', ord('５'): '5',
}

NUMBER_SUB = str.maketrans('013456789', 'oieassszg')

VERSION_SUFFIX = re.compile(r'[-_]?v?\d+[-_]?$')


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


def _normalize(name: str) -> str:
    name = name.lower()
    name = name.translate(HOMOGLYPH_MAP)
    return name


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


def _get_candidates(skill_name: str) -> list[str]:
    normalized = _normalize(skill_name)
    stripped = VERSION_SUFFIX.sub('', normalized).rstrip('-_')
    number_normalized = normalized.translate(NUMBER_SUB)
    candidates = [normalized]
    if stripped and stripped != normalized:
        candidates.append(stripped)
    if number_normalized != normalized:
        candidates.append(number_normalized)
    return candidates


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

    candidates = _get_candidates(skill_name)
    seen_known: set = set()

    for known in KNOWN_SKILLS:
        # Skip if any candidate is an exact match
        if any(c == known for c in candidates):
            continue

        for candidate in candidates:
            distance = _levenshtein(candidate, known)
            if 0 < distance <= TYPOSQUAT_THRESHOLD and known not in seen_known:
                seen_known.add(known)
                findings.append(Finding(
                    detector="typosquat_checker",
                    severity=Severity.HIGH,
                    rule_id="TYPO_001",
                    description=f"Skill name '{skill_name}' is suspiciously similar to known skill '{known}' (edit distance {distance})",
                    file_path="SKILL.md",
                    line_number=1,
                    match=skill_name,
                ))
                break

    return DetectorResult(
        detector="typosquat_checker",
        passed=len(findings) == 0,
        findings=findings,
    )
