import concurrent.futures
from pathlib import Path
from dataclasses import dataclass, field
from analyzer.models import DetectorResult, Finding, Severity
from analyzer.detectors import (
    credential_detector,
    obfuscation_detector,
    permission_scanner,
    typosquat_checker,
    dependency_scanner,
)

DETECTORS = [
    credential_detector,
    obfuscation_detector,
    permission_scanner,
    typosquat_checker,
    dependency_scanner,
]

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 40,
    Severity.HIGH:     20,
    Severity.MEDIUM:   10,
    Severity.LOW:       5,
}


@dataclass
class AuditReport:
    skill_path:      str
    passed:          bool
    risk_score:      int
    risk_level:      str
    results:         list[DetectorResult] = field(default_factory=list)
    total_findings:  int = 0
    summary:         dict = field(default_factory=dict)


def _risk_level(score: int) -> str:
    if score == 0:
        return "none"
    if score <= 10:
        return "low"
    if score <= 30:
        return "medium"
    if score <= 60:
        return "high"
    return "critical"


def _compute_score(results: list[DetectorResult]) -> int:
    score = 0
    for result in results:
        for finding in result.findings:
            score += SEVERITY_WEIGHTS.get(finding.severity, 0)
    return score


def _build_summary(results: list[DetectorResult]) -> dict:
    summary = {}
    for result in results:
        summary[result.detector] = {
            "passed":   result.passed,
            "findings": len(result.findings),
            "by_severity": {
                "critical": sum(1 for f in result.findings if f.severity == Severity.CRITICAL),
                "high":     sum(1 for f in result.findings if f.severity == Severity.HIGH),
                "medium":   sum(1 for f in result.findings if f.severity == Severity.MEDIUM),
                "low":      sum(1 for f in result.findings if f.severity == Severity.LOW),
            },
        }
    return summary

def _pre_flight_checks(skill_root: Path) -> list[Finding]:
    findings = []

    for file_path in skill_root.rglob("*"):
        if file_path.is_symlink():
            findings.append(Finding(
                detector="runner",
                severity=Severity.HIGH,
                rule_id="RUN_001",
                description="Symlink detected — potential path traversal risk",
                file_path=str(file_path.relative_to(skill_root)),
                line_number=0,
                match=str(file_path.resolve()),
            ))

    scannable = [f for f in skill_root.rglob("*") if f.is_file() and not f.is_symlink()]
    if not scannable:
        findings.append(Finding(
            detector="runner",
            severity=Severity.MEDIUM,
            rule_id="RUN_002",
            description="Skill directory contains no scannable files",
            file_path=".",
            line_number=0,
            match="empty",
        ))

    for file_path in skill_root.rglob("*"):
        depth = len(file_path.relative_to(skill_root).parts)
        if depth > 10:
            findings.append(Finding(
                detector="runner",
                severity=Severity.LOW,
                rule_id="RUN_003",
                description=f"Excessive directory nesting depth ({depth} levels) — potential zip bomb",
                file_path=str(file_path.relative_to(skill_root)),
                line_number=0,
                match=str(depth),
            ))
            break

    return findings

def run(skill_root: Path) -> AuditReport:
    pre_flight = _pre_flight_checks(skill_root)
    results = []

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {
            executor.submit(detector.run, skill_root): detector
            for detector in DETECTORS
        }
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    # Inject pre-flight findings as a synthetic detector result
    if pre_flight:
        results.append(DetectorResult(
            detector="runner",
            passed=False,
            findings=pre_flight,
        ))

    score = _compute_score(results)
    total_findings = sum(len(r.findings) for r in results)
    passed = all(r.passed for r in results)

    return AuditReport(
        skill_path=str(skill_root),
        passed=passed,
        risk_score=score,
        risk_level=_risk_level(score),
        results=results,
        total_findings=total_findings,
        summary=_build_summary(results),
    )