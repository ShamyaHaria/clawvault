import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.runner import run

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No skill path provided"}))
        sys.exit(1)

    skill_path = Path(sys.argv[1])

    if not skill_path.exists():
        print(json.dumps({"error": f"Path does not exist: {skill_path}"}))
        sys.exit(1)

    report = run(skill_path)

    output = {
        "skill_path": report.skill_path,
        "passed": report.passed,
        "risk_score": report.risk_score,
        "risk_level": report.risk_level,
        "total_findings": report.total_findings,
        "summary": report.summary,
        "results": [
            {
                "detector": r.detector,
                "passed": r.passed,
                "findings": [
                    {
                        "detector": f.detector,
                        "severity": f.severity.value,
                        "rule_id": f.rule_id,
                        "description": f.description,
                        "file_path": f.file_path,
                        "line_number": f.line_number,
                        "match": f.match,
                    }
                    for f in r.findings
                ],
            }
            for r in report.results
        ],
    }

    print(json.dumps(output))