from dataclasses import dataclass, field
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"

@dataclass
class Finding:
    detector:    str
    severity:    Severity
    rule_id:     str
    description: str
    file_path:   str
    line_number: int
    match:       str

@dataclass
class DetectorResult:
    detector:  str
    passed:    bool
    findings:  list[Finding] = field(default_factory=list)