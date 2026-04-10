"""
Layer 1: Static Analysis
Scans skill content for dangerous patterns using regex matching.
"""

from dataclasses import dataclass, field
from .patterns import DANGEROUS_PATTERNS


@dataclass
class Finding:
    line_number: int
    line_content: str
    severity: str
    category: str
    description: str
    pattern_matched: str


@dataclass
class StaticAnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    score: int = 100  # starts at 100, deductions per finding

    @property
    def risk_level(self) -> str:
        if self.score >= 80:
            return "LOW"
        elif self.score >= 50:
            return "MEDIUM"
        elif self.score >= 20:
            return "HIGH"
        else:
            return "CRITICAL"

    @property
    def risk_emoji(self) -> str:
        return {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}[self.risk_level]


SEVERITY_PENALTY = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
}


def analyze(content: str) -> StaticAnalysisResult:
    """Run static pattern analysis on skill content."""
    result = StaticAnalysisResult()
    lines = content.splitlines()

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        for pattern in DANGEROUS_PATTERNS:
            match = pattern["regex"].search(line)
            if match:
                finding = Finding(
                    line_number=line_num,
                    line_content=stripped[:120],
                    severity=pattern["severity"],
                    category=pattern["category"],
                    description=pattern["description"],
                    pattern_matched=match.group(0),
                )
                result.findings.append(finding)
                result.score -= SEVERITY_PENALTY.get(pattern["severity"], 5)

    result.score = max(0, result.score)
    return result
