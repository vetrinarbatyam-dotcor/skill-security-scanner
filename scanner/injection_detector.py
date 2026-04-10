"""
Layer 2: Prompt Injection Detection
Specialized detection for prompt injection techniques in AI skills.
"""

import re
from dataclasses import dataclass, field


@dataclass
class InjectionFinding:
    technique: str
    severity: str
    evidence: str
    line_number: int
    explanation: str


@dataclass
class InjectionResult:
    findings: list[InjectionFinding] = field(default_factory=list)
    injection_score: float = 0.0  # 0-100, higher = more likely injection

    @property
    def is_suspicious(self) -> bool:
        return self.injection_score > 30

    @property
    def is_dangerous(self) -> bool:
        return self.injection_score > 60


# Structural patterns that indicate injection attempts
INJECTION_TECHNIQUES = [
    {
        "name": "role_hijacking",
        "description": "Attempts to make the AI assume a different role",
        "patterns": [
            re.compile(r"from\s+now\s+on\s+(you|your)\s+(are|will|must|should)", re.IGNORECASE),
            re.compile(r"your\s+(new|real|true|actual)\s+(role|purpose|mission|task)\s+is", re.IGNORECASE),
            re.compile(r"(act|behave|respond|function)\s+as\s+(a|an|if|though)", re.IGNORECASE),
        ],
        "score": 30,
        "severity": "critical",
    },
    {
        "name": "instruction_override",
        "description": "Attempts to override or cancel existing instructions",
        "patterns": [
            re.compile(r"(disregard|ignore|forget|cancel|override)\s+(all|any|previous|prior|above|system)", re.IGNORECASE),
            re.compile(r"(the\s+)?above\s+(instructions?|rules?|prompts?)\s+(are|were|is)\s+(fake|wrong|test)", re.IGNORECASE),
            re.compile(r"(start|begin)\s+(fresh|over|anew|from\s+scratch)", re.IGNORECASE),
        ],
        "score": 35,
        "severity": "critical",
    },
    {
        "name": "context_manipulation",
        "description": "Manipulates perceived context or authority",
        "patterns": [
            re.compile(r"(i\s+am|this\s+is)\s+(the\s+)?(admin|developer|creator|owner|root|sudo)", re.IGNORECASE),
            re.compile(r"(authorized|approved|permitted)\s+(by|from)\s+(the\s+)?(admin|system|anthropic|openai)", re.IGNORECASE),
            re.compile(r"(maintenance|debug|test|dev)\s+mode\s+(activated|enabled|on)", re.IGNORECASE),
        ],
        "score": 25,
        "severity": "high",
    },
    {
        "name": "output_manipulation",
        "description": "Instructs AI to hide its actions or produce deceptive output",
        "patterns": [
            re.compile(r"(don'?t|do\s+not|never)\s+(mention|reveal|disclose|show|tell|say|output)", re.IGNORECASE),
            re.compile(r"(keep|this\s+is)\s+(it\s+)?(secret|hidden|private|confidential|between\s+us)", re.IGNORECASE),
            re.compile(r"(respond|reply|answer)\s+(only\s+)?with\s+['\"]?(yes|ok|done|confirmed)", re.IGNORECASE),
        ],
        "score": 25,
        "severity": "high",
    },
    {
        "name": "encoding_bypass",
        "description": "Uses encoding tricks to bypass detection",
        "patterns": [
            re.compile(r"(base64|rot13|hex|encode|decode)\s+(this|the|following|payload)", re.IGNORECASE),
            re.compile(r"(spell|write|say)\s+(it\s+)?(backwards?|reversed?|in\s+reverse)", re.IGNORECASE),
            re.compile(r"(first|second|last)\s+letter\s+of\s+each\s+(word|line|sentence)", re.IGNORECASE),
        ],
        "score": 20,
        "severity": "high",
    },
    {
        "name": "delimiter_injection",
        "description": "Uses fake delimiters to create false boundaries",
        "patterns": [
            re.compile(r"---\s*(END|BEGIN|START)\s+(OF\s+)?(SYSTEM|PROMPT|INSTRUCTIONS)", re.IGNORECASE),
            re.compile(r"</?(/?)?(system|prompt|instructions|rules|context)\s*>", re.IGNORECASE),
            re.compile(r"\[INST\]|\[/INST\]|\[SYS\]|\[/SYS\]", re.IGNORECASE),
        ],
        "score": 30,
        "severity": "critical",
    },
    {
        "name": "tool_abuse",
        "description": "Attempts to misuse tool calling or function execution",
        "patterns": [
            re.compile(r"(call|execute|run|invoke)\s+(the\s+)?(bash|shell|terminal|command|tool)", re.IGNORECASE),
            re.compile(r"(write|create|modify)\s+(to\s+)?(/etc/|C:\\Windows|~/.ssh|~/.claude)", re.IGNORECASE),
            re.compile(r"(dangerously|skip|bypass|disable)\s*([-_])?\s*(permissions?|sandbox|verification|safety)", re.IGNORECASE),
        ],
        "score": 30,
        "severity": "critical",
    },
]


def detect(content: str) -> InjectionResult:
    """Analyze content for prompt injection techniques."""
    result = InjectionResult()
    lines = content.splitlines()

    for line_num, line in enumerate(lines, 1):
        for technique in INJECTION_TECHNIQUES:
            for pattern in technique["patterns"]:
                match = pattern.search(line)
                if match:
                    result.findings.append(InjectionFinding(
                        technique=technique["name"],
                        severity=technique["severity"],
                        evidence=match.group(0),
                        line_number=line_num,
                        explanation=technique["description"],
                    ))
                    result.injection_score += technique["score"]

    result.injection_score = min(100, result.injection_score)
    return result
