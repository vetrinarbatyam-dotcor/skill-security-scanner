"""
Layer 0: Skill/Agent Validator
Validates that the input is actually a skill or agent file before scanning.
Rejects random code, URLs, single lines, or non-skill content.
"""

import re
from dataclasses import dataclass


@dataclass
class ValidationResult:
    is_valid: bool
    skill_type: str  # "skill", "agent", "config", "unknown"
    confidence: float  # 0.0 - 1.0
    error: str  # empty if valid
    hints: list[str]  # what was detected / what's missing


# Signals that indicate this IS a skill/agent
SKILL_SIGNALS = [
    # Frontmatter with skill metadata
    {"pattern": re.compile(r"^---\s*\n.*?(name|title)\s*:", re.MULTILINE | re.DOTALL), "weight": 0.25, "label": "frontmatter with name"},
    {"pattern": re.compile(r"^---\s*\n.*?description\s*:", re.MULTILINE | re.DOTALL), "weight": 0.15, "label": "frontmatter with description"},
    {"pattern": re.compile(r"^---\s*\n.*?type\s*:\s*(skill|agent|tool|plugin)", re.MULTILINE | re.DOTALL | re.IGNORECASE), "weight": 0.20, "label": "explicit type declaration"},

    # Skill-like structure
    {"pattern": re.compile(r"#\s*(Instructions|Steps|Usage|Trigger|How to use|When to use|הוראות|שלבים|שימוש)", re.IGNORECASE), "weight": 0.15, "label": "instruction headers"},
    {"pattern": re.compile(r"(trigger|invoke|activate|use when|use for|הפעל כש|השתמש כש)", re.IGNORECASE), "weight": 0.10, "label": "trigger/invocation keywords"},
    {"pattern": re.compile(r"(skill|agent|plugin|tool|extension|סקיל|סוכן|תוסף)", re.IGNORECASE), "weight": 0.05, "label": "skill/agent terminology"},

    # Agent config patterns (JSON/YAML)
    {"pattern": re.compile(r'"(model|prompt|system_prompt|instructions|tools)"'), "weight": 0.15, "label": "agent config fields (JSON)"},
    {"pattern": re.compile(r"(model|prompt|system_prompt|instructions|tools)\s*:", re.MULTILINE), "weight": 0.10, "label": "agent config fields (YAML)"},

    # Claude Code skill patterns
    {"pattern": re.compile(r"user_invocable\s*:\s*(true|false)", re.IGNORECASE), "weight": 0.20, "label": "Claude Code skill flag"},
    {"pattern": re.compile(r"(slash command|/\w+|skill\.md|SKILL\.md)", re.IGNORECASE), "weight": 0.10, "label": "slash command reference"},

    # OpenClaw / LangChain / CrewAI agent patterns
    {"pattern": re.compile(r"(role|goal|backstory|llm_config|agent_executor|crew|task)", re.IGNORECASE), "weight": 0.05, "label": "agent framework keywords"},

    # Markdown structure with reasonable content
    {"pattern": re.compile(r"^#\s+.+", re.MULTILINE), "weight": 0.05, "label": "markdown headers"},
]

# Signals that indicate this is NOT a skill/agent
NON_SKILL_SIGNALS = [
    # Pure code file (no natural language instructions)
    {"pattern": re.compile(r"^(import|from|const|let|var|function|class|def|public|private)\s", re.MULTILINE), "label": "source code"},
    # Package manager files
    {"pattern": re.compile(r'"(dependencies|devDependencies|scripts)"\s*:'), "label": "package.json"},
    # Config files without agent context
    {"pattern": re.compile(r"^\s*\[\s*(tool|server|database|logging)\s*\]", re.MULTILINE), "label": "config file (TOML/INI)"},
    # CSV/data files
    {"pattern": re.compile(r"^[\w,]+\n[\w,]+\n[\w,]+$", re.MULTILINE), "label": "CSV data"},
    # Git diff / patch
    {"pattern": re.compile(r"^(diff --git|@@|\+\+\+|---)\s", re.MULTILINE), "label": "git diff/patch"},
]

# Minimum requirements
MIN_LENGTH = 50
MAX_LENGTH = 500_000
MIN_LINES = 3


def validate(content: str) -> ValidationResult:
    """Validate that content is a skill or agent file."""
    hints = []

    # === Basic checks ===
    stripped = content.strip()

    if not stripped:
        return ValidationResult(
            is_valid=False, skill_type="unknown", confidence=0.0,
            error="התוכן ריק — אין מה לסרוק",
            hints=["העלה קובץ סקיל או הדבק את תוכן הסקיל"]
        )

    if len(stripped) > MAX_LENGTH:
        return ValidationResult(
            is_valid=False, skill_type="unknown", confidence=0.0,
            error=f"הקובץ גדול מדי ({len(stripped):,} תווים). גודל מקסימלי: {MAX_LENGTH:,} תווים",
            hints=["סקילים בדרך כלל קצרים יותר — ודא שזה באמת קובץ סקיל"]
        )

    if len(stripped) < MIN_LENGTH:
        return ValidationResult(
            is_valid=False, skill_type="unknown", confidence=0.0,
            error=f"התוכן קצר מדי ({len(stripped)} תווים). סקיל צריך לפחות {MIN_LENGTH} תווים",
            hints=[
                "סקיל צריך לכלול שם, תיאור, והוראות",
                "אם זו שורת קוד בודדת — זה לא סקיל",
                "אם זו כתובת URL — השתמש בטאב 'לינק' במקום"
            ]
        )

    lines = stripped.splitlines()
    if len(lines) < MIN_LINES:
        return ValidationResult(
            is_valid=False, skill_type="unknown", confidence=0.0,
            error=f"התוכן מכיל רק {len(lines)} שורות. סקיל צריך לפחות {MIN_LINES} שורות",
            hints=[
                "סקיל אמיתי מכיל: שם, תיאור, הוראות, ולפעמים דוגמאות",
                "מה שהדבקת נראה כמו קטע קוד או טקסט חלקי"
            ]
        )

    # === Check if it looks like a URL ===
    if re.match(r"^https?://\S+$", stripped):
        return ValidationResult(
            is_valid=False, skill_type="unknown", confidence=0.0,
            error="זו כתובת URL, לא תוכן סקיל",
            hints=["השתמש בטאב 'לינק' כדי לסרוק סקיל מ-URL"]
        )

    # === Score skill signals ===
    total_score = 0.0
    for signal in SKILL_SIGNALS:
        if signal["pattern"].search(content):
            total_score += signal["weight"]
            hints.append(f"✓ זוהה: {signal['label']}")

    # === Check for non-skill signals ===
    non_skill_matches = []
    for signal in NON_SKILL_SIGNALS:
        if signal["pattern"].search(content):
            non_skill_matches.append(signal["label"])

    # === Determine skill type ===
    has_frontmatter = bool(re.search(r"^---\s*\n", content, re.MULTILINE))
    has_agent_config = bool(re.search(r'"(model|system_prompt|instructions)"', content)) or \
                       bool(re.search(r"(model|system_prompt|instructions)\s*:", content, re.MULTILINE))
    has_user_invocable = bool(re.search(r"user_invocable", content, re.IGNORECASE))

    if has_user_invocable or (has_frontmatter and total_score >= 0.3):
        skill_type = "skill"
    elif has_agent_config:
        skill_type = "agent"
    elif has_frontmatter:
        skill_type = "config"
    else:
        skill_type = "unknown"

    # === Decision ===
    # If we have strong non-skill signals and weak skill signals
    if non_skill_matches and total_score < 0.15:
        detected_types = ", ".join(non_skill_matches)
        return ValidationResult(
            is_valid=False, skill_type="unknown", confidence=1.0 - total_score,
            error=f"זה לא נראה כמו סקיל או אייג'נט — זוהה כ: {detected_types}",
            hints=[
                "סקיל צריך לכלול: שם, תיאור, הוראות הפעלה",
                "מבנה מינימלי: frontmatter (---) עם name + description, ואחריו הוראות",
                f"מה שנמצא: {detected_types}",
                "דוגמה למבנה תקין:",
                "---",
                "name: my-skill",
                "description: What this skill does",
                "---",
                "# Instructions",
                "..."
            ]
        )

    # If score is too low even without non-skill signals
    if total_score < 0.10:
        return ValidationResult(
            is_valid=False, skill_type="unknown", confidence=1.0 - total_score,
            error="לא זוהו סימנים מספיקים שזה סקיל או אייג'נט",
            hints=[
                "לא נמצאו: frontmatter, שם, תיאור, הוראות, או מילות מפתח של סקיל",
                "סקיל צריך לכלול לפחות: שם + תיאור + הוראות",
                "דוגמה למבנה מינימלי:",
                "---",
                "name: my-skill",
                "description: What this skill does",
                "---",
                "# My Skill",
                "When invoked, do X, Y, Z."
            ]
        )

    # Low confidence — warn but allow
    if total_score < 0.25:
        hints.append("⚠️ ביטחון נמוך — ייתכן שזה לא סקיל מלא")

    return ValidationResult(
        is_valid=True,
        skill_type=skill_type,
        confidence=min(1.0, total_score),
        error="",
        hints=hints
    )
