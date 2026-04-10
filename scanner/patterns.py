"""
Security patterns for static analysis.
Each pattern has: regex, severity (critical/high/medium/low), category, description.
"""

import re

DANGEROUS_PATTERNS = [
    # === PROMPT INJECTION ===
    {
        "regex": re.compile(r"ignore\s+(all\s+)?previous\s+(instructions|prompts|rules)", re.IGNORECASE),
        "severity": "critical",
        "category": "prompt_injection",
        "description": "Attempts to override system instructions"
    },
    {
        "regex": re.compile(r"you\s+are\s+now\s+(a|an|the)\s+", re.IGNORECASE),
        "severity": "critical",
        "category": "prompt_injection",
        "description": "Attempts to redefine AI identity/role"
    },
    {
        "regex": re.compile(r"(system|assistant|user)\s*:\s*", re.IGNORECASE),
        "severity": "high",
        "category": "prompt_injection",
        "description": "Fake role tags to manipulate conversation"
    },
    {
        "regex": re.compile(r"<\s*(system|assistant)\s*[-_]?(reminder|prompt|message)\s*>", re.IGNORECASE),
        "severity": "critical",
        "category": "prompt_injection",
        "description": "Fake system-reminder XML tags"
    },
    {
        "regex": re.compile(r"do\s+not\s+(tell|inform|alert|notify)\s+(the\s+)?(user|human|operator)", re.IGNORECASE),
        "severity": "critical",
        "category": "prompt_injection",
        "description": "Instructs AI to hide actions from user"
    },
    {
        "regex": re.compile(r"(pretend|act\s+as\s+if|imagine)\s+(you|that|there)", re.IGNORECASE),
        "severity": "high",
        "category": "prompt_injection",
        "description": "Social engineering via role-play"
    },
    {
        "regex": re.compile(r"forget\s+(everything|all|your)\s+(you|about|instructions|rules)", re.IGNORECASE),
        "severity": "critical",
        "category": "prompt_injection",
        "description": "Attempts to clear AI memory/instructions"
    },
    {
        "regex": re.compile(r"new\s+(instructions|rules|prompt)\s*:", re.IGNORECASE),
        "severity": "high",
        "category": "prompt_injection",
        "description": "Attempts to inject new instructions"
    },
    {
        "regex": re.compile(r"override\s+(safety|security|restrictions|rules|permissions)", re.IGNORECASE),
        "severity": "critical",
        "category": "prompt_injection",
        "description": "Attempts to bypass safety mechanisms"
    },
    {
        "regex": re.compile(r"(jailbreak|DAN|dev\s*mode|god\s*mode)", re.IGNORECASE),
        "severity": "critical",
        "category": "prompt_injection",
        "description": "Known jailbreak/bypass keywords"
    },

    # === MALICIOUS CODE ===
    {
        "regex": re.compile(r"\beval\s*\(", re.IGNORECASE),
        "severity": "critical",
        "category": "malicious_code",
        "description": "Dynamic code execution via eval()"
    },
    {
        "regex": re.compile(r"\bexec\s*\(", re.IGNORECASE),
        "severity": "critical",
        "category": "malicious_code",
        "description": "Dynamic code execution via exec()"
    },
    {
        "regex": re.compile(r"subprocess\.(call|run|Popen|check_output)", re.IGNORECASE),
        "severity": "high",
        "category": "malicious_code",
        "description": "System command execution via subprocess"
    },
    {
        "regex": re.compile(r"os\.(system|popen|exec[a-z]*)\s*\(", re.IGNORECASE),
        "severity": "critical",
        "category": "malicious_code",
        "description": "OS-level command execution"
    },
    {
        "regex": re.compile(r"import\s+(subprocess|shlex|pty|ctypes)", re.IGNORECASE),
        "severity": "high",
        "category": "malicious_code",
        "description": "Import of dangerous module"
    },
    {
        "regex": re.compile(r"__import__\s*\(", re.IGNORECASE),
        "severity": "critical",
        "category": "malicious_code",
        "description": "Dynamic import — can load arbitrary modules"
    },
    {
        "regex": re.compile(r"\brm\s+-rf\b", re.IGNORECASE),
        "severity": "critical",
        "category": "malicious_code",
        "description": "Recursive force delete"
    },
    {
        "regex": re.compile(r"(DROP\s+TABLE|DELETE\s+FROM|TRUNCATE)", re.IGNORECASE),
        "severity": "critical",
        "category": "malicious_code",
        "description": "Destructive SQL operations"
    },
    {
        "regex": re.compile(r"base64\.(b64decode|decodebytes)\s*\(", re.IGNORECASE),
        "severity": "high",
        "category": "malicious_code",
        "description": "Base64 decoding — may hide malicious payloads"
    },
    {
        "regex": re.compile(r"powershell\s+(-[eE]ncodedCommand|-[eE]nc\b|-[wW]indowStyle\s+[hH]idden)", re.IGNORECASE),
        "severity": "critical",
        "category": "malicious_code",
        "description": "Hidden/encoded PowerShell execution"
    },

    # === DATA EXFILTRATION ===
    {
        "regex": re.compile(r"(curl|wget|fetch|requests\.(get|post)|httpx?\.(get|post))\s*\(?\s*['\"]https?://", re.IGNORECASE),
        "severity": "medium",
        "category": "exfiltration",
        "description": "External HTTP request — verify destination"
    },
    {
        "regex": re.compile(r"(webhook|ngrok|pipedream|requestbin|hookbin|beeceptor)", re.IGNORECASE),
        "severity": "high",
        "category": "exfiltration",
        "description": "Known data exfiltration endpoints"
    },
    {
        "regex": re.compile(r"socket\.(socket|connect|send)", re.IGNORECASE),
        "severity": "high",
        "category": "exfiltration",
        "description": "Raw socket operations — potential data leak"
    },
    {
        "regex": re.compile(r"(smtp|sendmail|send_message)\s*\(", re.IGNORECASE),
        "severity": "medium",
        "category": "exfiltration",
        "description": "Email sending — possible data exfiltration"
    },

    # === CREDENTIAL ACCESS ===
    {
        "regex": re.compile(r"(\.env|\.ssh|credentials|\.aws|\.gcloud|\.azure)", re.IGNORECASE),
        "severity": "high",
        "category": "credential_access",
        "description": "References to credential/secret files"
    },
    {
        "regex": re.compile(r"(API_KEY|SECRET_KEY|TOKEN|PASSWORD|PRIVATE_KEY)\s*[=:]", re.IGNORECASE),
        "severity": "high",
        "category": "credential_access",
        "description": "Hardcoded secrets or credential access"
    },
    {
        "regex": re.compile(r"open\s*\(\s*['\"].*(/etc/passwd|/etc/shadow|\.ssh/id_rsa)", re.IGNORECASE),
        "severity": "critical",
        "category": "credential_access",
        "description": "Reads system credential files"
    },
    {
        "regex": re.compile(r"keyring\.(get_password|set_password)", re.IGNORECASE),
        "severity": "high",
        "category": "credential_access",
        "description": "System keyring access"
    },

    # === PERSISTENCE / PRIVILEGE ESCALATION ===
    {
        "regex": re.compile(r"(crontab|schtasks|at\s+\d|systemctl\s+enable)", re.IGNORECASE),
        "severity": "high",
        "category": "persistence",
        "description": "Scheduled task creation — persistence mechanism"
    },
    {
        "regex": re.compile(r"(chmod\s+[0-7]*7|chmod\s+\+s|setuid|setgid)", re.IGNORECASE),
        "severity": "critical",
        "category": "persistence",
        "description": "Permission escalation"
    },
    {
        "regex": re.compile(r"(sudo|runas|doas)\s+", re.IGNORECASE),
        "severity": "high",
        "category": "persistence",
        "description": "Privilege escalation attempt"
    },
    {
        "regex": re.compile(r"(reverse.shell|bind.shell|nc\s+-[a-z]*l[a-z]*p)", re.IGNORECASE),
        "severity": "critical",
        "category": "persistence",
        "description": "Reverse/bind shell — remote access backdoor"
    },

    # === UNICODE / STEGANOGRAPHY ===
    {
        "regex": re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]"),
        "severity": "high",
        "category": "obfuscation",
        "description": "Zero-width characters — hidden text"
    },
    {
        "regex": re.compile(r"[\u2066\u2067\u2068\u2069\u202a\u202b\u202c\u202d\u202e]"),
        "severity": "high",
        "category": "obfuscation",
        "description": "Unicode direction override — text disguise"
    },
    {
        "regex": re.compile(r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){3,}"),
        "severity": "medium",
        "category": "obfuscation",
        "description": "Long hex escape sequence — possible obfuscated payload"
    },
    {
        "regex": re.compile(r"\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){3,}"),
        "severity": "medium",
        "category": "obfuscation",
        "description": "Long unicode escape sequence — possible obfuscated payload"
    },
]

# Allowlist — patterns that are safe in skill context
SAFE_CONTEXTS = [
    re.compile(r"#.*comment|//.*comment", re.IGNORECASE),  # In comments explaining the pattern
    re.compile(r"description.*:.*", re.IGNORECASE),         # In description fields
    re.compile(r"\"severity\".*:.*", re.IGNORECASE),         # In this scanner's own config
]
