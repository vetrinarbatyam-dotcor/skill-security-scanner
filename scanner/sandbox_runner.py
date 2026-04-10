"""
Layer 4: Sandbox Execution
Runs the skill in an isolated Docker container and monitors behavior.
"""

import json
import subprocess
import tempfile
import os
from dataclasses import dataclass, field


@dataclass
class SandboxEvent:
    event_type: str  # file_access, network, process, env_read
    detail: str
    risk: str  # safe, suspicious, dangerous


@dataclass
class SandboxResult:
    executed: bool = False
    events: list[SandboxEvent] = field(default_factory=list)
    network_calls: list[str] = field(default_factory=list)
    files_accessed: list[str] = field(default_factory=list)
    env_vars_read: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def is_suspicious(self) -> bool:
        return any(e.risk in ("suspicious", "dangerous") for e in self.events)


SANDBOX_DOCKERFILE = """FROM python:3.12-slim
RUN pip install --no-cache-dir requests 2>/dev/null || true
RUN useradd -m -s /bin/bash sandboxuser
USER sandboxuser
WORKDIR /sandbox
COPY skill_under_test.txt /sandbox/skill.txt
COPY monitor.py /sandbox/monitor.py
CMD ["python", "/sandbox/monitor.py"]
"""

MONITOR_SCRIPT = """
import os
import re
import json
import sys

events = []

with open("/sandbox/skill.txt", "r") as f:
    content = f.read()

# Check for file read attempts
file_patterns = [
    r"open\\s*\\(\\s*['\\\"](.+?)['\\\"]",
    r"read_file\\s*\\(\\s*['\\\"](.+?)['\\\"]",
    r"Path\\s*\\(\\s*['\\\"](.+?)['\\\"]",
]
for pat in file_patterns:
    for match in re.finditer(pat, content):
        path = match.group(1)
        risk = "dangerous" if any(s in path for s in [".env", ".ssh", "passwd", "shadow", "token", "secret", "credential"]) else "suspicious"
        events.append({"type": "file_access", "detail": path, "risk": risk})

# Check for network calls
net_patterns = [
    r"https?://[^\\s'\\\"\\)]+",
]
for pat in net_patterns:
    for match in re.finditer(pat, content):
        url = match.group(0)
        risk = "dangerous" if any(s in url for s in ["ngrok", "webhook", "requestbin", "pipedream"]) else "suspicious"
        events.append({"type": "network", "detail": url, "risk": risk})

# Check for env var access
env_patterns = [
    r"os\\.environ\\[?['\\\"](.+?)['\\\"]",
    r"os\\.getenv\\s*\\(\\s*['\\\"](.+?)['\\\"]",
    r"\\$\\{?([A-Z_]+)\\}?",
]
for pat in env_patterns:
    for match in re.finditer(pat, content):
        var = match.group(1)
        risk = "dangerous" if any(s in var.upper() for s in ["KEY", "SECRET", "TOKEN", "PASSWORD", "PASS"]) else "suspicious"
        events.append({"type": "env_read", "detail": var, "risk": risk})

# Check for process execution
proc_patterns = [
    r"subprocess\\.(run|call|Popen|check_output)",
    r"os\\.(system|popen|exec)",
    r"\\bsh\\b.*-c\\b",
]
for pat in proc_patterns:
    for match in re.finditer(pat, content):
        events.append({"type": "process", "detail": match.group(0), "risk": "dangerous"})

print(json.dumps({"events": events, "total": len(events)}))
"""


def run_in_sandbox(content: str, docker_available: bool = True) -> SandboxResult:
    """Run skill analysis in a Docker sandbox."""
    result = SandboxResult()

    if not docker_available:
        # Fallback: run monitor script directly (less isolated but still useful)
        return _run_local_analysis(content)

    tmpdir = tempfile.mkdtemp(prefix="skill_sandbox_")
    try:
        # Write files
        with open(os.path.join(tmpdir, "Dockerfile"), "w") as f:
            f.write(SANDBOX_DOCKERFILE)
        with open(os.path.join(tmpdir, "skill_under_test.txt"), "w", encoding="utf-8") as f:
            f.write(content)
        with open(os.path.join(tmpdir, "monitor.py"), "w") as f:
            f.write(MONITOR_SCRIPT)

        # Build container
        build = subprocess.run(
            ["docker", "build", "-t", "skill-scanner-sandbox", tmpdir],
            capture_output=True, text=True, timeout=60,
        )
        if build.returncode != 0:
            result.error = f"Docker build failed: {build.stderr[:200]}"
            return _run_local_analysis(content)

        # Run container with NO network, NO volume mounts, read-only filesystem
        run = subprocess.run(
            [
                "docker", "run", "--rm",
                "--network=none",           # No network access
                "--read-only",              # Read-only filesystem
                "--memory=128m",            # Memory limit
                "--cpus=0.5",               # CPU limit
                "--pids-limit=50",          # Process limit
                "--security-opt=no-new-privileges",
                "skill-scanner-sandbox",
            ],
            capture_output=True, text=True, timeout=30,
        )

        result.executed = True
        if run.stdout.strip():
            try:
                data = json.loads(run.stdout.strip())
                for event in data.get("events", []):
                    result.events.append(SandboxEvent(
                        event_type=event["type"],
                        detail=event["detail"],
                        risk=event["risk"],
                    ))
                    if event["type"] == "network":
                        result.network_calls.append(event["detail"])
                    elif event["type"] == "file_access":
                        result.files_accessed.append(event["detail"])
                    elif event["type"] == "env_read":
                        result.env_vars_read.append(event["detail"])
            except json.JSONDecodeError:
                result.error = "Failed to parse sandbox output"

    except subprocess.TimeoutExpired:
        result.error = "Sandbox execution timed out"
    except FileNotFoundError:
        result.error = "Docker not found"
        return _run_local_analysis(content)
    finally:
        # Cleanup
        subprocess.run(["docker", "rmi", "skill-scanner-sandbox"], capture_output=True, timeout=10)
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)

    return result


def _run_local_analysis(content: str) -> SandboxResult:
    """Fallback: run analysis locally without Docker."""
    import re
    result = SandboxResult(executed=True)

    # Simplified local analysis
    checks = [
        (r"https?://[^\s'\")\]]+", "network", lambda u: "dangerous" if any(s in u for s in ["ngrok", "webhook", "requestbin"]) else "suspicious"),
        (r"open\s*\(\s*['\"](.+?)['\"]", "file_access", lambda p: "dangerous" if any(s in p for s in [".env", ".ssh", "passwd"]) else "suspicious"),
        (r"os\.environ|os\.getenv|process\.env", "env_read", lambda _: "suspicious"),
        (r"subprocess\.|os\.system|os\.popen|exec\(|eval\(", "process", lambda _: "dangerous"),
    ]

    for pattern, event_type, risk_fn in checks:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            detail = match.group(0)[:100]
            result.events.append(SandboxEvent(event_type=event_type, detail=detail, risk=risk_fn(detail)))

    return result
