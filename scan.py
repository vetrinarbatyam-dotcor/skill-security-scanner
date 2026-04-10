#!/usr/bin/env python3
"""
Skill Security Scanner — CLI
Scans AI skills (Claude Code / OpenClaw) for security risks.

Usage:
    python scan.py <skill_file_or_url>              # Full scan (4 layers)
    python scan.py <skill_file> --quick              # Layers 1+2 only (no LLM, no sandbox)
    python scan.py <skill_file> --no-llm             # Skip LLM review
    python scan.py <skill_file> --no-sandbox         # Skip sandbox
    python scan.py <skill_file> --json               # Output as JSON
    python scan.py <skill_file> --json -o report.json # Save to file
"""

import argparse
import sys
import os
import json
import tempfile

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.skill_validator import validate as skill_validate
from scanner.static_analyzer import analyze as static_analyze
from scanner.injection_detector import detect as injection_detect
from scanner.llm_reviewer import review_with_llm
from scanner.sandbox_runner import run_in_sandbox
from scanner.report import generate_text_report, generate_json_report


def load_content(source: str) -> tuple[str, str]:
    """Load skill content from file path or URL. Returns (content, filename)."""
    if source.startswith("http://") or source.startswith("https://"):
        import urllib.request
        filename = source.split("/")[-1] or "remote_skill"
        req = urllib.request.Request(source, headers={"User-Agent": "SkillSecurityScanner/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read().decode("utf-8")
        return content, filename
    else:
        with open(source, "r", encoding="utf-8") as f:
            content = f.read()
        return content, os.path.basename(source)


def main():
    parser = argparse.ArgumentParser(
        description="Skill Security Scanner — scan AI skills for security risks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scan.py my_skill.md                    # Full scan
  python scan.py my_skill.md --quick            # Fast scan (no LLM/sandbox)
  python scan.py my_skill.md --json -o out.json # JSON report to file
  python scan.py https://raw.github.com/.../skill.md  # Scan from URL
        """,
    )
    parser.add_argument("source", help="Path to skill file or URL")
    parser.add_argument("--quick", action="store_true", help="Quick scan: layers 1+2 only")
    parser.add_argument("--no-llm", action="store_true", help="Skip LLM review (layer 3)")
    parser.add_argument("--no-sandbox", action="store_true", help="Skip sandbox (layer 4)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("-o", "--output", help="Save report to file")
    parser.add_argument("--model", default="claude-sonnet-4-6", help="LLM model for review")

    args = parser.parse_args()

    # Load content
    try:
        content, filename = load_content(args.source)
    except Exception as e:
        print(f"Error loading {args.source}: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"\n🔍 Scanning: {filename} ({len(content)} chars)\n")

    # Layer 0: Validate this is actually a skill/agent
    print("  [0/4] Skill validation...", end=" ", flush=True)
    validation = skill_validate(content)
    if not validation.is_valid:
        print(f"❌ FAILED")
        print(f"\n  ❌ שגיאה: {validation.error}\n")
        for hint in validation.hints:
            print(f"     💡 {hint}")
        print()
        sys.exit(2)
    type_label = {"skill": "סקיל", "agent": "אייג'נט", "config": "קונפיג"}.get(validation.skill_type, "לא ידוע")
    conf_pct = int(validation.confidence * 100)
    print(f"✅ {type_label} (ביטחון: {conf_pct}%)")

    # Layer 1: Static Analysis
    print("  [1/4] Static analysis...", end=" ", flush=True)
    static_result = static_analyze(content)
    print(f"{static_result.risk_emoji} {static_result.risk_level} ({len(static_result.findings)} findings)")

    # Layer 2: Injection Detection
    print("  [2/4] Injection detection...", end=" ", flush=True)
    injection_result = injection_detect(content)
    status = "🔴" if injection_result.is_dangerous else "🟡" if injection_result.is_suspicious else "🟢"
    print(f"{status} Score: {injection_result.injection_score}/100")

    # Layer 3: LLM Review
    if args.quick or args.no_llm:
        print("  [3/4] LLM review... ⏭️  Skipped")
        llm_result = {"overall_risk_score": -1, "summary": "Skipped", "recommendation": "N/A", "findings": []}
    else:
        print("  [3/4] LLM review...", end=" ", flush=True)
        llm_result = review_with_llm(content, model=args.model)
        rec = llm_result.get("recommendation", "?")
        emoji = {"SAFE": "🟢", "REVIEW": "🟡", "REJECT": "🔴"}.get(rec, "❓")
        print(f"{emoji} {rec}")

    # Layer 4: Sandbox
    if args.quick or args.no_sandbox:
        print("  [4/4] Sandbox analysis... ⏭️  Skipped")
        from scanner.sandbox_runner import SandboxResult
        sandbox_result = SandboxResult()
    else:
        print("  [4/4] Sandbox analysis...", end=" ", flush=True)
        sandbox_result = run_in_sandbox(content)
        status = "🔴" if sandbox_result.is_suspicious else "🟢"
        print(f"{status} ({len(sandbox_result.events)} events)")

    # Generate report
    if args.json:
        report = json.dumps(generate_json_report(filename, static_result, injection_result, llm_result, sandbox_result), indent=2, ensure_ascii=False)
    else:
        report = generate_text_report(filename, static_result, injection_result, llm_result, sandbox_result)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"\n📄 Report saved to: {args.output}")
    else:
        print(f"\n{report}")


if __name__ == "__main__":
    main()
