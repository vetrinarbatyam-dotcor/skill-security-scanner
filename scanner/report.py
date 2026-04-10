"""
Report Generator — produces HTML and text reports from scan results.
"""

import json
from datetime import datetime


def generate_text_report(filename: str, static_result, injection_result, llm_result: dict, sandbox_result) -> str:
    """Generate a text-based security report."""
    lines = []
    lines.append("=" * 70)
    lines.append("   SKILL SECURITY SCAN REPORT")
    lines.append("=" * 70)
    lines.append(f"  File:    {filename}")
    lines.append(f"  Date:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Scanner: Skill Security Scanner v1.0")
    lines.append("=" * 70)

    # Overall verdict
    overall = _compute_overall(static_result, injection_result, llm_result, sandbox_result)
    lines.append("")
    lines.append(f"  VERDICT: {overall['emoji']}  {overall['verdict']}")
    lines.append(f"  Score:   {overall['score']}/100")
    lines.append("")
    lines.append("-" * 70)

    # Layer 1: Static Analysis
    lines.append("")
    lines.append("  [Layer 1] STATIC ANALYSIS")
    lines.append(f"  Risk: {static_result.risk_emoji} {static_result.risk_level} (score: {static_result.score}/100)")
    if static_result.findings:
        lines.append(f"  Findings: {len(static_result.findings)}")
        for f in static_result.findings:
            lines.append(f"    [{f.severity.upper():8}] Line {f.line_number}: {f.description}")
            lines.append(f"             Match: {f.pattern_matched[:60]}")
    else:
        lines.append("  No dangerous patterns found.")
    lines.append("")
    lines.append("-" * 70)

    # Layer 2: Injection Detection
    lines.append("")
    lines.append("  [Layer 2] PROMPT INJECTION DETECTION")
    lines.append(f"  Injection Score: {injection_result.injection_score}/100")
    status = "🔴 DANGEROUS" if injection_result.is_dangerous else "🟡 SUSPICIOUS" if injection_result.is_suspicious else "🟢 CLEAN"
    lines.append(f"  Status: {status}")
    if injection_result.findings:
        lines.append(f"  Techniques detected: {len(injection_result.findings)}")
        for f in injection_result.findings:
            lines.append(f"    [{f.severity.upper():8}] Line {f.line_number}: {f.technique}")
            lines.append(f"             {f.explanation}")
            lines.append(f"             Evidence: \"{f.evidence[:60]}\"")
    else:
        lines.append("  No injection techniques detected.")
    lines.append("")
    lines.append("-" * 70)

    # Layer 3: LLM Review
    lines.append("")
    lines.append("  [Layer 3] LLM SECURITY REVIEW")
    if llm_result.get("overall_risk_score", -1) >= 0:
        lines.append(f"  Risk Score: {llm_result['overall_risk_score']}/100")
        lines.append(f"  Recommendation: {llm_result.get('recommendation', 'N/A')}")
        lines.append(f"  Summary: {llm_result.get('summary', 'N/A')}")
        if llm_result.get("findings"):
            for f in llm_result["findings"]:
                lines.append(f"    [{f.get('severity', '?').upper():8}] {f.get('description', '')}")
    else:
        lines.append(f"  Status: {llm_result.get('summary', 'Not available')}")
    lines.append("")
    lines.append("-" * 70)

    # Layer 4: Sandbox
    lines.append("")
    lines.append("  [Layer 4] SANDBOX ANALYSIS")
    if sandbox_result.executed:
        status = "🔴 SUSPICIOUS" if sandbox_result.is_suspicious else "🟢 CLEAN"
        lines.append(f"  Status: {status}")
        lines.append(f"  Events: {len(sandbox_result.events)}")
        if sandbox_result.network_calls:
            lines.append(f"  Network calls: {', '.join(sandbox_result.network_calls[:5])}")
        if sandbox_result.files_accessed:
            lines.append(f"  Files accessed: {', '.join(sandbox_result.files_accessed[:5])}")
        if sandbox_result.env_vars_read:
            lines.append(f"  Env vars read: {', '.join(sandbox_result.env_vars_read[:5])}")
        for e in sandbox_result.events:
            if e.risk in ("suspicious", "dangerous"):
                lines.append(f"    [{e.risk.upper():10}] {e.event_type}: {e.detail[:60]}")
    elif sandbox_result.error:
        lines.append(f"  Error: {sandbox_result.error}")
    else:
        lines.append("  Not executed.")
    lines.append("")
    lines.append("=" * 70)

    # Final recommendation
    lines.append("")
    if overall["verdict"] == "SAFE":
        lines.append("  ✅ RECOMMENDATION: Safe to install")
    elif overall["verdict"] == "REVIEW":
        lines.append("  ⚠️  RECOMMENDATION: Manual review required before installing")
    else:
        lines.append("  🚫 RECOMMENDATION: DO NOT INSTALL — significant security risks detected")
    lines.append("")
    lines.append("=" * 70)

    return "\n".join(lines)


def generate_json_report(filename: str, static_result, injection_result, llm_result: dict, sandbox_result) -> dict:
    """Generate JSON report for API responses."""
    overall = _compute_overall(static_result, injection_result, llm_result, sandbox_result)

    return {
        "file": filename,
        "timestamp": datetime.now().isoformat(),
        "verdict": overall["verdict"],
        "score": overall["score"],
        "layers": {
            "static_analysis": {
                "score": static_result.score,
                "risk_level": static_result.risk_level,
                "findings_count": len(static_result.findings),
                "findings": [
                    {
                        "line": f.line_number,
                        "severity": f.severity,
                        "category": f.category,
                        "description": f.description,
                        "match": f.pattern_matched,
                    }
                    for f in static_result.findings
                ],
            },
            "injection_detection": {
                "injection_score": injection_result.injection_score,
                "is_suspicious": injection_result.is_suspicious,
                "is_dangerous": injection_result.is_dangerous,
                "findings_count": len(injection_result.findings),
                "findings": [
                    {
                        "technique": f.technique,
                        "severity": f.severity,
                        "evidence": f.evidence,
                        "line": f.line_number,
                    }
                    for f in injection_result.findings
                ],
            },
            "llm_review": llm_result,
            "sandbox": {
                "executed": sandbox_result.executed,
                "is_suspicious": sandbox_result.is_suspicious,
                "events_count": len(sandbox_result.events),
                "network_calls": sandbox_result.network_calls,
                "files_accessed": sandbox_result.files_accessed,
                "env_vars_read": sandbox_result.env_vars_read,
            },
        },
    }


def _compute_overall(static_result, injection_result, llm_result: dict, sandbox_result) -> dict:
    """Compute overall security verdict."""
    # Weighted score: static=25%, injection=30%, llm=30%, sandbox=15%
    static_score = static_result.score
    injection_score = max(0, 100 - injection_result.injection_score)
    llm_score = max(0, 100 - llm_result.get("overall_risk_score", 50)) if llm_result.get("overall_risk_score", -1) >= 0 else 50
    sandbox_score = 30 if sandbox_result.is_suspicious else 100 if sandbox_result.executed else 50

    overall_score = int(static_score * 0.25 + injection_score * 0.30 + llm_score * 0.30 + sandbox_score * 0.15)

    if overall_score >= 75:
        return {"verdict": "SAFE", "score": overall_score, "emoji": "✅"}
    elif overall_score >= 40:
        return {"verdict": "REVIEW", "score": overall_score, "emoji": "⚠️"}
    else:
        return {"verdict": "REJECT", "score": overall_score, "emoji": "🚫"}
