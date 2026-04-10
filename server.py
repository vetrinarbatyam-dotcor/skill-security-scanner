#!/usr/bin/env python3
"""
Skill Security Scanner — FastAPI Server
REST API for scanning skills remotely (deployed on Contabo).

Endpoints:
    POST /scan         — scan skill content (body: {content, filename, layers})
    POST /scan/url     — scan skill from URL (body: {url})
    GET  /health       — health check
"""

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import uvicorn
import os

from scanner.zip_handler import extract_skills_from_zip
from scanner.skill_validator import validate as skill_validate
from scanner.static_analyzer import analyze as static_analyze
from scanner.injection_detector import detect as injection_detect
from scanner.llm_reviewer import review_with_llm
from scanner.sandbox_runner import run_in_sandbox
from scanner.report import generate_json_report

app = FastAPI(
    title="Skill Security Scanner",
    description="Multi-layer security scanner for AI skills (Claude Code / OpenClaw)",
    version="1.0.0",
)

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


@app.get("/")
def root():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


class ScanRequest(BaseModel):
    content: str
    filename: str = "unknown_skill"
    skip_llm: bool = False
    skip_sandbox: bool = False


class ScanURLRequest(BaseModel):
    url: str
    skip_llm: bool = False
    skip_sandbox: bool = False


@app.get("/health")
def health():
    return {"status": "ok", "service": "skill-security-scanner", "version": "1.0.0"}


@app.post("/scan")
def scan_skill(req: ScanRequest):
    """Scan skill content for security risks."""
    if not req.content.strip():
        raise HTTPException(400, "Content is empty")
    if len(req.content) > 500_000:
        raise HTTPException(400, "Content too large (max 500KB)")

    # Layer 0: Validate this is a skill/agent
    validation = skill_validate(req.content)
    if not validation.is_valid:
        raise HTTPException(422, detail={
            "error": "not_a_skill",
            "message": validation.error,
            "hints": validation.hints,
            "detected_type": validation.skill_type,
        })

    static_result = static_analyze(req.content)
    injection_result = injection_detect(req.content)

    if req.skip_llm:
        llm_result = {"overall_risk_score": -1, "summary": "Skipped", "recommendation": "N/A", "findings": []}
    else:
        llm_result = review_with_llm(req.content)

    if req.skip_sandbox:
        from scanner.sandbox_runner import SandboxResult
        sandbox_result = SandboxResult()
    else:
        sandbox_result = run_in_sandbox(req.content)

    report = generate_json_report(req.filename, static_result, injection_result, llm_result, sandbox_result)
    report["source_code"] = req.content
    return report


@app.post("/scan/url")
def scan_url(req: ScanURLRequest):
    """Scan a skill from URL."""
    import urllib.request
    try:
        r = urllib.request.Request(req.url, headers={"User-Agent": "SkillSecurityScanner/1.0"})
        with urllib.request.urlopen(r, timeout=30) as resp:
            content = resp.read().decode("utf-8")
    except Exception as e:
        raise HTTPException(400, f"Failed to fetch URL: {e}")

    filename = req.url.split("/")[-1] or "remote_skill"
    scan_req = ScanRequest(content=content, filename=filename, skip_llm=req.skip_llm, skip_sandbox=req.skip_sandbox)
    return scan_skill(scan_req)


@app.post("/scan/zip")
async def scan_zip(file: UploadFile = File(...), skip_llm: bool = Form(True), skip_sandbox: bool = Form(True)):
    """Scan all skill files inside a ZIP archive."""
    if not file.filename or not file.filename.lower().endswith('.zip'):
        raise HTTPException(400, "Only .zip files are accepted")

    zip_bytes = await file.read()
    if len(zip_bytes) > 10 * 1024 * 1024:
        raise HTTPException(400, "ZIP too large (max 10MB)")

    try:
        skill_files = extract_skills_from_zip(zip_bytes)
    except ValueError as e:
        raise HTTPException(422, detail={"error": "zip_error", "message": str(e), "hints": []})

    results = []
    skipped = []

    for sf in skill_files:
        # Validate each file
        validation = skill_validate(sf['content'])
        if not validation.is_valid:
            skipped.append({
                "filename": sf['filename'],
                "reason": validation.error,
                "size": sf['size'],
            })
            continue

        # Scan valid skills
        static_result = static_analyze(sf['content'])
        injection_result = injection_detect(sf['content'])

        if skip_llm:
            llm_result = {"overall_risk_score": -1, "summary": "Skipped", "recommendation": "N/A", "findings": []}
        else:
            llm_result = review_with_llm(sf['content'])

        if skip_sandbox:
            from scanner.sandbox_runner import SandboxResult
            sandbox_result = SandboxResult()
        else:
            sandbox_result = run_in_sandbox(sf['content'])

        report = generate_json_report(sf['filename'], static_result, injection_result, llm_result, sandbox_result)
        report["source_code"] = sf['content']
        results.append(report)

    # Overall verdict
    if results:
        worst_score = min(r['score'] for r in results)
        if worst_score >= 75:
            overall = "SAFE"
        elif worst_score >= 40:
            overall = "REVIEW"
        else:
            overall = "REJECT"
    else:
        overall = "EMPTY"

    return {
        "zip_filename": file.filename,
        "total_files_found": len(skill_files),
        "scanned": len(results),
        "skipped": len(skipped),
        "skipped_files": skipped,
        "overall_verdict": overall,
        "results": results,
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8990)
