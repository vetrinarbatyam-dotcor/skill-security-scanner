#!/usr/bin/env python3
"""
Skill Security Scanner — FastAPI Server
REST API for scanning skills remotely (deployed on Contabo).

Endpoints:
    POST /scan         — scan skill content (body: {content, filename, layers})
    POST /scan/url     — scan skill from URL (body: {url})
    GET  /health       — health check
"""

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import uvicorn
import os

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

    return generate_json_report(req.filename, static_result, injection_result, llm_result, sandbox_result)


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


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8990)
