from contextlib import asynccontextmanager

from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional
import json
import subprocess
import shutil
import os
import sys
import asyncio


def _configure_stdio_utf8():
    """Avoid Windows console UnicodeEncodeError on emoji / non-ASCII in prints."""
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError, AttributeError):
                pass


_configure_stdio_utf8()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")


class DependencyInput(BaseModel):
    dependencies: Optional[str] = None


def find_npm_executable():
    for cmd in ["npm", "npm.cmd"]:
        try:
            subprocess.run([cmd, "--version"], capture_output=True, text=True, check=True)
            return cmd
        except Exception:
            continue
    return None


def run_npm_audit():
    npm_cmd = find_npm_executable()
    if npm_cmd is None:
        return {"error": "npm not found"}

    try:
        result = subprocess.run(
            [npm_cmd, "audit", "--json"],
            capture_output=True,
            text=True,
            cwd=BASE_DIR
        )

        if result.returncode != 0 and not result.stdout:
            return {"error": result.stderr.strip() or "npm audit failed"}

        if not result.stdout:
            return {"error": "npm audit returned no output"}

        return json.loads(result.stdout)

    except Exception as e:
        return {"error": str(e)}


def auto_fix(vulns):
    npm_cmd = find_npm_executable()
    if npm_cmd is None:
        return "npm not found"

    try:
        if vulns.get("critical", 0) > 0:
            subprocess.run([npm_cmd, "audit", "fix", "--force"], capture_output=True, text=True, cwd=BASE_DIR)
            return "🔥 Critical fixed"

        elif vulns.get("high", 0) > 2:
            subprocess.run([npm_cmd, "audit", "fix"], capture_output=True, text=True, cwd=BASE_DIR)
            return "⚠️ High fixed"

        return "✅ No fix needed"

    except Exception as e:
        return str(e)


def analyze_npm_data(audit_data):
    if "error" in audit_data:
        err = audit_data["error"]
        return {
            "score": 0,
            "risk": "Error",
            "vulnerabilities": 0,
            "total_dependencies": 0,
            "fix": "npm audit failed",
            "message": err,
            "error": err,
        }

    vulns = audit_data.get("metadata", {}).get("vulnerabilities", {})
    total_vulns = sum(vulns.values())
    total_deps = audit_data.get("metadata", {}).get("totalDependencies", 0)

    score = 100
    score -= vulns.get("critical", 0) * 40
    score -= vulns.get("high", 0) * 25
    score -= vulns.get("moderate", 0) * 15
    score -= vulns.get("low", 0) * 5
    score = max(score, 0)

    if score < 40:
        risk = "High Risk"
    elif score < 70:
        risk = "Moderate Risk"
    else:
        risk = "Secure"

    if vulns.get("critical", 0) > 0:
        fix = "⚠️ Critical issues → Run: npm audit fix --force"
    elif vulns.get("high", 0) > 2:
        fix = "⚠️ Multiple high issues → Run: npm audit fix"
    elif total_vulns > 0:
        fix = "Run: npm audit fix"
    else:
        fix = "✅ No action needed"

    return {
        "score": score,
        "risk": risk,
        "total_dependencies": total_deps,
        "vulnerabilities": total_vulns,
        "details": vulns,
        "fix": fix,
        "message": "Analysis complete"
    }


async def auto_scan_loop():
    log_path = os.path.join(BASE_DIR, "log.txt")

    while True:
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write("Auto scan executed\n")

            audit_data = run_npm_audit()
            result = analyze_npm_data(audit_data)

            if result.get("error"):
                fix_status = "Skipped (audit failed)"
            else:
                fix_status = auto_fix(result.get("details", {}))

            print("Auto Result:", result)
            print("Auto Fix:", fix_status)

        except Exception as e:
            print("Auto Scan Error:", str(e))

        await asyncio.sleep(15)


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(auto_scan_loop())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def root():
    return FileResponse(os.path.join(BASE_DIR, "index.html"))


@app.get("/status")
def status():
    audit_data = run_npm_audit()
    result = analyze_npm_data(audit_data)

    if result.get("error"):
        result["auto_fix_status"] = "Skipped (audit failed)"
    else:
        result["auto_fix_status"] = auto_fix(result.get("details", {}))

    return result


@app.get("/package")
def load_package():
    package_path = os.path.join(BASE_DIR, "package.json")

    if not os.path.exists(package_path):
        return {"error": "package.json not found"}

    with open(package_path, "r", encoding="utf-8") as f:
        return {"content": f.read()}


@app.post("/scan")
def scan(data: DependencyInput):
    npm_cmd = find_npm_executable()
    if npm_cmd is None:
        return {"error": "npm not found"}

    payload = data.dependencies or ""
    package_path = os.path.join(BASE_DIR, "package.json")

    if not payload.strip():
        if not os.path.exists(package_path):
            return {"error": "No package.json available"}

        with open(package_path, "r", encoding="utf-8") as f:
            payload = f.read()

    try:
        with open(package_path, "w", encoding="utf-8") as f:
            f.write(payload)

        subprocess.run(
            [npm_cmd, "install"],
            check=True,
            capture_output=True,
            text=True,
            cwd=BASE_DIR
        )

        audit_data = run_npm_audit()
        return analyze_npm_data(audit_data)

    except Exception as e:
        return {"error": str(e)}


@app.post("/fix")
def fix():
    npm_cmd = find_npm_executable()
    if npm_cmd is None:
        return {"error": "npm not found"}

    package_path = os.path.join(BASE_DIR, "package.json")
    backup_path = os.path.join(BASE_DIR, "package_backup.json")

    try:
        if os.path.exists(package_path):
            shutil.copy(package_path, backup_path)

        subprocess.run(
            [npm_cmd, "audit", "fix"],
            check=True,
            capture_output=True,
            text=True,
            cwd=BASE_DIR
        )

        audit_data = run_npm_audit()
        result = analyze_npm_data(audit_data)

        return {
            "status": "success",
            "message": "✅ Fix applied + security validated",
            "result": result
        }

    except Exception as e:
        if os.path.exists(backup_path):
            shutil.copy(backup_path, package_path)

        return {
            "status": "rollback",
            "message": "⚠️ Fix failed. System restored previous safe state",
            "error": str(e)
        }


@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    await websocket.accept()

    try:
        while True:
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({"error": "Invalid JSON"}))
                continue
            dependencies = message.get("dependencies", "")

            npm_cmd = find_npm_executable()
            if npm_cmd is None:
                await websocket.send_text(json.dumps({"error": "npm not found"}))
                continue

            package_path = os.path.join(BASE_DIR, "package.json")

            with open(package_path, "w", encoding="utf-8") as f:
                f.write(dependencies)

            subprocess.run(
                [npm_cmd, "install"],
                check=True,
                capture_output=True,
                text=True,
                cwd=BASE_DIR
            )

            audit_data = run_npm_audit()
            result = analyze_npm_data(audit_data)

            await websocket.send_text(json.dumps(result))

    except WebSocketDisconnect:
        print("WebSocket disconnected")
