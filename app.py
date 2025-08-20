import os
import uuid
import zipfile
import shutil
import subprocess
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI()

# ========= 경로 설정 =========
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATE_DIR = BASE_DIR / "templates"
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
TMP_DIR = DATA_DIR / "tmp"
UNPACKED_DIR = DATA_DIR / "unpacked"
RESULT_DIR = BASE_DIR / "result"
SECURITY_JSON_DIR = BASE_DIR / "security_report"   # half_complete_code.py 출력
PYTHON_BIN = "python3"
ANALYZER_SCRIPT = "half_complete_code.py"
# =================================

# 디렉토리 준비
for d in [STATIC_DIR, TEMPLATE_DIR, DATA_DIR, UPLOAD_DIR, TMP_DIR, UNPACKED_DIR, RESULT_DIR, SECURITY_JSON_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# 정적 파일/템플릿
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


# 1) 홈: index.html (템플릿)
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# 2) 업로드 API: JSON 응답
@app.post("/api/upload", response_class=JSONResponse)
async def api_upload(zip_file: UploadFile = File(...)):
    # 파일명 검증
    filename = os.path.basename(zip_file.filename or "")
    if not filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="zip 파일만 업로드 가능합니다.")

    # Job 설정
    job_id = uuid.uuid4().hex[:12]
    saved_zip_path = UPLOAD_DIR / f"{job_id}_{filename}"
    tmp_job_dir = TMP_DIR / job_id
    final_unpacked_dir = UNPACKED_DIR / job_id
    report_txt_path = RESULT_DIR / f"{job_id}_report.txt"
    report_json_path = RESULT_DIR / f"{job_id}_security_report.json"

    # 저장
    try:
        with open(saved_zip_path, "wb") as f:
            f.write(await zip_file.read())
    except Exception as e:
        raise HTTPException(500, f"파일 저장 실패: {e}")

    # 압축 해제(임시→최종)
    try:
        if tmp_job_dir.exists():
            shutil.rmtree(tmp_job_dir)
        tmp_job_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(saved_zip_path, "r") as zf:
            zf.extractall(tmp_job_dir)
    except Exception as e:
        shutil.rmtree(tmp_job_dir, ignore_errors=True)
        raise HTTPException(400, f"압축 해제 실패: {e}")

    try:
        if final_unpacked_dir.exists():
            shutil.rmtree(final_unpacked_dir)
        os.rename(tmp_job_dir, final_unpacked_dir)
    except Exception as e:
        shutil.rmtree(tmp_job_dir, ignore_errors=True)
        raise HTTPException(500, f"작업 디렉터리 이동 실패: {e}")

    # 분석 실행
    try:
        proc = subprocess.run(
            [PYTHON_BIN, ANALYZER_SCRIPT, str(final_unpacked_dir)],
            capture_output=True,
            text=True
        )
        if proc.returncode not in (0, 1):
            err = proc.stderr.strip() or proc.stdout.strip() or "알 수 없는 오류"
            raise HTTPException(500, f"분석 중 오류 발생:\n{err}")
    except FileNotFoundError:
        raise HTTPException(500, f"분석 스크립트를 찾을 수 없습니다: {ANALYZER_SCRIPT}")
    except Exception as e:
        raise HTTPException(500, f"분석 실행 실패: {e}")

    # 리포트 저장(txt)
    try:
        with open(report_txt_path, "w", encoding="utf-8") as rf:
            rf.write(proc.stdout)
    except Exception:
        pass

    # security_report 내 최신 json을 result로 복사
    try:
        latest_json = None
        latest_mtime = -1
        if SECURITY_JSON_DIR.is_dir():
            for fn in SECURITY_JSON_DIR.iterdir():
                if fn.suffix == ".json":
                    m = fn.stat().st_mtime
                    if m > latest_mtime:
                        latest_mtime = m
                        latest_json = fn
        if latest_json:
            shutil.copy2(latest_json, report_json_path)
    except Exception:
        pass

    # API JSON 응답 → 프론트는 /result/{job_id}로 이동
    return {
        "job_id": job_id,
        "paths": {
            "zip": str(saved_zip_path),
            "unpacked": str(final_unpacked_dir),
            "txt": f"/api/download/{job_id}/txt",
            "json": f"/api/download/{job_id}/json",
        },
        "stdout": proc.stdout,  # 필요 시 프론트에서 일부만 사용
        "result_url": f"/result/{job_id}"
    }


# 3) 결과 페이지(템플릿 렌더)
@app.get("/result/{job_id}", response_class=HTMLResponse)
async def result_page(request: Request, job_id: str):
    if not job_id.isalnum():
        raise HTTPException(400, "잘못된 job_id")

    txt_path = RESULT_DIR / f"{job_id}_report.txt"
    stdout = ""
    if txt_path.exists():
        try:
            stdout = txt_path.read_text(encoding="utf-8")
        except Exception:
            stdout = ""

    context = {
        "request": request,
        "job_id": job_id,
        "txt_download": f"/api/download/{job_id}/txt",
        "json_download": f"/api/download/{job_id}/json",
        "stdout": stdout
    }
    return templates.TemplateResponse("result.html", context)


# 4) 다운로드 API
@app.get("/api/download/{job_id}/{kind}")
async def download_result(job_id: str, kind: str):
    if not job_id.isalnum():
        raise HTTPException(status_code=400, detail="잘못된 job_id")

    if kind == "txt":
        path = RESULT_DIR / f"{job_id}_report.txt"
        filename = f"{job_id}_report.txt"
    elif kind == "json":
        path = RESULT_DIR / f"{job_id}_security_report.json"
        filename = f"{job_id}_security_report.json"
    else:
        raise HTTPException(404, "지원하지 않는 형식")

    if not path.exists():
        raise HTTPException(404, "파일을 찾을 수 없습니다.")
    return FileResponse(str(path), media_type="application/octet-stream", filename=filename)

