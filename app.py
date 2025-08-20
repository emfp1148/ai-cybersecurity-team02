import os
import uuid
import zipfile
import shutil
import subprocess
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import RedirectResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI()

# ========= 커스터마이즈 가능한 설정 =========
STATIC_DIR = "static"                        # index.html 위치
DATA_DIR = "data"                            # 데이터 루트
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
TMP_DIR = os.path.join(DATA_DIR, "tmp")      # 작업용 임시 폴더
UNPACKED_DIR = os.path.join(DATA_DIR, "unpacked")
RESULT_DIR = "result"
PYTHON_BIN = "python3"
ANALYZER_SCRIPT = "half_complete_code.py"    # 분석 스크립트 파일명
# ==========================================

# 디렉토리 준비
for d in [STATIC_DIR, DATA_DIR, UPLOAD_DIR, TMP_DIR, UNPACKED_DIR, RESULT_DIR]:
    os.makedirs(d, exist_ok=True)

# 정적 파일 서빙 및 루트 → index.html 리다이렉트
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
async def root():
    return RedirectResponse(url="/static/index.html")

@app.post("/upload/", response_class=PlainTextResponse)
async def upload_and_analyze(zip_file: UploadFile = File(...)):
    # 1) 파일명 검증
    filename = os.path.basename(zip_file.filename or "")
    if not filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="zip 파일만 업로드 가능합니다.")

    # 2) Job ID 및 경로 설정
    job_id = uuid.uuid4().hex[:12]
    saved_zip_path = os.path.join(UPLOAD_DIR, f"{job_id}_{filename}")
    tmp_job_dir = os.path.join(TMP_DIR, job_id)
    final_unpacked_dir = os.path.join(UNPACKED_DIR, job_id)
    report_path = os.path.join(RESULT_DIR, f"{job_id}_report.txt")

    # 3) zip 저장
    try:
        with open(saved_zip_path, "wb") as f:
            f.write(await zip_file.read())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"파일 저장 실패: {e}")

    # 4) 임시 폴더에 압축 해제
    try:
        if os.path.exists(tmp_job_dir):
            shutil.rmtree(tmp_job_dir)
        os.makedirs(tmp_job_dir, exist_ok=True)

        with zipfile.ZipFile(saved_zip_path, "r") as zip_ref:
            zip_ref.extractall(tmp_job_dir)
    except Exception as e:
        shutil.rmtree(tmp_job_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail=f"압축 해제 실패: {e}")

    # 5) 최종 폴더로 이동(원자적 이동)
    try:
        if os.path.exists(final_unpacked_dir):
            shutil.rmtree(final_unpacked_dir)
        os.rename(tmp_job_dir, final_unpacked_dir)
    except Exception as e:
        shutil.rmtree(tmp_job_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=f"작업 디렉터리 이동 실패: {e}")

    # 6) 분석 스크립트 실행: python half_complete_code.py ./업로드_해제_경로
    try:
        proc = subprocess.run(
            [PYTHON_BIN, ANALYZER_SCRIPT, final_unpacked_dir],
            capture_output=True,
            text=True
        )
        # semgrep 성공/발견 시 0 또는 1 반환 가능. 그 외 코드는 에러로 간주.
        if proc.returncode not in (0, 1):
            # 표준에러/표준출력 함께 제공
            err = proc.stderr.strip() or proc.stdout.strip() or "알 수 없는 오류"
            raise HTTPException(status_code=500, detail=f"분석 중 오류 발생:\n{err}")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"분석 스크립트를 찾을 수 없습니다. {ANALYZER_SCRIPT} 위치를 확인하세요.")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"분석 실행 실패: {e}")

    # 7) 보고서 저장(선택)
    try:
        with open(report_path, "w", encoding="utf-8") as rf:
            rf.write(proc.stdout)
    except Exception:
        # 저장 실패해도 웹 응답은 정상 반환
        pass

    # 8) 헤더 + stdout 그대로 반환
    header = [
        f"[JOB ID]       {job_id}",
        f"[업로드 파일]  {saved_zip_path}",
        f"[해제 경로]    {final_unpacked_dir}",
        f"[리포트 파일]  {report_path}",
        "",
        "=== 분석 결과 출력 ===",
        "",
    ]
    return PlainTextResponse("\n".join(header) + proc.stdout)

