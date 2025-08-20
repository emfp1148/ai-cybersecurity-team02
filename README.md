# AI Cybersecurity Team 02

**α-VAT (Vulnerability Automatic Tool)** - AI 기반 자동화된 취약점 분석 및 보고서 생성 시스템

## 📋 프로젝트 개요

본 프로젝트는 FastAPI 기반의 웹 애플리케이션으로, 업로드된 ZIP 파일을 자동으로 분석하여 보안 취약점을 탐지하고 상세한 보고서를 생성하는 도구입니다. 기존의 정적 분석 도구와 AI를 결합하여 더욱 정확하고 포괄적인 보안 분석을 제공합니다.

### 🎯 주요 기능

- **📤 파일 업로드 및 자동 분석**: ZIP 파일 업로드 후 자동 압축 해제 및 분석
- **🔍 보안 스캔**: `alpha_vat.py` 스크립트를 통한 자동화된 보안 취약점 분석
- **📊 실시간 결과 확인**: 웹 인터페이스를 통한 분석 결과 실시간 확인
- **📝 다양한 형식 지원**: TXT, JSON 형태의 보고서 다운로드
- **🚀 고성능**: 비동기 처리 및 FastAPI의 고성능 웹 프레임워크 활용

## 🛠 기술 스택

### Backend Framework
- **Python 3.8+** - 메인 개발 언어 (83.3%)
- **FastAPI** - 고성능 웹 API 프레임워크
- **Uvicorn** - ASGI 서버
- **Pydantic** - 데이터 검증 및 시리얼라이제이션

### Frontend
- **HTML5** - 구조적 마크업 (6.2%)
- **CSS3** - 스타일링 및 레이아웃 (7.2%)
- **JavaScript (ES6+)** - 동적 UI 상호작용 (3.3%)

### 파일 처리 및 분석
- **zipfile** - ZIP 파일 압축 해제
- **subprocess** - 외부 스크립트 실행
- **pathlib** - 파일 시스템 경로 처리
- **shutil** - 파일 및 디렉터리 작업

### 웹 서비스
- **Jinja2Templates** - HTML 템플릿 엔진
- **StaticFiles** - 정적 파일 서빙
- **FileResponse** - 파일 다운로드

### 개발 및 운영
- **Git** - 버전 관리
- **GitHub** - 코드 호스팅 및 협업
- **UUID** - 고유 식별자 생성

## 📁 프로젝트 구조

```
ai-cybersecurity-team02/
├── app.py                      # FastAPI 메인 애플리케이션
├── alpha_vat.py                # 보안 분석 스크립트 (메인 분석 엔진)
├── static/                     # 정적 파일
│   ├── app.js                  # 프론트엔드 JavaScript
│   └── styles.css              # CSS 스타일시트
├── templates/                  # Jinja2 HTML 템플릿
│   ├── index.html              # 메인 업로드 페이지
│   └── result.html             # 결과 확인 페이지
├── data/                       # 데이터 저장 디렉터리
│   ├── uploads/                # 업로드된 파일
│   ├── tmp/                    # 임시 작업 폴더
│   └── unpacked/               # 압축 해제된 파일
├── result/                     # 분석 결과 저장
├── security_report/            # 보안 리포트 (JSON 형식)
├── 출력 json 예시/              # 출력 예시 파일
└── README.md
```

## 🚀 설치 및 실행

### 1. 저장소 클론
```bash
git clone https://github.com/choisein/ai-cybersecurity-team02.git
cd ai-cybersecurity-team02
```

### 2. 가상 환경 생성 및 활성화
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate  # Windows
```

### 3. 의존성 설치
```bash
pip install fastapi uvicorn python-multipart jinja2 aiofiles openai semgrep
```

### 4. 환경 변수 등록
```bash
echo 'export OPENAI_API_KEY="...your_key..."' >> ~/.bashrc
source ~/.bashrc
```

### 5. 서버 실행
```bash
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

서버가 실행되면 `http://localhost:8000`에서 웹 인터페이스에 접근할 수 있습니다.

## 📖 사용 방법

### 1. 웹 인터페이스 사용
1. 브라우저에서 `http://localhost:8000` 접속
2. **α-VAT (Vulnerability Automatic Tool)** 메인 페이지에서 ZIP 파일 선택
3. "분석 시작" 버튼 클릭
4. 분석 완료 후 결과 페이지에서 보고서 확인 및 다운로드

### 2. API 엔드포인트

#### POST `/api/upload`
- **설명**: ZIP 파일 업로드 및 분석
- **파라미터**: `zip_file` (multipart/form-data)
- **응답**: JSON 형태의 분석 결과 및 다운로드 링크

#### GET `/result/{job_id}`
- **설명**: 분석 결과 웹 페이지
- **파라미터**: `job_id` (분석 작업 고유 ID)
- **응답**: HTML 페이지

#### GET `/api/download/{job_id}/{kind}`
- **설명**: 분석 결과 파일 다운로드
- **파라미터**: 
  - `job_id`: 분석 작업 고유 ID
  - `kind`: `txt` 또는 `json`
- **응답**: 파일 다운로드

### 3. 분석 프로세스

1. **파일 업로드**: ZIP 파일이 `data/uploads/` 디렉터리에 저장
2. **압축 해제**: 파일이 `data/unpacked/{job_id}/` 디렉터리에 해제
3. **보안 분석**: `half_complete_code.py` 스크립트가 자동 실행
4. **결과 생성**: 
   - TXT 형태의 분석 로그: `result/{job_id}_report.txt`
   - JSON 형태의 상세 보고서: `result/{job_id}_security_report.json`

## 📊 결과물

프로젝트는 다음과 같은 결과물을 생성합니다:

1. **텍스트 보고서** (`{job_id}_report.txt`)
   - 분석 과정의 상세 로그
   - 표준 출력 결과

2. **JSON 보고서** (`{job_id}_security_report.json`)
   - 구조화된 보안 분석 결과
   - `security_report` 폴더의 최신 JSON 파일 복사
