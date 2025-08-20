import json
import os
import chardet
from openai import OpenAI



client = OpenAI(api_key="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")

# 인코딩 자동 감지 함수
def read_file_with_detected_encoding(path):
    try:
        with open(path, "rb") as f:
            raw = f.read()
            encoding = chardet.detect(raw)["encoding"] or "utf-8"
        return raw.decode(encoding, errors="replace").splitlines()
    except Exception as e:
        return [f" 코드 스니펫을 읽는 중 오류 발생: {e}"]
    
# 주석 강조 및 추출 함수
def emphasize_and_extract_comments(code_lines, file_path):
    ext = os.path.splitext(file_path)[1].lower()
    emphasized_lines = []
    comment_only = []

    # 단일 라인 주석
    single_line_comments = {
        ".py": "#", ".sh": "#", ".bash": "#", ".rb": "#", ".pl": "#", ".r": "#", ".jl": "#",
        ".sql": "--",
        ".js": "//", ".ts": "//", ".java": "//", ".c": "//", ".cpp": "//", ".go": "//", ".cs": "//",
        ".swift": "//", ".kt": "//", ".scala": "//",
    }

    # 다중 라인 주석
    multi_line_comments = {
        ".js": ("/*", "*/"), ".ts": ("/*", "*/"), ".java": ("/*", "*/"),
        ".c": ("/*", "*/"), ".cpp": ("/*", "*/"), ".go": ("/*", "*/"), ".cs": ("/*", "*/"),
        ".swift": ("/*", "*/"), ".kt": ("/*", "*/"), ".scala": ("/*", "*/"),
        ".html": ("<!--", "-->"), ".xml": ("<!--", "-->"),
    }

    in_multiline = False
    start_tag, end_tag = multi_line_comments.get(ext, (None, None))

    for line in code_lines:
        stripped = line.strip()
        is_comment = False

        # 다중라인 주석 처리
        if start_tag and end_tag:
            if in_multiline:
                is_comment = True
                if end_tag in stripped:
                    in_multiline = False
            elif start_tag in stripped:
                is_comment = True
                if end_tag not in stripped:
                    in_multiline = True

        # 단일라인 주석 처리
        marker = single_line_comments.get(ext)
        if marker and stripped.startswith(marker):
            is_comment = True

        if is_comment:
            emphasized_lines.append(f"주석: {line}")
            comment_only.append(line)
        else:
            emphasized_lines.append(line)

    return "\n".join(emphasized_lines), "\n".join(comment_only)

# Semgrep 결과 파일 로드
try:
    with open("semgrep_output.json", "r", encoding="utf-8") as f:
        content = f.read().strip()
        if not content:
            raise ValueError(" JSON 파일이 비어 있습니다.")
        semgrep_results = json.loads(content)
except Exception as e:
    print(f" JSON 파일 로딩 오류: {e}")
    semgrep_results = {"results": []}

#  GPT 프롬프트 구성
prompt = (
    "다음은 Semgrep 도구로 탐지된 보안 취약점 목록입니다. "
    "각 항목에 대해 소스코드와 주석을 함께 고려하여 보안 취약점을 진단하고, "
    "위험도 평가 및 개선 방안을 제시해주세요.\n\n"
)

results = semgrep_results.get("results", [])
all_detected_comments =[] #주석만 따로 저장

if not results:
    prompt += " 취약점이 탐지되지 않았습니다.\n"
else:
    for finding in results:
        check_id = finding.get("check_id", "알 수 없음")
        path = finding.get("path", "알 수 없음")
        line = finding.get("start", {}).get("line")

        # line이 숫자가 아닐 경우 처리
        if not isinstance(line, int):
            line = 0

        message = finding.get("extra", {}).get("message", "")

       # 코드 스니펫 추출 (주석 강조 + 주석만 저장)
        lines = read_file_with_detected_encoding(path)
        start = max(line - 3, 0)
        end = min(line + 2, len(lines))
        snippet, comment_only = emphasize_and_extract_comments(lines[start:end], path)
        all_detected_comments.append(f"[{check_id}] {path} (Line {line})\n{comment_only}\n")

        #  프롬프트에 추가
        prompt += f" [{check_id}] {path} (Line {line})\n"
        prompt += f"설명: {message}\n"
        prompt += f"코드 및 주석:\n{snippet}\n\n"

#  GPT 호출
response = client.chat.completions.create(
    model="gpt-4.1-mini",
    messages=[
        {"role": "system", "content": "너는 숙련된 보안 분석가야."},
        {"role": "user", "content": prompt}
    ]
)

# 탐지된 주석만 별도로 출력
print("\n탐지된 주석 목록:")
for c in all_detected_comments:
    print(c) 