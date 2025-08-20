import subprocess
import json
import openai
import os

openai.api_key = os.getenv("OPENAI_API_KEY")
if not openai.api_key:
    raise RuntimeError("환경변수 OPENAI_API_KEY가 설정되지 않았습니다. 먼저 설정해주세요.")

SEMGREP_CONFIG_PATH = "p/owasp-top-ten"

def run_semgrep_scan(target_path: str, config_path: str) -> dict:
    result = subprocess.run(
        ["semgrep", "--json", "--config", config_path, target_path],
        capture_output=True,
        text=True,
    )
    if result.returncode not in (0, 1):
        err_msg = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"Semgrep 실패: {err_msg}")
    return json.loads(result.stdout)

def read_code_snippet(path: str, start_line: int, end_line: int) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
        # 파일 크기 벗어나지 않도록 경계처리
        start = max(0, start_line - 1)
        end = min(len(lines), end_line)
        snippet = "".join(lines[start:end])
        return snippet
    except Exception as e:
        return f"코드 스니펫을 읽을 수 없습니다: {e}"

def translate_to_korean(text: str) -> str:
    prompt = f"아래 내용을 한국어로 요약하여 번역해줘:\n{text}"
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=500
    )
    return response.choices[0].message.content.strip()

def generate_attack_example(vuln_code: str) -> str:
    prompt = (
        f"아래 코드에서 발생할 수 있는 취약점에 대해 어떤 공격 구문이 있을지 테스트 할 수 있는 공격 구문만 작성하여 출력해줘. 예를 들어 sqli 이면 ' or 1=1 -- 이런 식으로. 취약점에 대해서는 설명하지 마. 공격 구문을 제시 못하는 경우 또는 구문 만들기 어려울거 같은 경우는 그냥 -. 그리고 설명은 하지 마.:\n{vuln_code}"
    )
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=700
    )
    return response.choices[0].message.content.strip()

def format_extra(extra: dict) -> str:
    # message는 제외하고 나머지는 보기 좋게 key: value 형식 출력
    keys_to_skip = {"message", "lines", "fingerprint", "validation_state", "engine_kind"}
    lines = []
    for key, val in extra.items():
        if key not in keys_to_skip:
            lines.append(f"{key}: {val}")
    return "\n".join(lines) if lines else "추가 정보가 없습니다."

def main():
    target_code_path = input("검사할 코드 경로를 입력하세요 (예: ./a): ").strip()
    semgrep_result = run_semgrep_scan(target_code_path, SEMGREP_CONFIG_PATH)

    results = semgrep_result.get("results", [])

    for i, finding in enumerate(results, 1):
        print(f"--- 취약점 #{i} ---")
        check_id = finding.get("check_id", "Unknown")
        path = finding.get("path", "Unknown path")
        start = finding.get("start", {})
        end = finding.get("end", {})
        extra = finding.get("extra", {})

        start_line = start.get("line", 0)
        end_line = end.get("line", start_line)

        print(f"룰 ID: {check_id}")
        print(f"파일 경로: {path}")
        print(f"취약 코드 위치: {start_line} line 부터 {end_line} line 까지\n")

        vuln_code = read_code_snippet(path, start_line, end_line)
        print("=== 취약 코드 스니펫 ===")
        print(vuln_code)

        print("=== 테스트 공격 구문 ===")
        attack_example = generate_attack_example(vuln_code)
        print(attack_example + '\n')

        # extra.message 한글 번역
        #message = extra.get("message", "")
        #if message:
        #    print("\n=== 경고 메시 ===")
        #    translated_msg = translate_to_korean(message)
        #    print(translated_msg)

        # extra 기타 정보 출력
        #print("\n=== 추가 정보 ===")
        #print(format_extra(extra))

        #print("\n" + "="*70 + "\n")

if __name__ == "__main__":
    main()

