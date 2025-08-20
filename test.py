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
        start = max(0, start_line - 1)
        end = min(len(lines), end_line)
        return "".join(lines[start:end])
    except Exception as e:
        return f"코드 스니펫을 읽을 수 없습니다: {e}"

def generate_attack_example(vuln_code: str) -> str:
    prompt = (
        f"아래 코드에서 발생할 수 있는 취약점에 대해 어떤 공격 구문이 있을지 테스트 할 수 있는 공격 구문만 작성하여 출력해줘. "
        f"예를 들어 sqli 이면 ' or 1=1 -- 이런 식으로. 취약점에 대해서는 설명하지 마. 공격 구문을 제시 못하는 경우 또는 구문 만들기 어려울거 같은 경우는 그냥 -. 그리고 설명은 하지 마.:\n{vuln_code}"
    )
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=700
    )
    return response.choices[0].message.content.strip()

def generate_patch_suggestion(vuln_code: str) -> str:
    prompt = (
        f"아래 취약한 코드를 보안 패치를 적용한 안전한 코드로 수정해줘. "
        f"원본 구조와 기능은 유지하되 보안 취약점만 해결하고, 기존 주석은 건드리지 말고 새 주석을 추가하지 마. "
        f"수정된 코드만 출력하고 설명은 하지 마:\n{vuln_code}"
    )
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1000
    )
    return response.choices[0].message.content.strip()

def is_overlap(range1: tuple, range2: tuple) -> bool:
    start1, end1 = range1
    start2, end2 = range2
    return not (end1 < start2 or end2 < start1)


def main():
    target_code_path = input("검사할 코드 경로를 입력하세요 (예: ./a): ").strip()
    semgrep_result = run_semgrep_scan(target_code_path, SEMGREP_CONFIG_PATH)

    results = semgrep_result.get("results", [])

    # 중복 체크용 딕셔너리: {파일경로: [ (start_line,end_line), ... ] }
    seen_ranges = {}

    idx = 0
    for finding in results:
        path = finding.get("path", "Unknown path")
        start = finding.get("start", {})
        end = finding.get("end", {})

        start_line = start.get("line", 0)
        end_line = end.get("line", start_line)

        # 기존 취약점들과 범위 중복 검사
        has_overlap = False
        if path in seen_ranges:
            for existing_range in seen_ranges[path]:
                if is_overlap(existing_range, (start_line, end_line)):
                    has_overlap = True
                    break
        else:
            seen_ranges[path] = []

        if has_overlap:
            continue  # 중복 발견 시 건너뜀

        # 중복 아니면 추가
        seen_ranges[path].append((start_line, end_line))

        idx += 1
        print(f"--- 취약점 #{idx} ---")
        check_id = finding.get("check_id", "Unknown")

        print(f"룰 ID: {check_id}")
        print(f"파일 경로: {path}")
        print(f"취약 코드 위치: {start_line} line 부터 {end_line} line 까지\n")

        vuln_code = read_code_snippet(path, start_line, end_line)
        print("=== 취약 코드 스니펫 ===")
        print(vuln_code)

        print("=== 테스트 공격 구문 ===")
        attack_example = generate_attack_example(vuln_code)
        print(attack_example + "\n")

        print("=== 보안 패치 권고 ===")
        patch_suggestion = generate_patch_suggestion(vuln_code)
        print(patch_suggestion + "\n")

if __name__ == "__main__":
    main()

