import subprocess
import json
import openai
import os
from typing import List, Dict, Set

openai.api_key = os.getenv("OPENAI_API_KEY")
if not openai.api_key:
    raise RuntimeError("환경변수 OPENAI_API_KEY가 설정되지 않았습니다. 먼저 설정해주세요.")

# 기본 Semgrep Registry config 경로 설정
SEMGREP_CONFIG_PATH = "p/owasp-top-ten"

def run_semgrep_scan(target_path: str, config_path: str) -> dict:
    print(f"Semgrep 스캔을 시작합니다: 대상 경로='{target_path}', 룰='{config_path}'")
    result = subprocess.run(
        ["semgrep", "--json", "--config", config_path, target_path],
        capture_output=True,
        text=True,
    )
    if result.returncode not in (0, 1):
        err_msg = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"Semgrep 실패: {err_msg}")
    return json.loads(result.stdout)

def generate_attack_pattern(vuln_id: str, code_snippet: str) -> str:
    prompt = (
        f"취약점 ID '{vuln_id}'와 관련된 코드:\n{code_snippet}\n\n"
        "이 취약점에 사용될 수 있는 공격 구문과 발생 원인을 상세히 설명해 주세요."
    )
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content.strip()

def generate_security_patch(vuln_id: str, code_snippet: str) -> str:
    prompt = (
        f"취약점 ID '{vuln_id}' 관련 코드:\n{code_snippet}\n\n"
        "이 취약점을 완화하거나 보안 패치하는 방법을 단계별로 설명해 주세요."
    )
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content.strip()

def postprocess_semgrep_results(semgrep_json: dict) -> List[Dict]:
    processed_results = []
    seen_keys: Set[str] = set()

    findings = semgrep_json.get("results", [])
    for finding in findings:
        vuln_id = finding.get("check_id", "Unknown")
        code_line = finding.get("extra", {}).get("lines", "")

        key = vuln_id + code_line[:50]
        if key in seen_keys:
            continue
        seen_keys.add(key)

        print(f"LLM 분석 중... 취약점 ID: {vuln_id}")
        attack_pattern = generate_attack_pattern(vuln_id, code_line)
        security_patch = generate_security_patch(vuln_id, code_line)

        processed_results.append({
            "check_id": vuln_id,
            "code": code_line,
            "attack_pattern": attack_pattern,
            "security_patch": security_patch,
        })

    return processed_results


def generate_new_rules(findings: List[Dict]) -> str:
    """Semgrep 스캔 결과를 바탕으로 새로운 보안 규칙을 생성합니다."""
    
    # 모든 취약점 정보를 하나의 문맥으로 결합
    context = "\n\n".join([
        f"취약점 ID: {finding['check_id']}\n"
        f"취약 코드:\n{finding['code']}\n"
        f"공격 패턴:\n{finding['attack_pattern']}"
        for finding in findings
    ])
    
    prompt = f"""다음은 발견된 보안 취약점들의 목록입니다:

{context}

위 취약점들을 분석하여:
1. 추가로 발견할 수 있는 유사한 패턴의 취약점
2. 이를 탐지하기 위한 Semgrep 규칙
3. 각 규칙에 대한 설명과 탐지 근거

를 YAML 형식으로 작성해주세요."""

    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    
    return response.choices[0].message.content.strip()

def main():
    print("※ 검사 대상 경로는 루트 기준 상대경로(예: ./a) 형태로 입력하세요.")
    target_code_path = input("검사할 코드 경로를 입력하세요 (예: ./a): ").strip()

    semgrep_result = run_semgrep_scan(target_code_path, SEMGREP_CONFIG_PATH)
    final_results = postprocess_semgrep_results(semgrep_result)

    print("\n--- 최종 보고서 ---")
    for res in final_results:
        print(f"취약점 ID: {res['check_id']}")
        print(f"취약코드:\n{res['code']}")
        print(f"공격 구문 예시 및 발생 원인:\n{res['attack_pattern']}")
        print(f"보안 패치 방법:\n{res['security_patch']}")
        print("=" * 60)

    # 새로운 규칙 생성 및 출력
    print("\n--- 추가 보안 규칙 제안 ---")
    new_rules = generate_new_rules(final_results)
    print(new_rules)

if __name__ == "__main__":
    main()