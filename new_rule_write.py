import subprocess
import json
import openai
import os
import sys
import yaml
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
    
    context = "\n\n".join([
        f"취약점 ID: {finding['check_id']}\n"
        f"취약 코드:\n{finding['code']}\n"
        f"공격 패턴:\n{finding['attack_pattern']}"
        for finding in findings
    ])
    
    prompt = f"""다음은 발견된 보안 취약점들의 목록입니다:

{context}

위 취약점들을 분석하여 Semgrep 규칙을 YAML 형식으로 작성해주세요.
다음 형식을 반드시 지켜주세요:

rules:
  - id: rule_name
    pattern: pattern_here
    message: "설명"
    languages: [python]
    severity: WARNING

각 규칙은 반드시 위 형식을 따라야 하며, 'rules:' 키워드로 시작해야 합니다."""

    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    
    generated_rules = response.choices[0].message.content.strip()
    
    # YAML 형식 검증
    if not generated_rules.startswith("rules:"):
        generated_rules = "rules:\n" + generated_rules
    
    return generated_rules

def save_new_rules(rules: str, filename: str = "new_rules.yaml") -> str:
    """생성된 규칙을 YAML 파일로 저장합니다."""
    
    # YAML 유효성 검사
    try:
        yaml.safe_load(rules)
    except yaml.YAMLError as e:
        print(f"경고: 생성된 규칙이 유효한 YAML이 아닙니다: {e}")
        print("기본 규칙 템플릿으로 대체합니다.")
        rules = """rules:
  - id: default_rule
    pattern: $X = request.args.get(...)
    message: "사용자 입력을 검증 없이 사용하고 있습니다"
    languages: [python]
    severity: WARNING"""
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(rules)
    return filename

def run_additional_scan(target_path: str, rules_file: str) -> List[Dict]:
    """새로 생성된 규칙으로 추가 스캔을 실행합니다."""
    print(f"\n새로운 규칙으로 추가 스캔을 시작합니다...")
    
    if not os.path.exists(rules_file):
        raise FileNotFoundError(f"규칙 파일을 찾을 수 없습니다: {rules_file}")
    
    with open(rules_file, 'r', encoding='utf-8') as f:
        print(f"\n=== 적용할 규칙 내용 ===\n{f.read()}\n")
    
    # 첫 번째 스캔과 동일한 방식으로 실행
    result = subprocess.run(
        ["semgrep", "--json", "--config", rules_file, target_path],
        capture_output=True,
        text=True,
    )
    
    print(f"\n=== Semgrep 실행 결과 ===")
    print(f"Return Code: {result.returncode}")
    print(f"STDOUT: {result.stdout}")
    print(f"STDERR: {result.stderr}")
    
    if result.returncode not in (0, 1):
        err_msg = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"추가 스캔 실패: {err_msg}")
    
    if not result.stdout.strip():
        print("경고: Semgrep이 빈 출력을 반환했습니다.")
        return []
        
    try:
        return json.loads(result.stdout).get("results", [])
    except json.JSONDecodeError as e:
        print(f"JSON 파싱 오류: {e}")
        return []

def generate_additional_report(findings: List[Dict]) -> List[Dict]:
    """추가 발견된 취약점에 대한 보고서를 생성합니다."""
    additional_results = []
    
    for finding in findings:
        vuln_id = finding.get("check_id", "Unknown")
        code_line = finding.get("extra", {}).get("lines", "")
        
        print(f"추가 발견된 취약점 분석 중... ID: {vuln_id}")
        attack_pattern = generate_attack_pattern(vuln_id, code_line)
        security_patch = generate_security_patch(vuln_id, code_line)
        
        additional_results.append({
            "check_id": vuln_id,
            "code": code_line,
            "attack_pattern": attack_pattern,
            "security_patch": security_patch,
        })
    
    return additional_results

def main():
    print("※ 검사 대상 경로는 루트 기준 상대경로(예: ./a) 형태로 입력하세요.")
    target_code_path = input("검사할 코드 경로를 입력하세요 (예: ./a): ").strip()

    # 1. 기존 스캔 실행
    print("\n[1/4] 기본 보안 규칙으로 스캔 중...")
    semgrep_result = run_semgrep_scan(target_code_path, SEMGREP_CONFIG_PATH)
    final_results = postprocess_semgrep_results(semgrep_result)

    # 2. 새로운 규칙 생성
    print("\n[2/4] 추가 보안 규칙 생성 중...")
    new_rules = generate_new_rules(final_results)
    rules_file = save_new_rules(new_rules)
    print(f"새로운 규칙이 '{rules_file}'에 저장되었습니다.")

    # 3. 새로운 규칙으로 추가 스캔
    print("\n[3/4] 새로운 규칙으로 추가 스캔 중...")
    additional_findings = run_additional_scan(target_code_path, rules_file)
    additional_results = generate_additional_report(additional_findings)

    # 4. 전체 보고서 생성 및 저장
    print("\n[4/4] 최종 보고서 생성 중...")
    report = {
        "initial_findings": final_results,
        "new_rules": new_rules,
        "additional_findings": additional_results
    }
    
    # JSON 파일로 저장
    with open("security_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print("\n전체 보고서가 'security_report.json'에 저장되었습니다.")

    # 콘솔에 요약 출력
    print("\n=== 분석 결과 요약 ===")
    print(f"- 최초 발견된 취약점 수: {len(final_results)}")
    print(f"- 추가 발견된 취약점 수: {len(additional_results)}")
    print(f"- 전체 보고서: security_report.json")
    print(f"- 생성된 규칙: {rules_file}")

if __name__ == "__main__":

    main()

