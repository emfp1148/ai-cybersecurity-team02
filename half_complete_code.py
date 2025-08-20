import subprocess
import json
import openai
import os
import sys
import yaml
from typing import List, Dict, Set, Tuple

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

def read_code_snippet(path: str, start_line: int, end_line: int) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
        start = max(0, start_line - 1)
        end = min(len(lines), end_line)
        return "".join(lines[start:end])
    except Exception as e:
        return f"코드 스니펫을 읽을 수 없습니다: {e}"

def generate_attack_pattern(vuln_id: str, code_snippet: str) -> str:
    prompt = (
        f"아래 코드에서 발생할 수 있는 취약점에 대해 어떤 공격 구문이 있을지 테스트 할 수 있는 "
        f"공격 구문만 작성하여 출력해줘. 예를 들어 sqli 이면 ' or 1=1 -- 이런 식으로. "
        f"취약점에 대해서는 설명하지 마. 공격 구문을 제시 못하는 경우는 -:\n{code_snippet}"
    )
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=700
    )
    return response.choices[0].message.content.strip()

def generate_security_patch(vuln_id: str, code_snippet: str) -> str:
    prompt = (
        f"아래 취약한 코드를 보안 패치를 적용한 안전한 코드로 수정해줘. "
        f"원본 구조와 기능은 유지하되 보안 취약점만 해결하고, 기존 주석은 건드리지 말고 "
        f"새 주석을 추가하지 마. 수정된 코드만 출력:\n{code_snippet}"
    )
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1000
    )
    return response.choices[0].message.content.strip()

def is_overlap(range1: Tuple[int, int], range2: Tuple[int, int]) -> bool:
    """두 라인 범위가 겹치는지 확인합니다."""
    start1, end1 = range1
    start2, end2 = range2
    return not (end1 < start2 or end2 < start1)

def postprocess_semgrep_results(semgrep_json: dict) -> List[Dict]:
    processed_results = []
    seen_ranges = {}  # {파일경로: [(start_line,end_line), ...]}

    findings = semgrep_json.get("results", [])
    for finding in findings:
        path = finding.get("path", "Unknown path")
        start = finding.get("start", {}).get("line", 0)
        end = finding.get("end", {}).get("line", start)

        # 중복 검사
        if path in seen_ranges:
            if any(is_overlap((start, end), r) for r in seen_ranges[path]):
                continue
        else:
            seen_ranges[path] = []
        
        seen_ranges[path].append((start, end))
        
        # 코드 스니펫 추출
        code_snippet = read_code_snippet(path, start, end)
        vuln_id = finding.get("check_id", "Unknown")
        
        print(f"LLM 분석 중... 취약점 ID: {vuln_id}")
        attack_pattern = generate_attack_pattern(vuln_id, code_snippet)
        security_patch = generate_security_patch(vuln_id, code_snippet)

        processed_results.append({
            "check_id": vuln_id,
            "path": path,
            "location": {"start": start, "end": end},
            "code": code_snippet,
            "attack_pattern": attack_pattern,
            "security_patch": security_patch,
        })

    return processed_results

def generate_new_rules(findings: List[Dict]) -> str:
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
    if not generated_rules.startswith("rules:"):
        generated_rules = "rules:\n" + generated_rules
    
    return generated_rules

def save_new_rules(rules: str, target_path: str) -> str:
    """생성된 규칙을 YAML 파일로 저장합니다."""
    base_name = os.path.splitext(os.path.basename(target_path))[0]
    filename = f"new_rules_{base_name}.yaml"
    
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

def main():
    print("※ 검사 대상 경로는 루트 기준 상대경로(예: ./a) 형태로 입력하세요.")
    target_code_path = input("검사할 코드 경로를 입력하세요 (예: ./a): ").strip()

    # 1. 기존 스캔 실행
    print("\n[1/4] 기본 보안 규칙으로 스캔 중...")
    semgrep_result = run_semgrep_scan(target_code_path, SEMGREP_CONFIG_PATH)
    initial_findings = postprocess_semgrep_results(semgrep_result)

    # 2. 새로운 규칙 생성
    print("\n[2/4] 추가 보안 규칙 생성 중...")
    new_rules = generate_new_rules(initial_findings)
    rules_file = save_new_rules(new_rules, target_code_path)
    print(f"새로운 규칙이 '{rules_file}'에 저장되었습니다.")

    # 3. 새로운 규칙으로 추가 스캔
    print("\n[3/4] 새로운 규칙으로 추가 스캔 중...")
    additional_result = run_semgrep_scan(target_code_path, rules_file)
    additional_findings = postprocess_semgrep_results(additional_result)

    # 4. 전체 보고서 생성
    print("\n[4/4] 최종 보고서 생성 중...")
    
    # YAML 규칙을 파이썬 객체로 변환
    try:
        parsed_rules = yaml.safe_load(new_rules)
    except yaml.YAMLError as e:
        print(f"경고: 규칙 파싱 중 오류 발생: {e}")
        parsed_rules = {"rules": []}
    
    report = {
        "initial_findings": [
            {
                "check_id": finding["check_id"],
                "path": finding["path"],
                "location": finding["location"],
                "code": finding["code"],
                "attack_pattern": finding["attack_pattern"],
                "security_patch": finding["security_patch"]
            }
            for finding in initial_findings
        ],
        "new_rules": parsed_rules,
        "additional_findings": [
            {
                "check_id": finding["check_id"],
                "path": finding["path"],
                "location": finding["location"],
                "code": finding["code"],
                "attack_pattern": finding["attack_pattern"],
                "security_patch": finding["security_patch"]
            }
            for finding in additional_findings
        ]
    }
    
    base_name = os.path.splitext(os.path.basename(target_code_path))[0]
    report_filename = f"security_report_{base_name}.json"
    
    with open(report_filename, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\n전체 보고서가 '{report_filename}'에 저장되었습니다.")

    # 결과 요약 출력
    print("\n=== 분석 결과 요약 ===")
    print(f"- 최초 발견된 취약점 수: {len(initial_findings)}")
    print(f"- 추가 발견된 취약점 수: {len(additional_findings)}")
    print(f"- 전체 보고서: {report_filename}")
    print(f"- 생성된 규칙: {rules_file}")
    
    # 상세 결과 출력
    print("\n=== 상세 분석 결과 ===")
    for idx, finding in enumerate(initial_findings + additional_findings, 1):
        print(f"\n--- 취약점 #{idx} ---")
        print(f"룰 ID: {finding['check_id']}")
        print(f"파일 경로: {finding['path']}")
        print(f"취약 코드 위치: {finding['location']['start']} line부터 {finding['location']['end']} line까지\n")
        print("=== 취약 코드 스니펫 ===")
        print(finding['code'])
        print("\n=== 공격 패턴 분석 ===")
        print(finding['attack_pattern'])
        print("\n=== 보안 패치 권고 ===")
        print(finding['security_patch'])
        print("=" * 80)

if __name__ == "__main__":
    main()

