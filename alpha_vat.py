import subprocess
import json
import openai
import os
import sys
import yaml
import chardet
from typing import List, Dict, Set, Tuple

openai.api_key = ""

target_code_path = ""

if not openai.api_key:
    raise RuntimeError("환경변수 OPENAI_API_KEY가 설정되지 않았습니다. 먼저 설정해주세요.")

# 기본 Semgrep Registry config 경로 설정
SEMGREP_CONFIG_PATH = "p/owasp-top-ten"

def run_semgrep_scan(target_path: str, config_path: str) -> dict:
    """Semgrep으로 코드를 스캔합니다."""
    
    if not config_path.startswith("p/"):
        config_path = os.path.abspath(config_path)
    
    try:
        # 환경 변수 설정으로 경고 메시지 억제
        env = os.environ.copy()
        env["PYTHONWARNINGS"] = "ignore"
        
        result = subprocess.run(
            ["semgrep", 
             "--json",
             "--quiet",  
             "--disable-version-check",
             "--config", config_path,
             target_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            env=env  # 수정된 환경 변수 적용
        )
        
        # 실제 오류와 경고 구분
        if result.returncode > 1:  # 0,1은 정상 종료 코드
            real_errors = [line for line in result.stderr.splitlines() 
                         if not line.startswith('[WARNING]') 
                         and 'UserWarning' not in line]
            if real_errors:
                raise RuntimeError("\n".join(real_errors))
            
        try:
            scan_result = json.loads(result.stdout)
            return scan_result
        except json.JSONDecodeError:
            print("스캔 결과 없음")
            return {"results": []}
            
    except FileNotFoundError:
        raise RuntimeError("Semgrep이 설치되어 있지 않습니다. 'pip install semgrep'로 설치해주세요.")
    except Exception as e:
        if "WARNING" in str(e) or "UserWarning" in str(e):
            # 경고는 무시하고 빈 결과 반환
            print("경고를 무시하고 계속 진행합니다.")
            return {"results": []}
        raise RuntimeError(f"예기치 않은 오류 발생: {str(e)}")

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

def read_file_with_detected_encoding(path: str) -> List[str]:
    """파일의 인코딩을 자동으로 감지하여 읽습니다."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
            encoding = chardet.detect(raw)["encoding"] or "utf-8"
        return raw.decode(encoding, errors="replace").splitlines()
    except Exception as e:
        return [f"코드 스니펫을 읽는 중 오류 발생: {e}"]

def emphasize_and_extract_comments(code_lines: List[str], file_path: str) -> Tuple[str, str]:
    """코드에서 주석을 강조하고 추출합니다."""
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

def postprocess_semgrep_results(semgrep_json: dict) -> List[Dict]:
    processed_results = []
    seen_ranges = {}  # {파일경로: [(start_line,end_line), ...]}
    all_detected_comments = []  # 주석만 따로 저장

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
        
        # 코드 스니펫과 주석 추출
        lines = read_file_with_detected_encoding(path)
        start_idx = max(start - 3, 0)
        end_idx = min(end + 2, len(lines))
        snippet_lines = lines[start_idx:end_idx]
        
        code_snippet, comments = emphasize_and_extract_comments(snippet_lines, path)
        vuln_id = finding.get("check_id", "Unknown")
        
        if comments:
            all_detected_comments.append(f"[{vuln_id}] {path} (Line {start})\n{comments}\n")
        
        attack_pattern = generate_attack_pattern(vuln_id, code_snippet)
        security_patch = generate_security_patch(vuln_id, code_snippet)

        processed_results.append({
            "check_id": vuln_id,
            "path": path,
            "location": {"start": start, "end": end},
            "code": code_snippet,
            "comments": comments,  # 주석 정보 추가
            "attack_pattern": attack_pattern,
            "security_patch": security_patch,
        })

    # 탐지된 주석 출력
    #if all_detected_comments:
    #    for comment in all_detected_comments:

    return processed_results

def generate_new_rules(findings: List[Dict]) -> str:
    """분석된 취약점을 바탕으로 새로운 Semgrep 규칙을 생성합니다."""
    context = "\n\n".join([
        f"취약점 ID: {finding['check_id']}\n"
        f"취약 코드:\n{finding['code']}\n"
        f"공격 패턴:\n{finding['attack_pattern']}"
        for finding in findings
    ])
    
    prompt = f"""다음은 발견된 보안 취약점들의 목록입니다:

{context}

위 취약점들을 분석하여 Semgrep 규칙을 YAML 형식으로 작성해주세요.
각 취약점 패턴마다 새로운 규칙을 만들어주세요.

규칙 작성 시 다음 사항을 반드시 준수해주세요:
1. 각 규칙은 고유한 id를 가져야 합니다
2. pattern은 실제 코드 패턴을 반영해야 합니다
3. message는 구체적인 취약점 설명을 포함해야 합니다
4. severity는 취약점의 심각도를 반영해야 합니다 (WARNING, ERROR, INFO)

예시 형식:
rules:
  - id: custom_sql_injection_1
    pattern: "SELECT ... WHERE ... = '$...'"
    message: "SQL 인젝션 취약점: 사용자 입력을 직접 쿼리에 사용"
    languages: [python]
    severity: ERROR

  - id: xss_vulnerability_1
    pattern: response.write("..." + user_input + "...")
    message: "XSS 취약점: 사용자 입력을 이스케이프 처리 없이 출력"
    languages: [python]
    severity: ERROR"""

    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7,  # 창의성 조절
        max_tokens=2000   # 더 긴 응답 허용
    )
    
    generated_rules = response.choices[0].message.content.strip()
    return generated_rules

def ensure_directory_exists(directory: str) -> None:
    """지정된 디렉토리가 없으면 생성합니다."""
    if not os.path.exists(directory):
        os.makedirs(directory)

def save_new_rules(rules: str, target_path: str) -> str:
    """생성된 규칙을 YAML 파일로 저장합니다."""
    # new_rules 폴더 생성
    rules_dir = "new_rules"
    ensure_directory_exists(rules_dir)
    
    base_name = os.path.splitext(os.path.basename(target_path))[0]
    filename = f"new_rules_{base_name}.yaml"
    filepath = os.path.join(rules_dir, filename)
    
    try:
        # YAML 유효성 검사
        parsed_rules = yaml.safe_load(rules)
        
        # 기본적인 구조 검사
        if not isinstance(parsed_rules, dict) or "rules" not in parsed_rules:
            raise ValueError("규칙이 올바른 형식이 아닙니다")
        
        if not parsed_rules["rules"]:
            raise ValueError("규칙이 비어있습니다")
        
        # 각 규칙의 필수 필드 검사
        required_fields = {"id", "pattern", "message", "languages", "severity"}
        for rule in parsed_rules["rules"]:
            missing_fields = required_fields - set(rule.keys())
            if missing_fields:
                raise ValueError(f"규칙에 필수 필드가 누락됨: {missing_fields}")
        
        # 유효한 규칙이면 저장
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(rules)
        return filepath
        
    except (yaml.YAMLError, ValueError) as e:
        
        # 규칙 재생성 시도
        prompt = f"""이전 규칙 생성에 문제가 있었습니다. 다음 형식을 정확히 지켜서 다시 작성해주세요:

rules:
  - id: unique_rule_id
    pattern: |
      $PATTERN = dangerous_function($INPUT)
    message: "구체적인 취약점 설명"
    languages: [python]
    severity: ERROR"""
        
        response = openai.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.5
        )
        
        new_rules = response.choices[0].message.content.strip()
        
        # 재생성된 규칙 저장
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(new_rules)
        
        return filepath

def main():
    global target_code_path

    if len(sys.argv) >= 2:
        target_code_path = sys.argv[1]
    else:
        print("※ 검사 대상 경로는 루트 기준 상대경로(예: ./a) 형태로 입력하세요.")
        target_code_path = input("검사할 코드 경로를 입력하세요 (예: ./a): ").strip()

    # 1. 기존 스캔 실행
    semgrep_result = run_semgrep_scan(target_code_path, SEMGREP_CONFIG_PATH)
    initial_findings = postprocess_semgrep_results(semgrep_result)

    # 2. 새로운 규칙 생성
    new_rules = generate_new_rules(initial_findings)
    rules_file = save_new_rules(new_rules, target_code_path)

    # 3. 새로운 규칙으로 추가 스캔
    additional_result = run_semgrep_scan(target_code_path, rules_file)
    additional_findings = postprocess_semgrep_results(additional_result)

    # 4. 전체 보고서 생성
    
    # security_report 폴더 생성
    report_dir = "security_report"
    ensure_directory_exists(report_dir)
    
    # YAML 규칙을 파이썬 객체로 변환
    try:
        parsed_rules = yaml.safe_load(new_rules)
    except yaml.YAMLError as e:
        parsed_rules = {"rules": []}
    
    report = {
        "initial_findings": [
            {
                "check_id": finding["check_id"],
                "path": finding["path"],
                "location": finding["location"],
                "code": finding["code"],
                "comments": finding.get("comments", ""),
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
                "comments": finding.get("comments", ""),
                "attack_pattern": finding["attack_pattern"],
                "security_patch": finding["security_patch"]
            }
            for finding in additional_findings
        ]
    }
    
    base_name = os.path.splitext(os.path.basename(target_code_path))[0]
    report_filename = f"security_report_{base_name}.json"
    report_filepath = os.path.join(report_dir, report_filename)
    
    with open(report_filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    
    # 결과 요약 출력
    print("\n=== 분석 결과 요약 ===")
    print(f"- 최초 발견된 취약점 수: {len(initial_findings)}")
    print(f"- 추가 발견된 취약점 수: {len(additional_findings)}")
    
    # 상세 결과 출력
    print("\n=== 상세 분석 결과 ===")
    for idx, finding in enumerate(initial_findings + additional_findings, 1):
        print(f"\n--- 취약점 #{idx} ---")
        print(f"룰 ID: {finding['check_id']}")
        tacp = target_code_path.replace('./','')
        Path = finding['path'].replace(tacp,'')
        print(f"파일 경로: {Path}")
        print(f"취약 코드 위치: {finding['location']['start']} line부터 {finding['location']['end']} line까지\n")
        print("=== 취약 코드 ===")
        print(finding['code'])
        print("\n=== 예상 공격 페이로드 ===")
        print(finding['attack_pattern'])
        print("\n=== 보안 패치 방안 ===")
        print(finding['security_patch'])
        print("=" * 80)

if __name__ == "__main__":
    main()

