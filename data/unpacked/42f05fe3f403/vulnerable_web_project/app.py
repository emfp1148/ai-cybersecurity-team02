from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

@app.route('/semgrep', methods=['POST'])
def run_semgrep():
    code = request.json.get('code', '')
    if not code:
        return jsonify({'error': 'No code provided'}), 400

    # 임시 파일에 코드를 저장
    with open('temp_code.py', 'w') as f:
        f.write(code)

    # semgrep 실행 (예: 기본 python 규칙, json 출력)
    try:
        result = subprocess.run(
            ['semgrep', '--json', '--config', 'p/python', 'temp_code.py'],
            capture_output=True, text=True, check=True
        )
        return jsonify({'result': result.stdout})
    except subprocess.CalledProcessError as e:
        return jsonify({'error': e.stderr}), 500

if __name__ == '__main__':
    app.run(debug=True)
