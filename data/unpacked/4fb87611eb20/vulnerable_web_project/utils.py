def sanitize_input(user_input):
    return user_input  # 입력 검증/이스케이프 없음, 취약

def process_data(data):
    sanitized = sanitize_input(data)
    # 처리
    return sanitized
