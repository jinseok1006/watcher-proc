import re
from collections import defaultdict

# 로그 데이터의 형식을 정의하는 정규 표현식
LOG_PATTERN = re.compile(
    r"\[(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] EXEC "
    r"Container=(?P<container>[a-f0-9]+|unknown) "
    r"PID=(?P<pid>\d+) "
    r"Process=(?P<process>[^\s]+) "
    r"Path=(?P<path>[^\s]+|unknown) "
    r"CMD=(?P<cmd>.*)"
)

# 누락된 필드 또는 "unknown" 값을 집계하기 위한 딕셔너리
field_counts = defaultdict(int)
total_logs = 0

def parse_log_line(line):
    """로그 라인을 파싱하고 필드를 검사합니다."""
    global total_logs
    match = LOG_PATTERN.match(line)
    if not match:
        print(f"Invalid log format: {line}")
        return None
    
    total_logs += 1  # 전체 로그 수 카운트
    fields = match.groupdict()
    for field, value in fields.items():
        # 필드가 비어 있거나 "unknown"인지 확인
        if not value or value.lower() == "unknown":
            field_counts[field] += 1
    
    return fields

def analyze_logs_from_file(file_path):
    """로그 파일을 읽고 분석합니다."""
    try:
        with open(file_path, 'r') as file:
            for line in file:
                parse_log_line(line.strip())
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
    
    # 보고서 생성
    generate_report()

def generate_report():
    """누락된 필드 및 비율을 포함한 보고서를 출력합니다."""
    print("=== Log Analysis Report ===")
    print(f"Total Logs Processed: {total_logs}")
    print("\nField Missing/Unknown Analysis:")
    for field, count in field_counts.items():
        percentage = (count / total_logs) * 100 if total_logs > 0 else 0
        print(f"- {field}: {count} missing or 'unknown' entries ({percentage:.2f}%)")
    
    # 전체 누락 비율 계산
    total_missing = sum(field_counts.values())
    overall_percentage = (total_missing / (total_logs * len(field_counts))) * 100 if total_logs > 0 else 0
    print("\nOverall Missing/Unknown Rate:")
    print(f"- Total Missing/Unknown Entries: {total_missing}")
    print(f"- Overall Missing/Unknown Rate: {overall_percentage:.2f}%")

# 메인 실행
if __name__ == "__main__":
    # 로그 파일 경로
    log_file_path = "./test.log"
    
    # 로그 분석 실행
    analyze_logs_from_file(log_file_path)