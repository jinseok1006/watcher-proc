import logging
import sys
import contextvars
from typing import Optional

# PID를 저장할 context variable
current_pid = contextvars.ContextVar('pid', default=None)

class ProcessIdFilter(logging.Filter):
    """PID 정보를 로그 레코드에 추가하는 필터"""
    
    def filter(self, record):
        pid = current_pid.get()
        record.pid = f"PID:{pid}" if pid else "PID:---"
        return True

def get_logger(name: str) -> logging.Logger:
    """PID 정보가 포함된 로거를 반환합니다."""
    logger = logging.getLogger(name)
    logger.addFilter(ProcessIdFilter())
    return logger

def set_pid(pid: Optional[int]):
    """현재 컨텍스트의 PID를 설정합니다."""
    current_pid.set(pid)

def setup_logging(level: int = logging.INFO):
    """기본 로깅 설정
    
    Args:
        level: 로깅 레벨 (기본값: logging.INFO)
    """
    # 루트 로거 설정
    root = logging.getLogger()
    root.setLevel(level)
    
    # 기존 핸들러 제거
    for handler in root.handlers:
        root.removeHandler(handler)
    
    # 새 핸들러 생성 및 설정
    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(ProcessIdFilter())
    handler.setFormatter(
        logging.Formatter('%(asctime)s - %(levelname)s - [%(pid)s] - %(name)s - %(message)s')
    )
    
    # 핸들러 추가
    root.addHandler(handler)
    
    # 설정 완료 로그
    logger = get_logger(__name__)
    logger.debug(f"[설정] 로깅 설정 완료 (레벨: {logging.getLevelName(level)})") 