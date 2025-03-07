import logging
from .types import ProcessType
from ..config.settings import PROCESS_PATTERNS

class ProcessFilter:
    """프로세스 타입 결정"""
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.patterns = {
            ProcessType[k]: v for k, v in PROCESS_PATTERNS.items()
        }
        self.logger.info(f"[초기화] 프로세스 패턴: {self.patterns}")

    def get_process_type(self, binary_path: str, container_id: str = "") -> ProcessType:
        self.logger.info(f"[검사 시작] 바이너리 경로: {binary_path}")
        
        for proc_type, patterns in self.patterns.items():
            self.logger.debug(f"[패턴 검사] 패턴: {patterns}")
            if any(pattern in binary_path for pattern in patterns):
                matched_patterns = [p for p in patterns if p in binary_path]
                self.logger.info(
                    f"[프로세스 매칭] "
                    f"타입: {proc_type.name}, "
                    f"경로: {binary_path}, "
                    f"매칭된 패턴: {matched_patterns}"
                )
                return proc_type
                
        self.logger.info(f"[필터링] 매칭되지 않은 프로세스: {binary_path}")
        return ProcessType.UNKNOWN 