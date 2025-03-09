import logging
from typing import Dict, List
from .types import ProcessType
from ..config.settings import settings

class ProcessFilter:
    """프로세스 타입 결정"""
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.patterns: Dict[ProcessType, List[str]] = {
            ProcessType[k]: v for k, v in settings.PROCESS_PATTERNS.items()
        }
        self.logger.info(f"[초기화] 프로세스 패턴: {self.patterns}")

    def get_process_type(self, binary_path: str, container_id: str = "") -> ProcessType:
        """실행된 프로세스의 타입을 결정

        Args:
            binary_path: 실행 파일의 절대 경로
                예시: "/usr/lib/llvm-18/bin/clang" (컴파일러)
                예시: "/home/coder/project/hw1/a.out" (과제 실행 파일)
                예시: "/usr/bin/ls" (기타 프로세스)
            container_id: 컨테이너 ID (선택적)
                예시: "9a879f2ecd37"

        Returns:
            ProcessType:
                - GCC: gcc 컴파일러 실행 시
                - CLANG: clang 컴파일러 실행 시
                - PYTHON: python 인터프리터 실행 시
                - USER_BINARY: 과제 디렉토리 내 실행 파일 실행 시
                - UNKNOWN: 그 외 모든 경우

        Note:
            1. 시스템 바이너리 체크 -> 과제 실행 파일 체크 -> UNKNOWN 순으로 검사
            2. 과제 디렉토리는 '/home/coder/project/hw*' 형식이어야 함
        """
        try:
            # 1. 시스템 바이너리 (컴파일러/인터프리터) 체크
            for proc_type, patterns in self.patterns.items():
                if any(pattern in binary_path for pattern in patterns):
                    self.logger.info(
                        f"[감지] 시스템 프로세스: {proc_type.name}, "
                        f"경로: {binary_path}"
                    )
                    return proc_type

            # 2. 과제 디렉토리 내 실행 파일 체크
            if binary_path.startswith('/home/coder/project'):
                if hw_dir := self.hw_checker.get_homework_info(binary_path):
                    self.logger.info(
                        f"[감지] 과제 실행 파일: "
                        f"경로: {binary_path}, "
                        f"과제: {hw_dir}"
                    )
                    return ProcessType.USER_BINARY

            # 3. 그 외는 무시
            self.logger.debug(f"[스킵] 무시된 프로세스: {binary_path}")
            return ProcessType.UNKNOWN
            
        except Exception as e:
            self.logger.error(f"[오류] 프로세스 타입 결정 실패: {binary_path}, {str(e)}")
            return ProcessType.UNKNOWN 