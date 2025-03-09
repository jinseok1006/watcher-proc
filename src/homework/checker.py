import re
import logging
from pathlib import Path
from typing import Optional, Tuple
from .base import HomeworkChecker
from ..config.settings import settings

class DefaultHomeworkChecker(HomeworkChecker):
    """과제 디렉토리 체커 구현"""
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.path_pattern = re.compile(settings.homework_path_pattern)
        self.logger.info(
            f"[초기화] 과제 체커 초기화 "
            f"(경로 패턴: {settings.homework_path_pattern})"
        )

    def _extract_hw_dir(self, path: Path) -> Tuple[Optional[str], str]:
        """과제 디렉토리 추출 및 검증

        Args:
            path: 검사할 경로

        Returns:
            Tuple[Optional[str], str]: (과제 디렉토리명, 로그 메시지)
        """
        path_str = str(path)
        
        # 전체 경로 패턴 검사
        match = self.path_pattern.match(path_str)
        if not match:
            return None, f"[유효하지 않은 경로 패턴] 파일: {path_str}"
            
        try:
            # 경로의 부모 디렉토리들 확인
            parts = path.parts
            if len(parts) < 3:  # 최소 /{과목-분반-학번}/hw{숫자} 형식 필요
                return None, f"[경로가 너무 짧음] 파일: {path_str}"
            
            # 두 번째 부분이 과제 디렉토리여야 함
            hw_dir = parts[2]
            
            # 과제 디렉토리 이후에 다른 hw 디렉토리가 있는지 확인
            for part in parts[3:]:
                if part.startswith('hw'):
                    return None, f"[중첩된 과제 디렉토리 발견] 파일: {path_str}"
            
            return hw_dir, f"[과제 디렉토리 확인] 파일: {path_str}, 과제 디렉토리: {hw_dir}"
        except IndexError:
            return None, f"[경로 구조 오류] 파일: {path_str}"

    def get_homework_info(self, file_path: str | Path) -> Optional[str]:
        """과제 디렉토리 정보 확인

        Args:
            file_path: 검사할 파일의 절대 경로
                예시: "/os-5-202012180/hw1/main"
                예시: "/network-1-201912345/hw2/a.out"
                
        Note:
            - 경로는 HOMEWORK_PATH_PATTERN 환경변수에 맞는 형식이어야 함
            - 기본 패턴: /과목-분반-학번/hw숫자/
            - 올바른 예:
                - /os-5-202012180/hw1/...
                - /network-1-201912345/hw2/...
            - 잘못된 예:
                - /tmp/hw1/...
                - /os-5-202012180/abc/hw1/...

        Returns:
            Optional[str]: 
                - 성공 시: 과제 디렉토리 이름 (예: "hw1", "hw2")
                - 실패 시: None
        """
        self.logger.info(f"[경로 검사 시작] 파일: {file_path}")
        try:
            path = Path(file_path).resolve()
            hw_dir, log_msg = self._extract_hw_dir(path)
            self.logger.info(log_msg)
            return hw_dir
            
        except Exception as e:
            self.logger.error(f"[경로 검사 실패] 파일: {file_path}, 오류: {e}")
            return None 