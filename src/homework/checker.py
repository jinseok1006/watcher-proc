import logging
from pathlib import Path
from typing import Optional
from .base import HomeworkChecker
from ..config.settings import PROJECT_ROOT

class DefaultHomeworkChecker(HomeworkChecker):
    """기본 과제 디렉토리 체커 구현"""
    def __init__(self, project_root: str = PROJECT_ROOT):
        self.project_root = Path(project_root)
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"[초기화] 프로젝트 루트 설정: {project_root}")

    def get_homework_info(self, file_path: str | Path) -> Optional[str]:
        """과제 디렉토리 정보 확인

        Args:
            file_path: 검사할 파일의 절대 경로
                예시: "/home/coder/project/hw1/main.c"
                예시: "/home/coder/project/hw2/a.out"
                예시: "/usr/bin/gcc"

        Returns:
            Optional[str]: 
                - 성공 시: 과제 디렉토리 이름 (예: "hw1", "hw2")
                - 실패 시: None (프로젝트 외부이거나 과제 디렉토리가 아닌 경우)
        """
        self.logger.info(f"[경로 검사 시작] 파일: {file_path}")
        try:
            path = Path(file_path).resolve()
            if self.project_root in path.parents:
                hw_dir = path.relative_to(self.project_root).parts[0]
                if hw_dir.startswith('hw'):
                    self.logger.info(
                        f"[과제 디렉토리 확인] "
                        f"파일: {file_path}, "
                        f"과제 디렉토리: {hw_dir}"
                    )
                    return hw_dir
                else:
                    self.logger.info(
                        f"[과제 외 디렉토리] "
                        f"파일: {file_path}, "
                        f"디렉토리: {hw_dir}"
                    )
            else:
                self.logger.info(
                    f"[프로젝트 외부 경로] "
                    f"파일: {file_path}, "
                    f"프로젝트 루트: {self.project_root}"
                )
        except Exception as e:
            self.logger.error(f"[경로 검사 실패] 파일: {file_path}, 오류: {e}")
        return None 