from abc import ABC, abstractmethod
from typing import Optional
from pathlib import Path

class HomeworkChecker(ABC):
    """과제 디렉토리 체커 인터페이스"""
    @abstractmethod
    def get_homework_info(self, file_path: str | Path) -> Optional[str]:
        """과제 디렉토리 정보 확인
        
        Args:
            file_path: 검사할 파일 경로
            
        Returns:
            Optional[str]: 과제 디렉토리명 (예: 'hw1') 또는 None
        """
        pass 