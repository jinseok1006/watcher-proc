from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List
from ..process.types import ProcessType

@dataclass
class CommandResult:
    """명령어 파싱 결과"""
    source_files: List[str]  # 소스 파일 경로 목록
    cwd: str                 # 작업 디렉토리
    process_type: ProcessType

class Parser(ABC):
    """명령어 파서 인터페이스"""
    @abstractmethod
    def parse(self, args: str, cwd: str) -> CommandResult:
        """명령어 파싱
        
        Args:
            args: 명령어 인자
            cwd: 현재 작업 디렉토리
            
        Returns:
            CommandResult: 파싱 결과
        """
        pass 