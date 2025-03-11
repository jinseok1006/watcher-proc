from typing import List
from pathlib import Path

from .base import Parser, CommandResult
from ..process.types import ProcessType
from ..utils.logging import get_logger

class PythonParser(Parser):
    """Python 인터프리터 명령어 파서
    
    python 명령어에서 실행되는 소스 파일을 추출합니다.
    예시:
    - python test.py
    - python3 /home/user/test.py arg1 arg2
    - python -m pytest test_file.py
    """
    
    def __init__(self, process_type: ProcessType):
        self.logger = get_logger(__name__)
        self.process_type = process_type
    
    def parse(self, args: str, cwd: str) -> CommandResult:
        """Python 명령어에서 소스 파일 경로를 추출합니다.
        
        Args:
            args: 명령어 인자 문자열
                예: "script.py arg1 arg2"
                예: "script.py --verbose -o output.txt"
                예: "-m pytest test_file.py"
            cwd: 현재 작업 디렉토리
        """
        try:
            # 빈 문자열이나 공백만 있는 경우
            if not args or args.isspace():
                return CommandResult(source_files=[], cwd=cwd, process_type=self.process_type)
            
            args_list = args.split()
            
            # 첫 번째로 나오는 .py 파일 찾기
            potential_source = None
            for arg in args_list:
                if arg.endswith('.py'):
                    potential_source = arg
                    break
                    
            if not potential_source:
                self.logger.debug("Python 소스 파일을 찾을 수 없음")
                return CommandResult(source_files=[], cwd=cwd, process_type=self.process_type)
            
            # 상대 경로를 절대 경로로 변환
            source_path = str(Path(cwd) / potential_source)
            self.logger.debug(f"Python 소스 파일 발견: {source_path}")
            
            return CommandResult(
                source_files=[source_path],
                cwd=cwd,
                process_type=self.process_type
            )
            
        except Exception as e:
            self.logger.error(f"Python 명령어 파싱 실패: {str(e)}")
            return CommandResult(source_files=[], cwd=cwd, process_type=self.process_type)
