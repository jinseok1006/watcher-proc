from pathlib import Path
from .base import Parser, CommandResult
from ..process.types import ProcessType
from ..utils.logging import get_logger

class PythonParser(Parser):
    """Python 인터프리터 명령어 파서"""
    def __init__(self):
        self.logger = get_logger(__name__)
        self.logger.info("[PythonParser] 파서 초기화 완료")
    
    def parse(self, args: str, cwd: str) -> CommandResult:
        """파이썬 명령어 파싱

        Args:
            args: 명령어 인자 문자열
                예시: "test.py"
                예시: "-m pytest"
                예시: "script.py arg1 arg2"
            cwd: 현재 작업 디렉토리 (절대 경로)
                예시: "/home/coder/project/hw1"

        Returns:
            CommandResult:
                - source_files: 소스 파일 절대 경로 목록 (예: ["/home/coder/project/hw1/test.py"])
                - cwd: 현재 작업 디렉토리 (입력값 그대로)
                - process_type: PYTHON

        Note:
            - -m 옵션으로 실행하는 경우 source_files는 빈 리스트
            - -c 옵션으로 실행하는 경우 source_files는 빈 리스트
            - 일반 .py 파일 실행의 경우만 source_files에 포함
        """
        self.logger.info(f"[PythonParser] 명령어 파싱 시작 - 명령어: {args}")
        args_list = args.split()
        source_files = []
        
        if not args_list:
            self.logger.debug("[PythonParser] 인자가 없음")
            return CommandResult(
                source_files=[],
                cwd=cwd,
                process_type=ProcessType.PYTHON
            )
        
        # -m 또는 -c 옵션 체크
        if args_list[0] in ['-m', '-c']:
            self.logger.debug(f"[PythonParser] 특수 옵션 감지 - 옵션: {args_list[0]}")
            return CommandResult(
                source_files=[],
                cwd=cwd,
                process_type=ProcessType.PYTHON
            )
        
        # .py 파일 찾기
        for arg in args_list:
            if arg.endswith('.py') and not arg.startswith('-'):
                full_path = Path(cwd) / arg
                resolved_path = str(full_path.resolve())
                source_files.append(resolved_path)
                self.logger.info(f"[PythonParser] 소스 파일 발견 - 파일: {resolved_path}")
                break  # 첫 번째 .py 파일만 처리
        
        result = CommandResult(
            source_files=source_files,
            cwd=cwd,
            process_type=ProcessType.PYTHON
        )
        self.logger.info(f"[PythonParser] 명령어 파싱 완료 - 결과: {result}")
        return result
