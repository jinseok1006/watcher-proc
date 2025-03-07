import logging
from pathlib import Path
from .base import Parser, CommandResult
from ..process.types import ProcessType
from ..config.settings import COMPILER_SKIP_OPTIONS

class CCompilerParser(Parser):
    """gcc/clang 명령어 파서"""
    def __init__(self, process_type: ProcessType):
        self.process_type = process_type
        self.logger = logging.getLogger(__name__)
        self.skip_options = COMPILER_SKIP_OPTIONS
        self.logger.info(f"[초기화] {process_type.name} 파서 생성됨")
    
    def parse(self, args: str, cwd: str) -> CommandResult:
        self.logger.info(f"[파싱 시작] 명령어: {args}")
        args_list = args.split()
        source_files = []
        skip_next = False
        
        for arg in args_list:
            if skip_next:
                skip_next = False
                continue
            
            if arg in self.skip_options:
                self.logger.debug(f"[옵션 스킵] 옵션: {arg}")
                skip_next = True
                continue
                
            if arg.endswith('.c') and not arg.startswith('-'):
                full_path = Path(cwd) / arg
                resolved_path = str(full_path.resolve())
                source_files.append(resolved_path)
                self.logger.info(f"[소스 파일 발견] 파일: {resolved_path}")
        
        result = CommandResult(
            source_files=source_files,
            cwd=cwd,
            process_type=self.process_type
        )
        self.logger.info(f"[파싱 완료] 결과: {result}")
        return result 