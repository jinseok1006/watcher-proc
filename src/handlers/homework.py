import os
from typing import Optional, Dict
from pathlib import Path

from .base import EventHandler
from ..events.models import EventBuilder, HomeworkInfo
from ..homework.checker import HomeworkChecker
from ..process.types import ProcessType
from ..parser.base import Parser
from ..parser.compiler import CCompilerParser
from ..parser.python import PythonParser
from ..utils.logging import get_logger

class HomeworkHandler(EventHandler[EventBuilder, EventBuilder]):
    """과제 정보 처리 핸들러
    
    실행된 프로세스가 과제와 관련된 경우 과제 정보를 추가합니다.
    1. 유저 바이너리인 경우: 실행 파일이 과제 디렉토리 내에 있는지 확인
    2. 컴파일러/인터프리터 프로세스인 경우: 명령어에서 소스 파일을 추출하고 과제 디렉토리 확인
    """
    
    def __init__(self, homework_checker: HomeworkChecker):
        self.logger = get_logger(__name__)
        self.hw_checker = homework_checker
        self.gcc_parser = CCompilerParser(ProcessType.GCC)
        self.clang_parser = CCompilerParser(ProcessType.CLANG)
        self.python_parser = PythonParser(ProcessType.PYTHON)
    
    def _get_parser(self, process_type: ProcessType) -> Optional[Parser]:
        """프로세스 타입에 맞는 파서를 반환합니다."""
        if process_type == ProcessType.GCC:
            return self.gcc_parser
        elif process_type == ProcessType.CLANG:
            return self.clang_parser
        elif process_type == ProcessType.PYTHON:
            return self.python_parser
        return None
    
    async def _handle_user_binary(self, builder: EventBuilder) -> Optional[EventBuilder]:
        """유저 바이너리 실행을 처리합니다."""
        try:
            hw_dir = self.hw_checker.get_homework_info(builder.base.binary_path)
            if hw_dir:
                builder.homework = HomeworkInfo(homework_dir=hw_dir, source_file=None)
                self.logger.info(f"과제 정보 설정 - 바이너리 실행: {builder.base.binary_path}, 과제: {hw_dir}")
            else:
                self.logger.debug(f"무시 - 과제 디렉토리 외 실행 파일: {builder.base.binary_path}")
            return await self._handle_next(builder)
        except Exception as e:
            self.logger.error(f"과제 실행 파일 처리 오류 - {str(e)}, 경로: {builder.base.binary_path}")
            return None

    async def _handle_source_file(self, builder: EventBuilder, parser: Parser) -> Optional[EventBuilder]:
        """소스 파일을 파싱하고 과제 관련 여부를 확인합니다."""
        try:
            self.logger.debug(f"소스 파일 처리 시작 - 타입: {builder.process.type}, 명령어: {builder.base.args}")
            
            result = parser.parse(builder.base.args, builder.base.cwd)
            if not result.source_files:
                self.logger.debug(
                    f"소스 파일 없음 - "
                    f"실행 파일: {builder.base.binary_path}, "
                    f"작업 디렉토리: {builder.base.cwd}, "
                    f"명령어: {builder.base.args}"
                )
                return None
            
            self.logger.debug(f"소스 파일 발견 - 개수: {len(result.source_files)}")
            
            source_file = result.source_files[0]
            hw_dir = self.hw_checker.get_homework_info(source_file)
            if hw_dir:
                self.logger.info(f"과제 정보 설정 - 실행: {source_file}, 과제: {hw_dir}")
                builder.homework = HomeworkInfo(homework_dir=hw_dir, source_file=source_file)
                return await self._handle_next(builder)
            else:
                self.logger.debug(f"과제 외 소스 파일 - 파일: {source_file}")
                return None
                
        except Exception as e:
            self.logger.error(f"소스 파일 처리 오류 - {str(e)}")
            return None
    
    async def handle(self, builder: EventBuilder) -> Optional[EventBuilder]:
        """이벤트를 처리합니다.
        
        프로세스 타입에 따라 다른 처리를 수행합니다:
        - USER_BINARY: 실행 파일이 과제 디렉토리 내에 있는지 확인
        - GCC/CLANG: 소스 파일을 추출하고 과제 디렉토리 확인
        """
        self.logger.info("=== 이벤트 파싱 완료 ===")
        self.logger.info(f"프로세스: {builder.process.type}")
        self.logger.info(f"실행 파일: {builder.base.binary_path}")
        
        try:
            if builder.process.type == ProcessType.USER_BINARY:
                self.logger.info("유저 바이너리 처리 시작")
                return await self._handle_user_binary(builder)
                
            parser = self._get_parser(builder.process.type)
            if parser:
                self.logger.info("컴파일러/인터프리터 처리 시작")
                return await self._handle_source_file(builder, parser)
            
            self.logger.info(f"처리하지 않는 프로세스 타입: {builder.process.type}")
            return await self._handle_next(builder)
            
        except Exception as e:
            self.logger.error(f"오류 - 상세 정보: {str(e)}", exc_info=True)
            return await self._handle_next(builder)  # 오류 발생해도 체인 계속 진행 