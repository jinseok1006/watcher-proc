import os
from typing import Optional, Dict
from pathlib import Path

from .base import EventHandler
from ..events.models import EventBuilder, HomeworkInfo
from ..homework.base import HomeworkChecker
from ..process.types import ProcessType
from ..parser.base import Parser
from ..parser.compiler import CCompilerParser

class HomeworkHandler(EventHandler[EventBuilder, EventBuilder]):
    """과제 정보 처리 핸들러
    
    실행된 프로세스가 과제와 관련된 경우 과제 정보를 추가합니다.
    """
    
    def __init__(self, homework_checker: HomeworkChecker):
        """초기화
        
        Args:
            homework_checker: 과제 체커
            
        Note:
            과제 디렉토리는 정확한 매칭을 위해 절대 경로로 변환됩니다.
        """
        super().__init__()
        self.homework_checker = homework_checker
        # 컴파일러별 파서 초기화
        self.parsers: Dict[ProcessType, Parser] = {
            ProcessType.GCC: CCompilerParser(ProcessType.GCC),
            ProcessType.CLANG: CCompilerParser(ProcessType.CLANG)
        }
    
    async def handle(self, builder: EventBuilder) -> Optional[EventBuilder]:
        """이벤트 처리
        
        Args:
            builder: 이벤트 빌더
            
        Returns:
            처리된 이벤트 빌더 또는 None
        """
        try:
            self.logger.info(f"[HomeworkHandler] 과제 정보 처리 시작 - PID: {builder.base.pid}")
            
            # 과제 디렉토리 확인
            homework_dir = self.homework_checker.get_homework_info(builder.base.binary_path)
            if not homework_dir:
                self.logger.info(f"[HomeworkHandler] 과제 디렉토리 아님 - PID: {builder.base.pid}, 경로: {builder.base.binary_path}")
                return await self._handle_next(builder)
                
            # 컴파일러인 경우 소스 파일 파싱
            source_file = None
            if builder.process and builder.process.type in (ProcessType.GCC, ProcessType.CLANG):
                try:
                    args = builder.base.args.split()
                    for arg in reversed(args):
                        if arg.endswith('.c'):
                            source_file = os.path.basename(arg)
                            break
                except Exception as e:
                    self.logger.error(f"[HomeworkHandler] 소스 파일 파싱 실패 - PID: {builder.base.pid}, 오류: {str(e)}")
            
            # 과제 정보 설정
            builder.homework = HomeworkInfo(
                homework_dir=homework_dir,
                source_file=source_file
            )
            
            self.logger.info(
                f"[HomeworkHandler] 과제 정보 처리 완료 - "
                f"PID: {builder.base.pid}, "
                f"과제 디렉토리: {homework_dir}, "
                f"소스 파일: {source_file or '없음'}"
            )
            
            return await self._handle_next(builder)
            
        except Exception as e:
            self.logger.error(f"[HomeworkHandler] 과제 정보 처리 실패 - PID: {builder.base.pid}, 오류: {str(e)}")
            raise 