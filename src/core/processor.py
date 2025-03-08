import logging
import asyncio
import ctypes
from datetime import datetime
from typing import Dict, Optional, Any
from ..process.types import ProcessType
from ..process.filter import ProcessFilter
from ..parser.base import Parser, CommandResult
from ..homework.base import HomeworkChecker
from ..bpf.event import ProcessEvent, ProcessEventData

class AsyncEventProcessor:
    """비동기 이벤트 처리"""
    def __init__(self, 
                 event_queue: asyncio.Queue,
                 parser_registry: Dict[ProcessType, Parser],
                 homework_checker: HomeworkChecker):
        self.event_queue = event_queue
        self.logger = logging.getLogger(__name__)
        self._running = True
        self.process_filter = ProcessFilter()
        self.parsers = parser_registry
        self.hw_checker = homework_checker
        self.logger.info("[초기화] AsyncEventProcessor 초기화 완료")

    async def prepare_event(self, data: Any, size: int) -> ProcessEventData:
        self.logger.debug("[이벤트 준비]")
        event = ctypes.cast(data, ctypes.POINTER(ProcessEvent)).contents
        
        binary_path = bytes(event.binary_path[event.binary_path_offset:]).strip(b'\0').decode('utf-8')
        container_id = event.container_id.decode()
        
        process_type = self.process_filter.get_process_type(
            binary_path=binary_path,
            container_id=container_id
        )
        
        event_data = ProcessEventData(
            timestamp=datetime.now().isoformat(),
            pid=event.pid,
            process_type=process_type,
            binary_path=binary_path,
            container_id=container_id,
            cwd=bytes(event.cwd[event.cwd_offset:]).strip(b'\0').decode('utf-8'),
            args=' '.join(arg.decode('utf-8', errors='replace') 
                         for arg in bytes(event.args[:event.args_len]).split(b'\0') if arg),
            error_flags=bin(event.error_flags),
            exit_code=event.exit_code
        )
        self.logger.debug(f"[이벤트 준비 완료] 데이터: {event_data}")
        return event_data

    async def handle_process_event(self, event: ProcessEventData) -> None:
        self.logger.info(
            f"프로세스 정보: "
            f"PID={event.pid}, "
            f"타입={event.process_type.name}, "
            f"경로={event.binary_path}"
        )

        # 1. 사용자 바이너리 실행 처리
        if event.process_type == ProcessType.USER_BINARY:
            try:
                hw_dir = self.hw_checker.get_homework_info(event.binary_path)
                if hw_dir:
                    self.logger.info(
                        f"[실행 감지] "
                        f"과제: {hw_dir}, "
                        f"실행 파일: {event.binary_path}, "
                        f"작업 디렉토리: {event.cwd}, "
                        f"명령줄: {event.args}, "
                        f"종료 코드: {event.exit_code}"
                    )
                    # TODO: API 호출 준비
                    # {
                    #     "homework_dir": hw_dir,
                    #     "binary_path": event.binary_path,
                    #     "working_dir": event.cwd,
                    #     "command_line": event.args,
                    #     "exit_code": event.exit_code,
                    #     "timestamp": event.timestamp
                    # }
                else:
                    self.logger.debug(
                        f"[무시] 과제 디렉토리 외 실행 파일: {event.binary_path}"
                    )
            except Exception as e:
                self.logger.error(
                    f"[오류] 과제 실행 파일 처리 중 오류 발생: {str(e)}, "
                    f"경로: {event.binary_path}"
                )
            return

        # 2. 컴파일러 실행 처리
        parser = self.parsers.get(event.process_type)
        if not parser:
            self.logger.info(
                f"[처리 중단] "
                f"사유: 지원하지 않는 프로세스 타입({event.process_type.name})"
            )
            return
            
        cmd = parser.parse(event.args, event.cwd)
        
        for source_file in cmd.source_files:
            hw_dir = self.hw_checker.get_homework_info(source_file)
            if hw_dir:
                self.logger.info(
                    f"[과제 파일 감지] "
                    f"디렉토리: {hw_dir}, "
                    f"파일: {source_file}"
                )
                # TODO: API 호출 준비
            else:
                self.logger.debug(
                    f"[과제 외 파일] "
                    f"파일: {source_file}"
                )

    async def run(self) -> None:
        """이벤트 처리 메인 루프"""
        self.logger.info("[시작] 이벤트 처리 루프 시작")
        while self._running:
            try:
                data, size = await self.event_queue.get()
                event = await self.prepare_event(data, size)
                
                if event.process_type != ProcessType.UNKNOWN:
                    await self.handle_process_event(event)
                else:
                    self.logger.debug(f"[스킵] 알 수 없는 프로세스 타입")
                
                self.event_queue.task_done()
            except asyncio.CancelledError:
                self.logger.info("[종료] 이벤트 처리 루프 종료 요청")
                break
            except Exception as e:
                self.logger.error(f"[오류] 이벤트 처리 중 오류 발생: {e}") 