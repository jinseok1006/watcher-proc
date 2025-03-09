import logging
import asyncio
import ctypes
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional, Any
from ..process.types import ProcessType
from ..process.filter import ProcessFilter
from ..parser.base import Parser, CommandResult
from ..homework.base import HomeworkChecker
from ..bpf.event import ProcessEvent, ProcessEventData


@dataclass
class EnrichedProcessEvent:
    """확장된 프로세스 이벤트 데이터"""
    # BPF 이벤트 필드들
    timestamp: str
    pid: int
    process_type: ProcessType
    binary_path: str
    container_id: str
    cwd: str
    args: str
    error_flags: str
    exit_code: int
    
    # 쿠버네티스 관련 확장 필드들
    pod_name: str
    namespace: str
    class_div: str  # e.g. "os-1"
    student_id: str  # e.g. "202012180"
    
    @classmethod
    def from_bpf_event(cls, bpf_event: ProcessEventData, **extra_fields) -> 'EnrichedProcessEvent':
        return cls(
            timestamp=bpf_event.timestamp,
            pid=bpf_event.pid,
            process_type=bpf_event.process_type,
            binary_path=bpf_event.binary_path,
            container_id=bpf_event.container_id,
            cwd=bpf_event.cwd,
            args=bpf_event.args,
            error_flags=bpf_event.error_flags,
            exit_code=bpf_event.exit_code,
            **extra_fields
        )


class AsyncEventProcessor:
    """비동기 이벤트 처리"""
    def __init__(self, 
                 event_queue: asyncio.Queue,
                 parser_registry: Dict[ProcessType, Parser],
                 homework_checker: HomeworkChecker,
                 container_repository: 'ContainerHashRepository'):  # 타입 힌트는 문자열로
        self.event_queue = event_queue
        self.logger = logging.getLogger(__name__)
        self._running = True
        self.hw_checker = homework_checker
        self.process_filter = ProcessFilter(homework_checker)  # homework_checker 전달
        self.parsers = parser_registry
        self.container_repository = container_repository  # 컨테이너 저장소 참조 저장
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

    async def enrich_event(self, bpf_event: ProcessEventData) -> Optional[EnrichedProcessEvent]:
        """BPF 이벤트를 확장된 이벤트로 변환"""
        if not bpf_event.container_id:
            self.logger.error(f"[오류] 컨테이너 ID가 없는 이벤트: {bpf_event}")
            return None
            
        # 컨테이너 ID의 처음 12자리가 해시값
        container_hash = bpf_event.container_id[:12]
        pod_info = self.container_repository.find_by_hash(container_hash)
        if not pod_info:
            self.logger.debug(f"[스킵] 컨테이너 해시에 매핑되는 파드 정보 없음: {container_hash}")
            return None
        
        # 파드 네임 파싱: "jcode-os-1-202012180-hash(-hash...)"
        parts = pod_info['pod_name'].split('-')
        if len(parts) < 5:  # 최소 5개 부분은 있어야 함
            self.logger.error(f"[스킵] 잘못된 파드 네임 형식: {pod_info['pod_name']}")
            return None
            
        class_div = f"{parts[1]}-{parts[2]}"  # "os-1" (항상 2,3번째 부분)
        student_id = parts[3]  # "202012180" (항상 4번째 부분)
        
        self.logger.debug(
            f"[컨테이너-파드 매핑] "
            f"컨테이너 해시: {container_hash}, "
            f"파드: {pod_info['pod_name']}, "
            f"분반: {class_div}, "
            f"학번: {student_id}"
        )
        
        return EnrichedProcessEvent.from_bpf_event(
            bpf_event,
            pod_name=pod_info['pod_name'],
            namespace=pod_info['namespace'],
            class_div=class_div,
            student_id=student_id
        )

    async def handle_process_event(self, event: EnrichedProcessEvent) -> None:
        self.logger.info(
            f"프로세스 정보: "
            f"PID={event.pid}, "
            f"타입={event.process_type.name}, "
            f"경로={event.binary_path}, "
            f"파드={event.pod_name}, "
            f"분반={event.class_div}, "
            f"학번={event.student_id}"
        )

        # 1. 사용자 바이너리 실행 처리
        if event.process_type == ProcessType.USER_BINARY:
            try:
                hw_dir = self.hw_checker.get_homework_info(event.binary_path)
                if hw_dir:  # hw1과 같은 형태
                    self.logger.info(
                        f"[API 발송 준비] 바이너리 실행: "
                        f"과제={hw_dir}, "
                        f"학번={event.student_id}, "
                        f"분반={event.class_div}, "
                        f"실행 파일={event.binary_path}, "
                        f"작업 디렉토리={event.cwd}, "
                        f"명령줄={event.args}, "
                        f"종료 코드={event.exit_code}, "
                        f"타임스탬프={event.timestamp}"
                    )
                    # TODO: API 호출
                else:
                    self.logger.debug(f"[무시] 과제 디렉토리 외 실행 파일: {event.binary_path}")
            except Exception as e:
                self.logger.error(f"[오류] 과제 실행 파일 처리 중 오류 발생: {str(e)}, 경로: {event.binary_path}")
            return

        # 2. 컴파일러 실행 처리
        parser = self.parsers.get(event.process_type)
        if not parser:
            self.logger.info(f"[처리 중단] 사유: 지원하지 않는 프로세스 타입({event.process_type.name})")
            return
            
        cmd = parser.parse(event.args, event.cwd)
        
        for source_file in cmd.source_files:
            hw_dir = self.hw_checker.get_homework_info(source_file)
            if hw_dir:
                self.logger.info(
                    f"[API 발송 준비] 컴파일: "
                    f"과제={hw_dir}, "
                    f"학번={event.student_id}, "
                    f"분반={event.class_div}, "
                    f"소스={source_file}, "
                    f"컴파일러={event.binary_path}, "
                    f"작업 디렉토리={event.cwd}, "
                    f"명령줄={event.args}, "
                    f"타임스탬프={event.timestamp}"
                )
                # TODO: API 호출
            else:
                self.logger.debug(f"[무시] 과제 외 파일: {source_file}")

    async def run(self) -> None:
        """이벤트 처리 메인 루프"""
        self.logger.info("[시작] 이벤트 처리 루프 시작")
        while self._running:
            try:
                data, size = await self.event_queue.get()
                
                # 1. BPF 이벤트 준비
                bpf_event = await self.prepare_event(data, size)
                
                # 2. 알 수 없는 프로세스 타입 필터링
                if bpf_event.process_type == ProcessType.UNKNOWN:
                    self.logger.debug(f"[스킵] 알 수 없는 프로세스 타입")
                    self.event_queue.task_done()
                    continue
                
                # 3. 이벤트 확장 (컨테이너 -> 파드 정보)
                enriched_event = await self.enrich_event(bpf_event)
                if enriched_event is None:
                    self.event_queue.task_done()
                    continue
                
                # 4. 이벤트 처리
                await self.handle_process_event(enriched_event)
                
                self.event_queue.task_done()
            except asyncio.CancelledError:
                self.logger.info("[종료] 이벤트 처리 루프 종료 요청")
                break
            except Exception as e:
                self.logger.error(f"[오류] 이벤트 처리 중 오류 발생: {e}") 