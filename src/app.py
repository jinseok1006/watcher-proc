#!/usr/bin/python3
from bcc import BPF
import ctypes
import os
import asyncio
import threading
import logging
from datetime import datetime
from typing import Dict, Any, List
from dataclasses import dataclass
from enum import Enum, auto

# 상수 정의
CONTAINER_ID_LEN = 12
MAX_PATH_LEN = 256
ARGSIZE = 384

class ProcessType(Enum):
    UNKNOWN = auto()
    COMPILER = auto()
    INTERPRETER = auto()
    USER_BINARY = auto()

@dataclass
class ProcessEventData:
    """프로세스 이벤트 데이터 클래스"""
    timestamp: str
    pid: int
    process_type: ProcessType
    binary_path: str
    container_id: str
    cwd: str
    args: str
    error_flags: str
    exit_code: int

class ProcessFilter:
    """프로세스 필터링 로직"""
    def __init__(self):
        # 초기 필터 패턴 설정
        self.patterns = {
            ProcessType.COMPILER: ['/usr/bin/x86_64-linux-gnu-gcc-13'],
            ProcessType.INTERPRETER: ['/usr/bin/python3.12'],
            ProcessType.USER_BINARY: ['/home/', '/tmp/']
        }

    def get_process_type(self, binary_path: str, container_id: str = "") -> ProcessType:
        for proc_type, patterns in self.patterns.items():
            if any(pattern in binary_path for pattern in patterns):
                return proc_type
        return ProcessType.UNKNOWN

class ProcessEvent(ctypes.Structure):
    """프로세스 이벤트 데이터 구조체"""
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("error_flags", ctypes.c_uint32),
        ("container_id", ctypes.c_char * CONTAINER_ID_LEN),
        ("binary_path", ctypes.c_ubyte * MAX_PATH_LEN),
        ("cwd", ctypes.c_ubyte * MAX_PATH_LEN),
        ("args", ctypes.c_ubyte * ARGSIZE),
        ("binary_path_offset", ctypes.c_int),
        ("cwd_offset", ctypes.c_int),
        ("args_len", ctypes.c_uint32),
        ("exit_code", ctypes.c_int)
    ]

class AsyncEventProcessor:
    """비동기 이벤트 처리"""
    def __init__(self, event_queue: asyncio.Queue):
        self.event_queue = event_queue
        self.logger = logging.getLogger(__name__)
        self._running = True
        self.process_filter = ProcessFilter()

    async def prepare_event(self, data: Any, size: int) -> ProcessEventData:
        """이벤트 데이터 준비 및 필터링"""
        event = ctypes.cast(data, ctypes.POINTER(ProcessEvent)).contents
        
        binary_path = bytes(event.binary_path[event.binary_path_offset:]).strip(b'\0').decode('utf-8')
        container_id = event.container_id.decode()
        
        process_type = self.process_filter.get_process_type(
            binary_path=binary_path,
            container_id=container_id
        )
        
        return ProcessEventData(
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

    async def handle_process_event(self, event: ProcessEventData) -> None:
        """필터링된 프로세스 처리"""
        # TODO: 실제 처리 로직 구현 (DB 저장 등)
        self.logger.info(f"Processing {event.process_type.name} process: {event}")

    async def run(self) -> None:
        """이벤트 처리 메인 루프"""
        while self._running:
            try:
                data, size = await self.event_queue.get()
                event = await self.prepare_event(data, size)
                
                # 관심 있는 프로세스만 처리
                if event.process_type != ProcessType.UNKNOWN:
                    await self.handle_process_event(event)
                
                self.event_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error processing event: {e}")

class BPFCollector:
    """BPF 이벤트 수집 담당 (동기 작업)"""
    def __init__(self, event_queue: asyncio.Queue):
        self.event_queue = event_queue
        self.bpf: Optional[BPF] = None
        self.logger = logging.getLogger(__name__)
        self._running = True
        self._loop = asyncio.get_event_loop()

    def event_callback(self, cpu: int, data: Any, size: int) -> None:
        """BPF 이벤트 콜백 - 최대한 가볍게 유지"""
        try:
            self._loop.call_soon_threadsafe(
                self.event_queue.put_nowait,
                (data, size)
            )
        except Exception as e:
            self.logger.error(f"Error in callback: {e}")

    def load_program(self) -> None:
        """BPF 프로그램 로드 및 설정"""
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            with open(os.path.join(current_dir, 'bpf.c'), 'r') as f:
                bpf_text = f.read()
            
            self.bpf = BPF(text=bpf_text)
            
            # 핸들러 순서 수정
            handlers = [
                self.bpf.load_func("init_handler", BPF.TRACEPOINT),
                self.bpf.load_func("container_handler", BPF.TRACEPOINT),
                self.bpf.load_func("binary_handler", BPF.TRACEPOINT),
                self.bpf.load_func("cwd_handler", BPF.TRACEPOINT),
                self.bpf.load_func("args_handler", BPF.TRACEPOINT)
            ]
            
            prog_array = self.bpf.get_table("prog_array")
            for idx, handler in enumerate(handlers):
                prog_array[idx] = handler
            
            self.bpf["events"].open_perf_buffer(self.event_callback)
            self.bpf.attach_tracepoint(tp="sched:sched_process_exec", fn_name="init_handler")
            self.bpf.attach_tracepoint(tp="sched:sched_process_exit", fn_name="exit_handler")
            
        except Exception as e:
            self.logger.error(f"Failed to load BPF program: {e}")
            raise

    def start_polling(self) -> None:
        """폴링 쓰레드 시작"""
        self._running = True
        self._polling_thread = threading.Thread(
            target=self.run_polling,
            daemon=True
        )
        self._polling_thread.start()

    def stop_polling(self) -> None:
        """폴링 중지 및 정리"""
        self._running = False
        if hasattr(self, '_polling_thread'):
            self._polling_thread.join(timeout=1.0)

    def run_polling(self) -> None:
        """BPF 이벤트 폴링 실행"""
        if not self.bpf:
            raise RuntimeError("BPF program not loaded")
            
        while self._running:
            try:
                self.bpf.perf_buffer_poll()
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.logger.error(f"Error in BPF polling: {e}")

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

async def main():
    """메인 비동기 함수"""
    logger = logging.getLogger(__name__)
    event_queue: asyncio.Queue = asyncio.Queue()
    
    # 컴포넌트 초기화
    collector = BPFCollector(event_queue)
    processor = AsyncEventProcessor(event_queue)
    
    logger.info("Starting BPF process watcher...")
    
    try:
        # BPF 프로그램 로드
        collector.load_program()
        
        # BPF 폴링 쓰레드 시작
        collector.start_polling()
        
        # 이벤트 처리 실행
        await processor.run()
        
    except asyncio.CancelledError:
        logger.info("Shutting down...")
        collector.stop_polling()
        processor.stop()
    except Exception as e:
        logger.error(f"Error running process watcher: {e}")
        raise
    finally:
        # 남은 이벤트 처리 대기
        await event_queue.join()
        logger.info("Cleanup complete")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("프로그램을 종료합니다...") 