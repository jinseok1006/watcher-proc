#!/usr/bin/python3
from bcc import BPF
import ctypes
import os
import asyncio
import threading
import logging
from datetime import datetime
from typing import Optional, Dict, Any

# 상수 정의
CONTAINER_ID_LEN = 12
MAX_PATH_LEN = 256
ARGSIZE = 384

class ProcessEvent(ctypes.Structure):
    """프로세스 이벤트 데이터 구조체"""
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("error_flags", ctypes.c_uint32),
        ("container_id", ctypes.c_char * CONTAINER_ID_LEN),
        ("fullpath", ctypes.c_ubyte * MAX_PATH_LEN),
        ("args", ctypes.c_ubyte * ARGSIZE),
        ("path_offset", ctypes.c_int),
        ("args_len", ctypes.c_uint32),
        ("exit_code", ctypes.c_int)
    ]

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
            
            # 핸들러 함수 로드 및 등록
            handlers = [
                self.bpf.load_func("init_handler", BPF.TRACEPOINT),
                self.bpf.load_func("container_handler", BPF.TRACEPOINT),
                self.bpf.load_func("cwd_handler", BPF.TRACEPOINT),
                self.bpf.load_func("args_handler", BPF.TRACEPOINT)
            ]
            
            # prog_array에 핸들러 등록
            prog_array = self.bpf.get_table("prog_array")
            for idx, handler in enumerate(handlers):
                prog_array[idx] = handler
            
            # 이벤트 콜백 및 트레이스포인트 설정
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

class AsyncEventProcessor:
    """이벤트 처리 담당 (비동기 작업)"""
    def __init__(self, event_queue: asyncio.Queue):
        self.event_queue = event_queue
        self.logger = logging.getLogger(__name__)
        self._running = True

    def stop(self) -> None:
        """처리 중지"""
        self._running = False

    async def process_event(self, data: Any, size: int) -> Dict[str, Any]:
        """이벤트 데이터 처리"""
        event = ctypes.cast(data, ctypes.POINTER(ProcessEvent)).contents
        
        fullpath_bytes = bytes(event.fullpath[event.path_offset:])
        args_bytes = bytes(event.args[:event.args_len])
        args_list = args_bytes.split(b'\0')
        args_str = ' '.join(arg.decode('utf-8', errors='replace') for arg in args_list if arg)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'pid': event.pid,
            'error_flags': bin(event.error_flags),
            'container_id': event.container_id.decode(),
            'cwd': fullpath_bytes.decode('utf-8', errors='replace'),
            'args': args_str,
            'exit_code': event.exit_code
        }

    async def run(self) -> None:
        """이벤트 처리 메인 루프"""
        while self._running:
            try:
                data, size = await self.event_queue.get()
                event_data = await self.process_event(data, size)
                self.logger.info(f"Process Event: {event_data}")
                self.event_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error processing event: {e}")

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