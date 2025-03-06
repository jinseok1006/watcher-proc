#!/usr/bin/python3
from bcc import BPF
import ctypes
import os
from datetime import datetime

# 상수 정의
CONTAINER_ID_LEN = 12
MAX_PATH_LEN = 256
ARGSIZE = 384

# Python 측 데이터 구조체
class Data(ctypes.Structure):
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

def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    # 바이트 데이터 처리
    fullpath_bytes = bytes(event.fullpath[event.path_offset:])
    args_bytes = bytes(event.args[:event.args_len])
    args_list = args_bytes.split(b'\0')
    args_str = ' '.join(arg.decode('utf-8', errors='replace') for arg in args_list if arg)
    
    # gcc 명령어만 필터링 (정확히 'gcc'인 경우만)
    if args_list and args_list[0] == b'gcc':
        # 현재 시각을 포함하여 한 줄로 모든 정보 출력
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        print(f"[TIME:{timestamp}] [PID:{event.pid}] [ERR:{bin(event.error_flags)}] [CID:{event.container_id.decode()}] [PATH:{fullpath_bytes.decode('utf-8', errors='replace')}] [ARGS:{args_str}] [EXIT:{event.exit_code}]")

if __name__ == "__main__":
    # BPF 프로그램 로드
    current_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(current_dir, 'bpf.c'), 'r') as f:
        bpf_text = f.read()
    
    b = BPF(text=bpf_text)
    
    # 핸들러 함수 로드
    fn1 = b.load_func("init_handler", BPF.TRACEPOINT)
    fn2 = b.load_func("container_handler", BPF.TRACEPOINT)
    fn3 = b.load_func("cwd_handler", BPF.TRACEPOINT)
    fn4 = b.load_func("args_handler", BPF.TRACEPOINT)
    
    # prog_array에 핸들러 등록
    prog_array = b.get_table("prog_array")
    prog_array[0] = fn1
    prog_array[1] = fn2
    prog_array[2] = fn3
    prog_array[3] = fn4
    
    # 이벤트 콜백 설정
    b["events"].open_perf_buffer(print_event)
    
    # exec과 exit 트레이스포인트 연결
    b.attach_tracepoint(tp="sched:sched_process_exec", fn_name="init_handler")
    b.attach_tracepoint(tp="sched:sched_process_exit", fn_name="exit_handler")
    
    print("Tracing... Ctrl+C to end")
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("Exiting...") 