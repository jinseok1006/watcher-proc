#!/usr/bin/python3
from bcc import BPF
import ctypes
import os

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
    print(f"\n[PID: {event.pid}]")
    print(f"Error flags: {bin(event.error_flags)}")
    print(f"Container ID: {event.container_id.decode()}")
    
    # fullpath와 args는 ubyte 배열이므로 bytes로 변환 후 decode
    fullpath_bytes = bytes(event.fullpath[event.path_offset:])
    args_bytes = bytes(event.args[:event.args_len])
    
    print(f"CWD: {fullpath_bytes.decode('utf-8', errors='replace')}")
    # args를 \0으로 스플릿하여 출력
    args_list = args_bytes.split(b'\0')
    args_str = ' '.join(arg.decode('utf-8', errors='replace') for arg in args_list if arg)
    print(f"Arguments: {args_str}")
    print(f"Exit code: {event.exit_code}")
    print("-" * 40)

if __name__ == "__main__":
    # BPF 프로그램 로드
    current_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(current_dir, 'chain.c'), 'r') as f:
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