#!/usr/bin/python3
from bcc import BPF
from time import sleep
import ctypes

# BPF 프로그램 정의
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include <bcc/proto.h>

#define ARGSIZE 256

struct data_t {
    u32 pid;
    char args[ARGSIZE];
    u32 len;
};

BPF_PERF_OUTPUT(events);

int trace_exec(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *task;
    struct mm_struct *mm;
    
    task = (struct task_struct *)bpf_get_current_task();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    
    mm = task->mm;
    if (mm && mm->arg_start) {
        data.len = mm->arg_end - mm->arg_start;
        if (data.len > ARGSIZE)
            data.len = ARGSIZE;
            
        // 한 번에 전체 인자 읽기
        bpf_probe_read_user(data.args, data.len, (void *)mm->arg_start);
    }
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# BPF 객체 생성 및 프로그램 로드
b = BPF(text=bpf_text)

# 유저 공간에서 트레이스포인트에 핸들러 연결
b.attach_tracepoint(tp="sched:sched_process_exec", fn_name="trace_exec")

class Data(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("args", ctypes.c_ubyte * 256),
        ("len", ctypes.c_uint32)
    ]

# 콜백 함수 정의
def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    
    # args를 bytes로 변환하고 직접 출력
    args_bytes = bytes(event.args[:event.len])
    
    print(f"args (raw bytes): {args_bytes}")
    print("-" * 40)

# 이벤트 루프 설정
b["events"].open_perf_buffer(print_event)

print("Tracing all process executions... Ctrl+C to end")



while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
