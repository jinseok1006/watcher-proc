#!/usr/bin/python3
from bcc import BPF
from time import sleep

# BPF 프로그램 정의
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include <bcc/proto.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char arg[32];
};

BPF_PERF_OUTPUT(events);

int trace_exec(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *task;
    struct mm_struct *mm;
    unsigned long offset = 0;
    char c;
    
    task = (struct task_struct *)bpf_get_current_task();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // gcc 명령어만 필터링
    if (data.comm[0] != 'g' || data.comm[1] != 'c' || data.comm[2] != 'c' || data.comm[3] != '\\0')
        return 0;
    
    mm = task->mm;
    if (mm && mm->arg_start) {
        // gcc 문자열 건너뛰기
        while (offset < 32) {
            bpf_probe_read_user(&c, 1, (void *)(mm->arg_start + offset));
            if (c == '\\0') {
                offset++;
                break;
            }
            offset++;
        }
        
        // 실제 인자 읽기
        if (offset < 32) {
            bpf_probe_read_user(&data.arg, sizeof(data.arg), (void *)(mm->arg_start + offset));
            bpf_trace_printk("gcc args: %s\\n", data.arg);
        }
    }
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# BPF 객체 생성 및 프로그램 로드
b = BPF(text=bpf_text)

# 유저 공간에서 트레이스포인트에 핸들러 연결
b.attach_tracepoint(tp="sched:sched_process_exec", fn_name="trace_exec")

# 콜백 함수 정의
def print_event(cpu, data, size):
    event = b["events"].event(data)
    comm = event.comm.decode('utf-8', 'replace').strip('\\x00')
    if comm == "gcc":
        arg = event.arg.decode('utf-8', 'replace').strip('\\x00')
        print(f"gcc args: {arg}")

# 이벤트 루프 설정
b["events"].open_perf_buffer(print_event)

print("Tracing gcc executions... Ctrl+C to end")

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
