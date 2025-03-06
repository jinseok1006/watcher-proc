#!/usr/bin/python3
from bcc import BPF

# 상수 정의
DATA_SIZE = 384

# 간단한 BPF 프로그램
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <bcc/proto.h>

#define DATA_SIZE 384

struct data_t {
    u32 pid;
    char data1[DATA_SIZE];
    char data2[DATA_SIZE];
};

BPF_HASH(data_map, u32, struct data_t);
BPF_PERCPU_ARRAY(tmp_array, struct data_t, 1);
BPF_PROG_ARRAY(prog_array, 2);
BPF_PERF_OUTPUT(events);

int handler1(void *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 zero = 0;
    struct data_t *data = tmp_array.lookup(&zero);
    if (!data)
        return 0;
    
    data->pid = pid;
    // 첫 번째 배열을 'A'로 채움
    for (int i = 0; i < DATA_SIZE; i++) {
        data->data1[i] = 'A';
    }
    
    data_map.update(&pid, data);
    bpf_trace_printk("handler1: pid=%d filled data1 with %d\\n", pid, data->data1[0]);
    prog_array.call(ctx, 1);  // handler2로 이동
    return 0;
}

int handler2(void *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct data_t *data = data_map.lookup(&pid);
    
    if (data) {
        // 두 번째 배열을 'B'로 채움
        for (int i = 0; i < DATA_SIZE; i++) {
            data->data2[i] = 'B';
        } 
        bpf_trace_printk("handler2: pid=%d data1[0]=%d, data2[0]=%d\\n", 
                        pid, data->data1[0], data->data2[0]);
        
        // 유저 공간으로 데이터 전송
        events.perf_submit(ctx, data, sizeof(struct data_t));
    }
    
    data_map.delete(&pid);
    return 0;
}
"""

# BPF 프로그램 로드
b = BPF(text=bpf_text)

# 핸들러 함수 로드
fn1 = b.load_func("handler1", BPF.TRACEPOINT)
fn2 = b.load_func("handler2", BPF.TRACEPOINT)

# prog_array에 핸들러 등록
prog_array = b.get_table("prog_array")
prog_array[0] = fn1
prog_array[1] = fn2

# 데이터 출력을 위한 콜백 함수
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"\nReceived data from userspace:")
    print(f"PID: {event.pid}")
    print("Data1 content:")
    print(''.join(chr(event.data1[i]) for i in range(DATA_SIZE)))
    print("\nData2 content:")
    print(''.join(chr(event.data2[i]) for i in range(DATA_SIZE)))
    print("-" * 40)

# perf 버퍼 콜백 설정
b["events"].open_perf_buffer(print_event)

# exec 트레이스포인트에 첫 번째 핸들러 연결
b.attach_tracepoint(tp="sched:sched_process_exec", fn_name="handler1")

print("Tracing... Ctrl+C to end")
# trace 출력 및 perf 버퍼 폴링
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
