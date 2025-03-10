#!/usr/bin/python
from bcc import BPF
import ctypes

# BPF 프로그램 소스코드
prog = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/utsname.h>
#include <linux/nsproxy.h>

#define TASK_COMM_LEN 16
#define __NEW_UTS_LEN 65

struct event_t {
    u32 pid;
    u64 uts_ns_id;
    char hostname[__NEW_UTS_LEN];
};

BPF_PERF_OUTPUT(events);

// TRACEPOINT_PROBE 매크로를 사용하여 sys_enter_execve 트레이스포인트에 부착합니다.
TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    struct event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *ns = task->nsproxy;
    if (!ns)
        return 0;
    struct uts_namespace *uts_ns = ns->uts_ns;
    if (!uts_ns)
        return 0;

    // uts_namespace 내의 nodename 필드를 읽어옵니다.
    bpf_probe_read_kernel_str(&event.hostname, sizeof(event.hostname),
                                uts_ns->name.nodename);

    // get_task_ns_id() 대신, uts_ns의 포인터 값을 고유 식별자로 사용합니다.
    event.uts_ns_id = (u64) uts_ns;
    event.pid = bpf_get_current_pid_tgid() >> 32;

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""

# 이벤트 구조체를 Python 측에서 재정의합니다.
class Event(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("uts_ns_id", ctypes.c_ulonglong),
        ("hostname", ctypes.c_char * 65)
    ]

# BPF 프로그램 컴파일
b = BPF(text=prog)

# 이벤트 콜백 함수: 출력 포맷은 필요에 따라 수정할 수 있습니다.
def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    hostname = event.hostname.decode('utf-8', 'replace')
    
    # jcode- 로 시작하는 hostname만 출력 (컨테이너)
    if hostname.startswith('jcode-'):
        print("PID: %-6d UTS_NS_ID: 0x%-16x Hostname: %s" % (
            event.pid,
            event.uts_ns_id,
            hostname
        ))

# perf 이벤트 버퍼 설정
b["events"].open_perf_buffer(print_event)
print("Tracing execve syscalls... Ctrl-C to end.")

# 이벤트 루프
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
