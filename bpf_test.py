#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
from bcc import BPF
from bcc.utils import printb

bpf_program = r"""
#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct event {
    u32 pid;
    char path[256];
};

BPF_PERF_OUTPUT(events);

// fexit 프로그램: __x64_sys_execve 함수 종료 시 호출
__attribute__((section("fexit/__x64_sys_execve"), used))
int fexit___x64_sys_execve(struct pt_regs *ctx)
{
    bpf_trace_printk("js is watching you \n");
    long ret = PT_REGS_RC(ctx);
    if (ret < 0)
        return 0; // execve 실패 시 무시

    // 선택적으로 필터링 (예: "gcc"인 경우만)
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    // 예시: 조건을 주석 처리하여 모든 execve 성공 이벤트 처리
    // if (comm[0] != 'g' || comm[1] != 'c' || comm[2] != 'c' || comm[3] != '\0')
    //     return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct file *exe_file = NULL;
    bpf_probe_read_kernel(&exe_file, sizeof(exe_file), &task->mm->exe_file);
    if (!exe_file)
        return 0;

    struct event e = {};
    int dret = bpf_d_path(&exe_file->f_path, e.path, sizeof(e.path));
    if (dret < 0)
        return 0;

    e.pid = bpf_get_current_pid_tgid() >> 32;
    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
"""

b = BPF(text=bpf_program)
print("Tracing execve using fexit... Hit Ctrl-C to exit.")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("PID: %d, Executable Path: %s" % (event.pid, event.path.decode("utf-8", "replace")))

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
