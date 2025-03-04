#!/usr/bin/env python3
from bcc import BPF
import json
import sys

# BPF 프로그램 정의
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/cgroup.h>

#define CONTAINER_ID_LEN 64
#define MAX_COMM_LEN 16

struct data_t {
    u32 pid;
    char comm[MAX_COMM_LEN];
    char container_id[CONTAINER_ID_LEN];
    int exit_code;
};

BPF_PERF_OUTPUT(events);

static inline bool check_prefix_and_extract(const char *name, const char *prefix, int prefix_len, char *container_id, int offset) {
    #pragma unroll
    for (int i = 0; i < prefix_len; i++) {
        if (name[i] != prefix[i])
            return false;
    }
    
    // container ID 길이 체크 (최소 12자)
    #pragma unroll
    for (int i = 0; i < 12; i++) {
        char c;
        bpf_probe_read_kernel(&c, 1, name + offset + i);
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    
    // 유효한 컨테이너 ID인 경우 복사
    #pragma unroll
    for (int i = 0; i < CONTAINER_ID_LEN; i++) {
        char c;
        bpf_probe_read_kernel(&c, 1, name + offset + i);
        if (c == '.' || c == 0)
            break;
        container_id[i] = c;
    }
    
    return true;
}

int trace_exit(struct tracepoint__sched__sched_process_exit *ctx) {
    struct data_t data = {};
    
    // cgroup 정보 가져오기
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    // task_struct에서 exit code 추출
    data.exit_code = (task->exit_code >> 8) & 0xff;

    struct cgroup *cgrp = task->cgroups->dfl_cgrp;
    if (!cgrp) 
        return 0;
        
    struct kernfs_node *kn = cgrp->kn;
    if (!kn) 
        return 0;
    
    // cgroup 이름 읽기
    char cgroup_name[CONTAINER_ID_LEN];
    bpf_probe_read_kernel_str(cgroup_name, sizeof(cgroup_name), (void *)kn->name);
    
    // container ID 초기화
    __builtin_memset(data.container_id, 0, CONTAINER_ID_LEN);
    
    // docker 형식 확인 (docker-)
    if (check_prefix_and_extract(cgroup_name, "docker-", 7, data.container_id, 7)) {
        data.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        events.perf_submit(ctx, &data, sizeof(data));
        return 0;
    }
    
    // containerd 형식 확인 (cri-containerd-)
    if (check_prefix_and_extract(cgroup_name, "cri-containerd-", 15, data.container_id, 15)) {
        data.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        events.perf_submit(ctx, &data, sizeof(data));
    }
    
    return 0;
}
"""

def main():
    # BPF 프로그램 로드
    b = BPF(text=bpf_text)
    b.attach_tracepoint(tp="sched:sched_process_exit", fn_name="trace_exit")
    
    def print_event(cpu, data, size):
        event = b["events"].event(data)
        output = {
            "pid": event.pid,
            "command": event.comm.decode('utf-8').rstrip('\x00'),
            "container_id": event.container_id.decode('utf-8').rstrip('\x00'),
            "exit_code": event.exit_code
        }
        print(json.dumps(output))
    
    # 이벤트 루프 설정
    b["events"].open_perf_buffer(print_event)
    
    print("프로세스 종료 추적 중... Ctrl+C로 종료하세요.", file=sys.stderr)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    main()
