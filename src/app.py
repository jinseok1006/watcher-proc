#!/usr/bin/env python3
from bcc import BPF
import time
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
#define RUNTIME_LEN 16

// 런타임 타입 정의
#define RT_HOST 0
#define RT_K8S 1
#define RT_CONTAINERD 2
#define RT_DOCKER 3

struct data_t {
    u32 pid;
    u32 runtime_type;
    char comm[MAX_COMM_LEN];
    char container_id[CONTAINER_ID_LEN];
};

BPF_PERF_OUTPUT(events);

static inline bool find_kubepods_container_id(const char *buf, char *container_id) {
    #pragma unroll
    for (int i = 0; i < CONTAINER_ID_LEN - 8; i++) {
        if (buf[i] == 'k' && buf[i+1] == 'u' && buf[i+2] == 'b' && 
            buf[i+3] == 'e' && buf[i+4] == 'p' && buf[i+5] == 'o' && 
            buf[i+6] == 'd' && buf[i+7] == 's') {
            
            #pragma unroll
            for (int j = i; j < CONTAINER_ID_LEN - 64; j++) {
                char c;
                bpf_probe_read_kernel(&c, 1, buf + j);
                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
                    int valid_hex = 1;
                    #pragma unroll
                    for (int k = 0; k < 64; k++) {
                        char hex_c;
                        bpf_probe_read_kernel(&hex_c, 1, buf + j + k);
                        if (!((hex_c >= '0' && hex_c <= '9') || (hex_c >= 'a' && hex_c <= 'f'))) {
                            valid_hex = 0;
                            break;
                        }
                    }
                    if (valid_hex) {
                        #pragma unroll
                        for (int k = 0; k < 64; k++) {
                            bpf_probe_read_kernel(&container_id[k], 1, buf + j + k);
                        }
                        return true;
                    }
                }
            }
            break;
        }
    }
    return false;
}

static inline bool find_containerd_id(const char *buf, char *container_id) {
    if (buf[0] == 'c' && buf[1] == 'r' && buf[2] == 'i' && buf[3] == '-' &&
        buf[4] == 'c' && buf[5] == 'o' && buf[6] == 'n' && buf[7] == 't' &&
        buf[8] == 'a' && buf[9] == 'i' && buf[10] == 'n' && buf[11] == 'e' &&
        buf[12] == 'r' && buf[13] == 'd' && buf[14] == '-') {
        
        #pragma unroll
        for (int i = 0; i < CONTAINER_ID_LEN; i++) {
            char c;
            bpf_probe_read_kernel(&c, 1, buf + 15 + i);
            if (c == '.' || c == 0)
                break;
            container_id[i] = c;
        }
        return true;
    }
    return false;
}

static inline bool find_docker_id(const char *buf, char *container_id) {
    if (buf[0] == 'd' && buf[1] == 'o' && buf[2] == 'c' && 
        buf[3] == 'k' && buf[4] == 'e' && buf[5] == 'r' && 
        buf[6] == '-') {
        
        #pragma unroll
        for (int i = 0; i < CONTAINER_ID_LEN; i++) {
            char c;
            bpf_probe_read_kernel(&c, 1, buf + 7 + i);
            if (c == '.' || c == 0)
                break;
            container_id[i] = c;
        }
        return true;
    }
    return false;
}

static inline u32 get_container_id(struct task_struct *task, char *container_id) {
    // 기본값 설정
    __builtin_memset(container_id, 0, CONTAINER_ID_LEN);
    
    // cgroup 정보 가져오기
    struct cgroup *cgrp = task->cgroups->dfl_cgrp;
    if (!cgrp) 
        return RT_HOST;
        
    struct kernfs_node *kn = cgrp->kn;
    if (!kn) 
        return RT_HOST;
    
    // cgroup 이름 읽기
    char buf[CONTAINER_ID_LEN];
    bpf_probe_read_kernel_str(buf, sizeof(buf), (void *)kn->name);
    
    // 순서대로 컨테이너 ID 찾기 시도
    if (find_kubepods_container_id(buf, container_id))
        return RT_K8S;
    if (find_containerd_id(buf, container_id))
        return RT_CONTAINERD;
    if (find_docker_id(buf, container_id))
        return RT_DOCKER;
    return RT_HOST;
}

int trace_exec(struct tracepoint__sched__sched_process_exec *ctx) {
    struct data_t data = {};
    
    // PID 및 명령어 이름 가져오기
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // 컨테이너 ID 추출
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.runtime_type = get_container_id(task, data.container_id);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

def main():
    # BPF 프로그램 로드
    b = BPF(text=bpf_text)
    b.attach_tracepoint(tp="sched:sched_process_exec", fn_name="trace_exec")
    
    # 런타임 타입 매핑
    runtime_names = {
        0: "host",
        1: "kubernetes",
        2: "containerd",
        3: "docker"
    }
    
    # 이벤트 콜백 함수
    def print_event(cpu, data, size):
        event = b["events"].event(data)
        container_id = event.container_id.decode('utf-8').rstrip('\x00')
        command = event.comm.decode('utf-8').rstrip('\x00')
        runtime = runtime_names.get(event.runtime_type, "unknown")
        
        output = {
            "pid": event.pid,
            "command": command,
            "runtime": runtime,
            "container_id": container_id if container_id else "host"
        }
        
        print(json.dumps(output))
    
    # 이벤트 루프 설정
    b["events"].open_perf_buffer(print_event)
    
    print("프로세스 추적 중... Ctrl+C로 종료하세요.", file=sys.stderr)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    main()
