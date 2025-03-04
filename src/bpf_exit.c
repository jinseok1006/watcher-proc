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

static inline bool is_target_command(const char *comm) {
    char gcc[] = "gcc";
    char gdb[] = "gdb";
    char gpp[] = "g++";
    
    #pragma unroll
    for (int i = 0; i < 3; i++) {
        if (comm[i] != gcc[i])
            goto check_gdb;
    }
    if (comm[3] == 0)
        return true;
        
check_gdb:
    #pragma unroll
    for (int i = 0; i < 3; i++) {
        if (comm[i] != gdb[i])
            goto check_gpp;
    }
    if (comm[3] == 0)
        return true;

check_gpp:
    #pragma unroll
    for (int i = 0; i < 3; i++) {
        if (comm[i] != gpp[i])
            return false;
    }
    if (comm[3] == 0)
        return true;
    
    return false;
}

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
    
    // 현재 프로세스의 comm 가져오기
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // 타겟 명령어가 아니면 무시
    if (!is_target_command(data.comm))
        return 0;
    
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
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    
    // docker 형식 확인 (docker-)
    if (check_prefix_and_extract(cgroup_name, "docker-", 7, data.container_id, 7)) {
        events.perf_submit(ctx, &data, sizeof(data));
        return 0;
    }
    
    // containerd 형식 확인 (cri-containerd-)
    if (check_prefix_and_extract(cgroup_name, "cri-containerd-", 15, data.container_id, 15)) {
        events.perf_submit(ctx, &data, sizeof(data));
    }
    
    return 0;
} 