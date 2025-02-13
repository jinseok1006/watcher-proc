from bcc import BPF
from time import strftime
import ctypes

# BPF 프로그램 재설계
bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/cgroup-defs.h>
#include <linux/kernfs.h>
#include <linux/cgroup.h>

struct exec_data_t {
    u32 pid;
    char container_id[64];
    char comm[16];
};

BPF_PERF_OUTPUT(events);

static inline void extract_container_id(struct task_struct *task, char *container_id) {
    // 기본값 설정
    __builtin_memset(container_id, 0, 64);
    
    // cgroup 정보 가져오기
    struct cgroup *cgrp = task->cgroups->dfl_cgrp;
    if (!cgrp) 
        return;
        
    struct kernfs_node *kn = cgrp->kn;
    if (!kn) 
        return;
    
    // cgroup 이름 읽기
    char buf[64];
    bpf_probe_read_kernel_str(buf, sizeof(buf), (void *)kn->name);
    
    // docker- 접두사 확인
    if (buf[0] == 'd' && buf[1] == 'o' && buf[2] == 'c' && 
        buf[3] == 'k' && buf[4] == 'e' && buf[5] == 'r' && 
        buf[6] == '-') {
        // docker- 이후의 컨테이너 ID 복사
        #pragma unroll
        for (int i = 0; i < 64; i++) {
            char c;
            bpf_probe_read_kernel(&c, 1, &buf[i + 7]);
            if (c == '.' || c == 0)  // .scope나 문자열 끝 확인
                break;
            container_id[i] = c;
        }
    }
}

int trace_exec(struct tracepoint__sched__sched_process_exec *ctx) {
    struct exec_data_t data = {};
    struct task_struct *task;
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    
    // 프로세스 이름 필터링
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    if (comm[0] != 'g' || comm[1] != 'c' || comm[2] != 'c') {
        return 0;
    }
    
    // 컨테이너 ID 추출
    extract_container_id(task, data.container_id);
    
    // 커맨드 이름 복사
    bpf_probe_read_kernel_str(data.comm, sizeof(data.comm), comm);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# BPF 초기화 및 함수 연결
bpf = BPF(text=bpf_source)
bpf.attach_tracepoint(tp="sched:sched_process_exec", fn_name="trace_exec")

# 사용자 공간 처리 함수
def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    container_id = event.container_id.decode('utf-8').rstrip('\x00')
    if not container_id:
        container_id = "host"
    
    print(f"[{strftime('%H:%M:%S')}] GCC Process: PID={event.pid}, "
          f"ContainerID={container_id}, Cmd='{event.comm.decode()}'")

# 이벤트 버퍼 설정
print("Monitoring GCC processes... Ctrl+C to exit")
bpf["events"].open_perf_buffer(print_event)

# 메인 폴링 루프
while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()