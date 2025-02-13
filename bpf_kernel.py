from bcc import BPF
from time import strftime, time_ns
import ctypes
import os
import threading
from concurrent.futures import ThreadPoolExecutor

# 최종 검증 완료 버전
bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/cgroup.h>
#include <linux/kernfs.h>
#include <linux/fs_struct.h>

// 청크 구조체 추가
struct command_chunk {
    char data[128];
};

// 공유 데이터 구조체
struct exec_data_t {
    u32 pid;
    u64 start_time;  // 프로세스 시작 시간 (ns 단위)
    char container_id[16];
    char comm[16];
    char cmd_head[64];  // 명령어 앞부분 63자
    char cwd[256];  // UTF-8 인코딩된 경로
};

// 전용 저장 맵 정의
BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(cmd_store, u8, 256);  // 256바이트 버퍼
BPF_PERCPU_ARRAY(cwd_store, u8, 256);
BPF_HASH(cmd_chunks, u64, struct command_chunk);  // 구조체 기반 해시맵

static inline void extract_container_id(struct task_struct *task, char *container_id) {
    __builtin_memset(container_id, 0, 16);
    
    struct css_set *cgroups = NULL;
    if (bpf_probe_read_kernel(&cgroups, sizeof(cgroups), &task->cgroups) || !cgroups)
        return;

    struct cgroup *dfl_cgrp = NULL;
    if (bpf_probe_read_kernel(&dfl_cgrp, sizeof(dfl_cgrp), &cgroups->dfl_cgrp) || !dfl_cgrp)
        return;

    struct kernfs_node *kn = NULL;
    if (bpf_probe_read_kernel(&kn, sizeof(kn), &dfl_cgrp->kn) || !kn)
        return;

    char *name_ptr = NULL;
    if (bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), &kn->name) || !name_ptr)
        return;

    char cgroup_name[32] = {0};
    bpf_probe_read_kernel_str(cgroup_name, sizeof(cgroup_name)-1, name_ptr);

    for (int i=0; i<16; i++) {
        if (cgroup_name[i]   == 'd' && cgroup_name[i+1] == 'o' &&
            cgroup_name[i+2] == 'c' && cgroup_name[i+3] == 'k' &&
            cgroup_name[i+4] == 'e' && cgroup_name[i+5] == 'r' &&
            cgroup_name[i+6] == '-') {
            bpf_probe_read_kernel_str(container_id, 15, &cgroup_name[i+7]);
            break;
        }
    }
}

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct exec_data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    if (!t) return 0;

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.start_time = bpf_ktime_get_ns();
    bpf_get_current_comm(data.comm, sizeof(data.comm));

    if (data.comm[0] != 'g' || data.comm[1] != 'c' || data.comm[2] != 'c')
        return 0;

    extract_container_id(t, data.container_id);

    if (t->mm && t->mm->arg_start) {
        bpf_probe_read_user_str(data.cmd_head, sizeof(data.cmd_head)-1, (void *)t->mm->arg_start);
    }

    struct fs_struct *fs = NULL;
    if (bpf_probe_read_kernel(&fs, sizeof(fs), &t->fs) || !fs)
        goto submit;
    
    struct path pwd;
    if (bpf_probe_read_kernel(&pwd, sizeof(pwd), &fs->pwd) || !pwd.dentry)
        goto submit;
    
    struct qstr d_name;
    if (bpf_probe_read_kernel(&d_name, sizeof(d_name), &pwd.dentry->d_name))
        goto submit;
    
    bpf_probe_read_kernel_str(data.cwd, sizeof(data.cwd)-1, d_name.name);

submit:
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

# BPF 초기화 (최종 컴파일 옵션)
bpf = BPF(text=bpf_source, cflags=[
    "-mllvm", "-bpf-stack-size=512",
    "-fno-stack-protector",
    "-Wno-address-of-packed-member",
    "-Wno-incompatible-pointer-types",
    "-Wno-array-bounds",
    "-Wno-gnu-variable-sized-type-not-at-end"
])

# 스레드 풀 생성 (최대 10개 스레드)
executor = ThreadPoolExecutor(max_workers=10)

def verify_process(pid: int, start_time_ns: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            stat = f.read().split()
            start_time_ticks = int(stat[21])
            hz = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
            actual_ns = (start_time_ticks * 1_000_000_000) // hz
            return abs(actual_ns - start_time_ns) < 1_000_000  # 1ms 이내 차이
    except:
        return False

def get_full_cmd(pid: int, start_time_ns: int, fallback_cmd: str) -> str:
    if not verify_process(pid, start_time_ns):
        return f"[Expired] {fallback_cmd}..."
    
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmdline = f.read().replace(b'\x00', b' ').decode().strip()
            return cmdline if cmdline else fallback_cmd
    except:
        return f"[Failed] {fallback_cmd}..."

def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    timestamp = strftime('%H:%M:%S')
    container_id = event.container_id.decode('utf-8', 'replace').strip('\x00')
    fallback_cmd = event.cmd_head.decode('utf-8', 'replace').strip('\x00')
    cwd = event.cwd.decode('utf-8', 'replace').strip('\x00')
    
    # 실시간 출력 (기본 정보)
    print(f"[{timestamp}] GCC: PID={event.pid} | Container={container_id} | CMD={event.comm.decode()} | CWD={cwd}")
    
    # 비동기 상세 정보 처리
    executor.submit(
        lambda: print(f"[{timestamp}] GCC-DETAIL: PID={event.pid} | FullCMD='{get_full_cmd(event.pid, event.start_time, fallback_cmd)}'")
    )

# 이벤트 리스너 설정
print("Monitoring GCC processes with reliable cmd capture... Ctrl+C to exit")
bpf["events"].open_perf_buffer(print_event)

# 권한 설정 안내
print("실행 전 다음 명령 실행:")
print("sudo setcap cap_bpf,cap_perfmon+ep $(which python3)")
print("sudo sysctl -w kernel.unprivileged_bpf_disabled=0")

# 메인 루프
try:
    while True:
        bpf.perf_buffer_poll()
except KeyboardInterrupt:
    executor.shutdown()
    exit()