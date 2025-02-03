#!/usr/bin/env python3
"""
Example: Attach to sched_process_exec tracepoint, parse container cgroup,
and write logs per container. (Manual function approach)

This version converts the BPF monotonic timestamp to wall-clock time
using a computed offset, and prints the time in "YYYY-MM-DD HH:MM:SS" format.
"""

import os
import time
import re
from bcc import BPF

# -----------------------------------------------------------------------------
# Compute offset between monotonic time and epoch time.
# bpf_ktime_get_ns() returns monotonic time in ns (since boot),
# so we compute:
#   time_offset = current_epoch_time - current_monotonic_time
# Then, for each event:
#   event_epoch = (event.timestamp / 1e9) + time_offset
#
# Note: time.monotonic_ns() is used to obtain the current monotonic time in ns.
# -----------------------------------------------------------------------------
start_monotonic_ns = time.monotonic_ns()  # 현재 monotonic ns
start_epoch = time.time()                 # 현재 epoch (초)
time_offset = start_epoch - (start_monotonic_ns / 1e9)

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 이벤트 구조체 정의
struct data_t {
    u32 pid;
    u64 timestamp;
    u64 cgroup_id;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

// 직접 함수 정의 (이름: sched_proc_exec_handler)
int sched_proc_exec_handler(struct trace_event_raw_sched_process_exec *ctx)
{
    struct data_t data = {};

    // 현재 프로세스 PID, 타임스탬프, cgroup id, 및 커맨드 이름 획득
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    data.pid = pid;
    data.timestamp = bpf_ktime_get_ns();
    data.cgroup_id = bpf_get_current_cgroup_id();

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // (선택) 특정 프로세스 필터링 (예: gcc, python, ./)
    if (!(
        (data.comm[0] == 'g' && data.comm[1] == 'c' && data.comm[2] == 'c') ||
        (data.comm[0] == 'p') ||
        (data.comm[0] == '.' && data.comm[1] == '/')
    )) {
        return 0;
    }

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
""".strip()

# 로그 저장 기본 경로 및 파일명
BASE_LOG_DIR = "/var/log/containers"
LOG_FILE_NAME = "execsnoop.log"

# -----------------------------------------------------------------------------
# BPF 로드 및 tracepoint attach
# -----------------------------------------------------------------------------
bpf = BPF(text=BPF_PROGRAM)
# 함수 이름: sched_proc_exec_handler (위에서 정의한 이름)
bpf.attach_tracepoint(tp="sched:sched_process_exec",
                      fn_name="sched_proc_exec_handler")

# -----------------------------------------------------------------------------
# 컨테이너 해시(또는 이름) 추출 함수
# -----------------------------------------------------------------------------
def get_container_id(pid: int) -> str:
    """
    /proc/<pid>/cgroup 파일을 분석하여 Docker 컨테이너 해시 추출.
    매칭 실패 시 빈 문자열("") 반환 (즉, 호스트 프로세스로 간주).
    """
    cgroup_file = f"/proc/{pid}/cgroup"
    if not os.path.exists(cgroup_file):
        return ""
    try:
        with open(cgroup_file, "r") as f:
            for line in f:
                parts = line.strip().split(':', 2)
                if len(parts) < 3:
                    continue
                cgroup_path = parts[2]

                # 패턴: /docker/<hash>
                m = re.search(r'/docker/([0-9a-f]{12,64})', cgroup_path)
                if m:
                    return m.group(1)

                # 패턴: /system.slice/docker-<hash>.scope
                m = re.search(r'docker-([0-9a-f]{12,64})\.scope', cgroup_path)
                if m:
                    return m.group(1)
    except Exception:
        return ""
    return ""

# -----------------------------------------------------------------------------
# Perf Buffer 콜백 함수
# -----------------------------------------------------------------------------
def handle_event(cpu, data, size):
    event = bpf["events"].event(data)
    pid = event.pid
    comm = event.comm.decode('utf-8', 'replace')

    container_hash = get_container_id(pid)
    if not container_hash:
        # 컨테이너 해시를 찾지 못하면(즉, 호스트이면) 무시
        return

    # event.timestamp는 nanosecond 단위의 monotonic time임.
    timestamp_monotonic = event.timestamp / 1e9
    # offset을 더해 실제 epoch time(초 단위)를 얻음.
    timestamp_epoch = timestamp_monotonic + time_offset

    # "YYYY-MM-DD HH:MM:SS" 형식으로 포맷 (소수점 이하 초는 출력하지 않음)
    formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_epoch))

    msg = f"[{formatted_time}] Container={container_hash} PID={pid} Process={comm}\n"

    # 콘솔 출력
    print(msg, end="")

    # 컨테이너 별 로그 파일 저장
    container_dir = os.path.join(BASE_LOG_DIR, container_hash)
    os.makedirs(container_dir, exist_ok=True)
    log_path = os.path.join(container_dir, LOG_FILE_NAME)
    with open(log_path, "a") as f:
        f.write(msg)

# -----------------------------------------------------------------------------
# 메인 루프
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    bpf["events"].open_perf_buffer(handle_event)
    print("Tracing container processes (manual function approach). Press Ctrl+C to exit.")

    try:
        while True:
            bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nTracing stopped.")
