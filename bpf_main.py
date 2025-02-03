#!/usr/bin/env python3
"""
Example: Attach to sched_process_exec tracepoint, parse container cgroup,
and write logs per container. Manual function + unique name to avoid collisions.
"""

import os
import time
import re
from bcc import BPF

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 이벤트 구조
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

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    data.pid = pid;
    data.timestamp = bpf_ktime_get_ns();
    data.cgroup_id = bpf_get_current_cgroup_id();

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // (선택) 특정 프로세스 필터 (gcc, python, ./)
    if (!(
        (data.comm[0] == 'g' && data.comm[1] == 'c' && data.comm[2] == 'c') ||
        (data.comm[0] == 'p' && data.comm[1] == 'y' && data.comm[2] == '\0') ||
        (data.comm[0] == 'p' && data.comm[1] == 'y' && data.comm[2] == 't') ||
        (data.comm[0] == '.' && data.comm[1] == '/')
    )) {
        return 0;
    }

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
""".strip()

# 로그 디렉토리
BASE_LOG_DIR = "/var/log/containers"
LOG_FILE_NAME = "execsnoop.log"

# BPF 로드
bpf = BPF(text=BPF_PROGRAM)
# 함수 이름: sched_proc_exec_handler (위에서 정의한 이름) -> Attach
bpf.attach_tracepoint(tp="sched:sched_process_exec",
                      fn_name="sched_proc_exec_handler")

# 컨테이너 해시 추출 함수
def get_container_id(pid: int) -> str:
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

                # /docker/<hash>
                m = re.search(r'/docker/([0-9a-f]{12,64})', cgroup_path)
                if m:
                    return m.group(1)

                # /system.slice/docker-<hash>.scope
                m = re.search(r'docker-([0-9a-f]{12,64})\.scope', cgroup_path)
                if m:
                    return m.group(1)
    except:
        return ""
    return ""

def handle_event(cpu, data, size):
    event = bpf["events"].event(data)
    pid = event.pid
    comm = event.comm.decode('utf-8', 'replace')

    container_hash = get_container_id(pid)
    if not container_hash:
        # 호스트이면 무시
        return

    # 기존에는 timestamp를 초 단위 부동소수점 값으로 출력함.
    # event.timestamp는 nanosecond 단위의 Unix epoch 값.
    timestamp_sec = event.timestamp / 1e9

    # 일반적인 날짜 포맷(YYYY-MM-DD HH:MM:SS.microsec)으로 변환
    time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_sec))
    microsec = int((timestamp_sec - int(timestamp_sec)) * 1e6)
    formatted_time = f"{time_str}.{microsec:06d}"

    msg = f"[{formatted_time}] Container={container_hash} PID={pid} Process={comm}\n"

    # 콘솔 출력
    print(msg, end="")

    # 로그 파일 저장
    container_dir = os.path.join(BASE_LOG_DIR, container_hash)
    os.makedirs(container_dir, exist_ok=True)
    log_path = os.path.join(container_dir, LOG_FILE_NAME)
    with open(log_path, "a") as f:
        f.write(msg)

if __name__ == "__main__":
    bpf["events"].open_perf_buffer(handle_event)
    print("Tracing container processes (manual function approach). Press Ctrl+C to exit.")

    try:
        while True:
            bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nTracing stopped.")
