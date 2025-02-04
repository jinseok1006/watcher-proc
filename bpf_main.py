#!/usr/bin/env python3
"""
컨테이너 프로세스 추적 프로그램

- sched_process_exec 트레이스포인트에 연결
- 컨테이너 cgroup 정보 파싱
- 컨테이너별 로그 기록
"""

import os
import time
import re
from bcc import BPF

# 시간 오프셋 계산
# monotonic 시간과 실제 시간(epoch) 간의 차이를 계산하여 이벤트 시간 변환에 사용
start_monotonic_ns = time.monotonic_ns()  
start_epoch = time.time()                 
time_offset = start_epoch - (start_monotonic_ns / 1e9)

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 이벤트 데이터 구조체
struct data_t {
    u32 pid;
    u64 timestamp;
    u64 cgroup_id;
    char comm[TASK_COMM_LEN];
};

// 추적할 프로세스 목록
static const char *whitelist[] = {
    "gcc",
};

BPF_PERF_OUTPUT(events);

// 프로세스 이름이 화이트리스트에 포함되는지 확인하는 함수
static __always_inline int is_whitelisted(const char *s) {
    #pragma unroll
    for (int i = 0; i < sizeof(whitelist)/sizeof(whitelist[0]); i++) {
        int match = 1;
        const char *prefix = whitelist[i];
        
        #pragma unroll
        for (int j = 0; j < 8; j++) {
            if (prefix[j] == '\0')
                break;
            if (s[j] != prefix[j]) {
                match = 0;
                break;
            }
        }
        
        if (match)
            return 1;
    }
    return 0;
}

// 프로세스 실행 시 호출되는 핸들러
int sched_proc_exec_handler(struct pt_regs *ctx)
{
    struct data_t data = {};

    // 프로세스 정보 수집
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    data.pid = pid;
    data.timestamp = bpf_ktime_get_ns();
    data.cgroup_id = bpf_get_current_cgroup_id();

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // 화이트리스트 검사
    if (!is_whitelisted(data.comm)) {
        return 0;
    }

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
""".strip()


# BPF 프로그램 초기화 및 이벤트 핸들러 연결
bpf = BPF(text=BPF_PROGRAM)
bpf.attach_tracepoint(tp="sched:sched_process_exec",
                      fn_name="sched_proc_exec_handler")

def get_container_id(pid: int) -> str:
    """
    PID를 이용해 컨테이너 ID 추출
    - /proc/<pid>/cgroup 파일에서 Docker 컨테이너 해시 검색
    - 컨테이너가 아닌 경우 빈 문자열 반환
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

                # Docker 컨테이너 ID 패턴 검색
                m = re.search(r'/docker/([0-9a-f]{12,64})', cgroup_path)
                if m:
                    return m.group(1)

                m = re.search(r'docker-([0-9a-f]{12,64})\.scope', cgroup_path)
                if m:
                    return m.group(1)
    except Exception:
        return ""
    return ""

def handle_event(cpu, data, size):
    """
    이벤트 처리 함수
    - 이벤트 데이터 파싱
    - 시간 변환 및 포맷팅
    - 로그 파일 기록
    """
    event = bpf["events"].event(data)
    pid = event.pid
    comm = event.comm.decode('utf-8', 'replace')

    # 컨테이너 ID 확인
    container_hash = get_container_id(pid)
    if not container_hash:
        return

    # 시간 변환 및 포맷팅
    timestamp_monotonic = event.timestamp / 1e9
    timestamp_epoch = timestamp_monotonic + time_offset
    formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_epoch))

    # 로그 메시지 생성
    msg = f"[{formatted_time}] Container={container_hash} PID={pid} Process={comm}\n"

    # 콘솔 출력
    print(msg, end="")

# 메인 실행 루프
if __name__ == "__main__":
    bpf["events"].open_perf_buffer(handle_event)
    print("컨테이너 프로세스 추적을 시작합니다. 종료하려면 Ctrl+C를 누르세요.")

    try:
        while True:
            bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\n추적이 중지되었습니다.")