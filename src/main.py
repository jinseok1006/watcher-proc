#!/usr/bin/env python3
"""
컨테이너 프로세스 추적 프로그램
- sched_process_exec 및 sched_process_exit 트레이스포인트에 연결
- 컨테이너 cgroup 정보 파싱
- GCC 실행 결과(성공/실패) 추적
"""
import os
import time
import re
from bcc import BPF
from container_map import ContainerPIDMap

# 시간 오프셋 계산
start_monotonic_ns = time.monotonic_ns()
start_epoch = time.time()
time_offset = start_epoch - (start_monotonic_ns / 1e9)

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/trace_events.h>  // 트레이스포인트 구조체 정의 포함

// 이벤트 타입 식별을 위한 열거형
enum event_type {
    PROC_EVENT_EXEC,
    PROC_EVENT_EXIT
};

// sched:sched_process_exit 트레이스포인트 구조체 정의
struct sched_process_exit_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long int code;  // exit code 필드
};

// 이벤트 데이터 구조체
struct data_t {
    enum event_type event_type;
    u32 pid;
    u64 timestamp;
    u64 cgroup_id;
    int exit_code;
    char comm[TASK_COMM_LEN];
};

// 추적할 프로세스 목록
static const char *whitelist[] = {
    "gcc",
    "java",
    "python",
    "node",
    "g++",
    "gdb"
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

// 프로세스 종료 핸들러 수정
int sched_proc_exit_handler(struct sched_process_exit_args *ctx) {
    struct data_t data = {};
    data.event_type = PROC_EVENT_EXIT;

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.timestamp = bpf_ktime_get_ns();
    data.cgroup_id = bpf_get_current_cgroup_id();
    data.exit_code = ctx->code;  // tracepoint 구조체에서 exit code 추출
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    if (!is_whitelisted(data.comm)) {
        return 0;
    }
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int sched_proc_exec_handler(struct pt_regs *ctx)
{
    struct data_t data = {};
    data.event_type = PROC_EVENT_EXEC;

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
bpf.attach_tracepoint(tp="sched:sched_process_exit", fn_name="sched_proc_exit_handler")
bpf.attach_tracepoint(tp="sched:sched_process_exec", fn_name="sched_proc_exec_handler")

class HashPIDMap:
    def __init__(self):
        self.map = {}

    def add(self, pid: int, pod_name: str):
        self.map[pid] = pod_name

    def get(self, pid: int) -> str:
        return self.map.pop(pid)
hash_pid_map = HashPIDMap()

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
                parts = line.strip().split(":", 2)
                if len(parts) < 3:
                    continue
                cgroup_path = parts[2]
                # Docker 컨테이너 ID 패턴 검색
                m = re.search(r"/docker/([0-9a-f]{12,64})", cgroup_path)
                if m:
                    return m.group(1)
                m = re.search(r"docker-([0-9a-f]{12,64})\.scope", cgroup_path)
                if m:
                    return m.group(1)
    except Exception:
        print(f"[ERROR] cgroup 파일 읽기 실패 (PID: {pid})")
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
    comm = event.comm.decode("utf-8", "replace")

    # 시간 변환 및 포맷팅
    timestamp_monotonic = event.timestamp / 1e9
    timestamp_epoch = timestamp_monotonic + time_offset
    formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_epoch))
    
    # 이벤트 타입에 따라 분기 처리
    if event.event_type == 0:  # EXEC 이벤트
        container_hash = get_container_id(pid)
        
        if container_hash:
            hash_pid_map.add(pid, container_hash)
            msg = f"[{formatted_time}] EXEC Container={container_hash} PID={pid} Process={comm}\n"
            print(msg, end="")

        return
    
    # EXIT 이벤트 처리
    exit_code = event.exit_code
    container_hash = hash_pid_map.get(pid)  # pop으로 안전하게 가져오기
    
    if not container_hash:  # None인 경우 early return
        return

    # 성공/실패 메시지 생성
    status = "Success" if exit_code == 0 else f"Failure (Exit Code: {exit_code})"
    msg = f"[{formatted_time}] EXIT Container={container_hash} PID={pid} Process={comm} Status={status}\n"

    # 콘솔 출력
    print(msg, end="")


# 메인 실행 루프
if __name__ == "__main__":
    bpf["events"].open_perf_buffer(handle_event)
    print("컨테이너 프로세스 추적을 시작합니다. 종료하려면 Ctrl+C를 누르세요.")
    try:
        while True:
            bpf.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        print("\n추적이 중지되었습니다.")
