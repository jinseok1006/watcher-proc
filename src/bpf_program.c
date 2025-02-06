#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/trace_events.h>

// 프로세스 이벤트 유형을 구분하기 위한 열거형
// EXEC: 프로세스 실행 시점
// EXIT: 프로세스 종료 시점
enum event_type {
    PROC_EVENT_EXEC,
    PROC_EVENT_EXIT
};

// eBPF 프로그램에서 사용자 공간으로 전달할 데이터 구조체
struct data_t {
    enum event_type event_type;    // 이벤트 유형 (EXEC/EXIT)
    u32 pid;                       // 프로세스 ID
    u64 timestamp;                 // 이벤트 발생 시간 (나노초)
    u64 cgroup_id;                 // 컨테이너 식별을 위한 cgroup ID
    int exit_code;                 // 프로세스 종료 코드 (EXIT 이벤트에서만 사용)
    char comm[TASK_COMM_LEN];      // 프로세스 이름 (실행 파일명)
};

// 모니터링 대상 프로세스 목록
static const char *whitelist[] = {
    "gcc",
    "java",
    "python",
    "node",
    "g++",
    "gdb"
};

// 이벤트를 사용자 공간으로 전송하기 위한 BPF 맵 선언
BPF_PERF_OUTPUT(events);

// 프로세스 이름이 화이트리스트에 포함되어 있는지 확인하는 헬퍼 함수
// @param s: 검사할 프로세스 이름
// @return: 화이트리스트에 포함되면 1, 아니면 0
static __always_inline int is_whitelisted(const char *s) {
    // 컴파일러에게 루프 펼치기 지시
    #pragma unroll
    // 화이트리스트의 모든 항목과 비교
    for (int i = 0; i < sizeof(whitelist)/sizeof(whitelist[0]); i++) {
        int match = 1;
        const char *prefix = whitelist[i];
        
        // 최대 8자까지 문자열 비교 (성능 최적화를 위해 제한)
        #pragma unroll
        for (int j = 0; j < 8; j++) {
            if (prefix[j] == '\0')  // 문자열 끝에 도달
                break;
            if (s[j] != prefix[j]) {  // 불일치 발견
                match = 0;
                break;
            }
        }
        
        if (match)
            return 1;
    }
    return 0;
}

// exit_code 추출을 위한 매크로
// 리눅스 커널에서 exit code는 상위 8비트에 저장됨
#define EXIT_CODE(x) ((x >> 8) & 0xff)

// 프로세스 종료 시 호출되는 BPF 프로그램
// @param ctx: BPF 컨텍스트 (레지스터 상태 포함)
int sched_proc_exit_handler(struct pt_regs *ctx)
{
    // 이벤트 데이터 구조체 초기화
    struct data_t data = {};
    data.event_type = PROC_EVENT_EXIT;

    // 현재 프로세스 정보 수집
    data.pid = bpf_get_current_pid_tgid() >> 32;  // 상위 32비트가 PID
    data.timestamp = bpf_ktime_get_ns();          // 현재 시간 (나노초)
    data.cgroup_id = bpf_get_current_cgroup_id(); // 컨테이너 ID
    
    // 현재 task_struct에서 종료 코드 추출
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.exit_code = (task->exit_code >> 8) & 0xff;
    
    // 프로세스 이름 가져오기
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // 화이트리스트에 없는 프로세스는 무시
    if (!is_whitelisted(data.comm)) {
        return 0;
    }
    
    // 수집한 데이터를 사용자 공간으로 전송
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// 프로세스 실행 시 호출되는 BPF 프로그램
// @param ctx: BPF 컨텍스트 (레지스터 상태 포함)
int sched_proc_exec_handler(struct pt_regs *ctx)
{
    // 이벤트 데이터 구조체 초기화
    struct data_t data = {};
    data.event_type = PROC_EVENT_EXEC;

    // 현재 프로세스 정보 수집
    data.pid = bpf_get_current_pid_tgid() >> 32;  // 상위 32비트가 PID
    data.timestamp = bpf_ktime_get_ns();          // 현재 시간 (나노초)
    data.cgroup_id = bpf_get_current_cgroup_id(); // 컨테이너 ID

    // 프로세스 이름 가져오기
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // 화이트리스트에 없는 프로세스는 무시
    if (!is_whitelisted(data.comm)) {
        return 0;
    }

    // 수집한 데이터를 사용자 공간으로 전송
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
