from bcc import BPF
from time import strftime

# BPF 프로그램
bpf_source = """
#include <linux/sched.h>
#include <linux/mm_types.h>

#define MAX_CMD_LEN 64
#define MAX_CMD_READ (MAX_CMD_LEN - 1)

struct exec_data_t {
    u32 pid;
    char cmd[MAX_CMD_LEN];
    char binary[MAX_CMD_LEN];  // 바이너리 경로용 버퍼
};

BPF_PERF_OUTPUT(events);

// 바이너리 경로 읽기 함수를 안전한 방식으로 수정
static inline int read_binary_path(struct tracepoint__sched__sched_process_exec *args, char *path) {
    const char *filename;
    
    // 안전한 방식으로 filename 포인터 읽기
    bpf_probe_read_kernel(&filename, sizeof(filename), &args->filename);
    if (!filename)
        return -1;
    
    // 문자열 읽기
    return bpf_probe_read_user_str(path, MAX_CMD_READ, filename);
}

// 커맨드 라인 읽기 함수
static inline int read_cmdline(struct task_struct *task, char *cmd, size_t size) {
    struct mm_struct *mm;
    bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm);
    if (!mm)
        return -1;
    
    unsigned long arg_start, arg_end;
    bpf_probe_read_kernel(&arg_start, sizeof(arg_start), &mm->arg_start);
    bpf_probe_read_kernel(&arg_end, sizeof(arg_end), &mm->arg_end);
    
    // 고정된 크기로 읽기
    long bytes = bpf_probe_read_user(cmd, MAX_CMD_READ, (void *)arg_start);
    if (bytes < 0)
        return -1;
    
    // 고정된 크기의 루프로 변경
    #pragma unroll
    for (int i = 0; i < MAX_CMD_READ; i++) {
        if (cmd[i] == '\\0')
            cmd[i] = ' ';
    }
    
    cmd[MAX_CMD_READ] = '\\0';
    return MAX_CMD_READ;
}

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct exec_data_t data = {};
    
    // task_struct 접근
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // command line 읽기
    if (read_cmdline(task, data.cmd, sizeof(data.cmd)) < 0)
        return 0;
    
    // GCC 프로세스만 필터링
    if (data.cmd[0] != 'g' || data.cmd[1] != 'c' || data.cmd[2] != 'c')
        return 0;
    
    // 바이너리 경로 읽기
    if (read_binary_path(args, data.binary) < 0) {
        data.binary[0] = '\\0';
    }
        
    data.pid = bpf_get_current_pid_tgid() >> 32;
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

# BPF 초기화
bpf = BPF(text=bpf_source)

# 이벤트 출력 함수
def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    cmd = event.cmd.decode('utf-8', errors='ignore').rstrip('\x00')
    binary = event.binary.decode('utf-8', errors='ignore').rstrip('\x00')
    print(f"{event.pid:<10} | BINARY: {binary:<30} | CMD: {cmd}")

# 이벤트 처리 설정
bpf["events"].open_perf_buffer(print_event)

# 메인 루프
while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()