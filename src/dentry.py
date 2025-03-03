#!/usr/bin/env python3
from bcc import BPF
import ctypes

bpf_program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/nsproxy.h>
#include <bcc/proto.h>

#define MAX_PATH_LEN 256
#define MAX_DENTRY_LEVEL 10

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char fullpath[MAX_PATH_LEN];
};

BPF_PERF_OUTPUT(events);



// dentry 체인을 따라 CWD 경로를 역순으로 재구성
static __always_inline int get_dentry_path(struct dentry *dentry, char *buf, int buf_size)
{
    // buf의 끝에서부터 문자열을 채워나감
    int pos = buf_size - 1;
    buf[pos] = '\0';



    // 고정된 횟수만큼 dentry->d_parent로 이동하며 경로를 구성
    // #pragma unroll을 사용할 경우 코드가 커져서 BPF 검증기가 거부할 수 있으니 주의
        
    #pragma unroll
    for (int i = 0; i < MAX_DENTRY_LEVEL; i++) {
        if (!dentry)
            break;

        // parent dentry 가져오기
        struct dentry *parent = NULL;
        bpf_probe_read(&parent, sizeof(parent), &dentry->d_parent);


        // root 검출: dentry가 자기 자신이면 최상위이므로 종료
        if (dentry == parent)
            break;

        // d_name 구조체 읽기
        struct qstr d_name;
        bpf_probe_read(&d_name, sizeof(d_name), &dentry->d_name);

        // 실제 파일/디렉토리 이름 읽기 (최대 32바이트)
        char dname[32];
        __builtin_memset(dname, 0, sizeof(dname));
        int name_len = bpf_probe_read_str(dname, sizeof(dname), d_name.name);

        // bpf_probe_read_str는 문자열 길이+1(널문자 포함)을 반환함
        // 0 이하이면 읽기 실패, 1이면 빈 문자열(""), 2 이상이면 유효 문자열
        if (name_len <= 1)
            break;  // 이름이 없거나 실패 시 중단

        // 남은 buf 공간이 부족하면 중단
        // name_len에는 널문자를 포함하므로 실제 복사할 문자는 (name_len - 1)개
        if (pos - (name_len - 1) - 1 < 0)
            break;

        // 문자열을 뒤에서 앞으로 복사
        // (name_len - 1)는 실제 문자 수
        pos -= (name_len - 1);
        bpf_probe_read(&buf[pos], name_len - 1, dname);

        // 맨 앞에 '/' 추가
        if (pos > 0) {
            pos--;
            buf[pos] = '/';
        }

        // 다음(상위) dentry로 이동
        dentry = parent;
    
    }
    // (디버그 용) 커널 디버그 출력 - 실제 사용 시 제거하거나 bpf_trace_printk를 사용 제한에 주의
     bpf_trace_printk("cwd path: %s\n", &buf[pos]);

    return pos;  // buf[pos]부터 경로가 시작됨
}


int trace_execve(struct pt_regs *ctx)
{
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    data.pid = pid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // 현재 task -> fs_struct -> pwd -> dentry
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    struct fs_struct *fs = NULL;
    bpf_probe_read(&fs, sizeof(fs), &task->fs);
    if (!fs)
        return 0;

    struct path pwd;
    bpf_probe_read(&pwd, sizeof(pwd), &fs->pwd);
    struct dentry *dentry = pwd.dentry;
    if (!dentry)
        return 0;

    

    get_dentry_path(dentry, data.fullpath, sizeof(data.fullpath));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

class Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("comm", ctypes.c_char * 16),
        ("fullpath", ctypes.c_char * 256)
    ]

def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    fullpath = event.fullpath.decode("utf-8", errors="replace").lstrip("\x00")
    print("PID: %d, COMM: %s, CWD: %s" % (event.pid, event.comm.decode(), fullpath))

if __name__ == "__main__":
    b = BPF(text=bpf_program)
    # kprobe 대신 tracepoint 사용
    b.attach_tracepoint(tp="sched:sched_process_exec", fn_name="trace_execve")

    b["events"].open_perf_buffer(print_event)
    print("Tracing... Ctrl+C to exit")
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        pass
    print("Exiting...")
