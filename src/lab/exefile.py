#!/usr/bin/env python
from bcc import BPF
from bcc.utils import printb
import ctypes

# 아주 간소화된 eBPF 프로그램 (실행 시 basename만 추출)
bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/fs_struct.h>
#include <linux/nsproxy.h>
#include <bcc/proto.h>

#define MAX_PATH_LEN 256
#define MAX_DENTRY_LEVEL 16
#define MAX_DNAME_LEN 64
#define TASK_COMM_LEN 16

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char fullpath[MAX_PATH_LEN];
    int path_offset;
    u8 is_valid;
};

BPF_PERF_OUTPUT(events);

static __always_inline int get_dentry_path(struct dentry *dentry, char *buf, int buf_size, u8 *is_valid)
{
    int pos = buf_size - 1;
    buf[pos] = '\0';
    *is_valid = 1;  // 초기값을 유효하다고 설정

    struct dentry *d = dentry;
    struct dentry *parent;
    
    for (int i = 0; i < MAX_DENTRY_LEVEL && d != NULL; i++) {
        bpf_probe_read(&parent, sizeof(parent), &d->d_parent);
        
        if (d == parent)
            break;

        struct qstr d_name = {};
        bpf_probe_read(&d_name, sizeof(d_name), &d->d_name);

        // dname 길이 검사를 먼저 수행
        if (d_name.len > MAX_DNAME_LEN) {
            *is_valid = 0;  // 유효하지 않음으로 표시
            break;
        }

        char dname[MAX_DNAME_LEN] = {};
        int name_len = bpf_probe_read_str(dname, sizeof(dname), d_name.name);

        if (name_len <= 1)
            break;

        if (pos - (name_len - 1) - 1 < 0)
            break;

        pos -= (name_len - 1);
        bpf_probe_read(&buf[pos], name_len - 1, dname);

        if (pos > 0) {
            pos--;
            buf[pos] = '/';
        }

        d = parent;
        
        // MAX_DENTRY_LEVEL에 도달했지만 아직 루트가 아닌 경우 체크
        if (i == MAX_DENTRY_LEVEL - 1) {
            bpf_probe_read(&parent, sizeof(parent), &d->d_parent);
            if (d != parent) {
                *is_valid = 0;  // 아직 루트에 도달하지 못했으므로 유효하지 않음
            }
        }
    }

    if (pos == buf_size - 1) {
        pos--;
        buf[pos] = '/';
    }
    
    return pos;
}

int trace_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    data.pid = pid;
    data.is_valid = 1;  // 초기값 설정

    // comm 읽기
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // 현재 task_struct 가져오기
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    // mm_struct 가져오기
    struct mm_struct *mm;
    bpf_probe_read(&mm, sizeof(mm), &task->mm);
    if (!mm)
        return 0;

    // mm->exe_file 읽기
    struct file *exe_file = NULL;
    bpf_probe_read(&exe_file, sizeof(exe_file), &mm->exe_file);
    if (!exe_file)
        return 0;

    // file->f_path 읽기
    struct path fpath = {};
    bpf_probe_read(&fpath, sizeof(fpath), &exe_file->f_path);

    // dentry에서 전체 경로 읽기
    data.path_offset = get_dentry_path(fpath.dentry, data.fullpath, sizeof(data.fullpath), &data.is_valid);
    
    if (data.path_offset >= 0 && data.path_offset < sizeof(data.fullpath)) {
        bpf_trace_printk("exe path: %s (valid: %d)\\n", &data.fullpath[data.path_offset], data.is_valid);
        events.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}
"""

class Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("comm", ctypes.c_char * 16),
        ("fullpath", ctypes.c_ubyte * 256),
        ("path_offset", ctypes.c_int),
        ("is_valid", ctypes.c_ubyte)
    ]

def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    print(f"PID: {event.pid}")    # PID는 항상 출력
    print(f"COMM: {event.comm.decode('utf-8', errors='replace')}")  # COMM 출력
    
    if 0 <= event.path_offset < 256:
        path_str = bytes(event.fullpath)[event.path_offset:].decode('utf-8', errors='replace')
        print(f"Path: {path_str}")
        print(f"유효한 경로: {'예' if event.is_valid else '아니오'}")
    print("-" * 40)

# eBPF 프로그램 로드 및 attach
b = BPF(text=bpf_text)
b.attach_tracepoint(tp="sched:sched_process_exec", fn_name="trace_exec")
b["events"].open_perf_buffer(print_event)
print("Tracing execve... Ctrl-C to end.")

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
