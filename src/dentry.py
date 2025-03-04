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
    int path_offset;
};

BPF_PERF_OUTPUT(events);

static __always_inline int get_dentry_path(struct dentry *dentry, char *buf, int buf_size)
{
    // 버퍼 전체를 0으로 초기화
    __builtin_memset(buf, 0, buf_size);
    
    int pos = buf_size - 1;
    buf[pos] = '\0';

    #pragma unroll
    for (int i = 0; i < MAX_DENTRY_LEVEL; i++) {
        if (!dentry)
            break;

        struct dentry *parent = NULL;
        bpf_probe_read(&parent, sizeof(parent), &dentry->d_parent);

        if (dentry == parent)
            break;

        struct qstr d_name;
        bpf_probe_read(&d_name, sizeof(d_name), &dentry->d_name);

        char dname[32];
        __builtin_memset(dname, 0, sizeof(dname));
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

        dentry = parent;
    }

    // 경로가 비어있으면 루트(/) 설정
    if (pos == buf_size - 1) {
        pos--;
        buf[pos] = '/';
    }
    
    bpf_trace_printk("cwd path in get_dentry_path: %s\n", &buf[pos]);
    return pos;
}

int trace_execve(struct pt_regs *ctx)
{
    struct data_t data = {};
    
    // data 구조체 전체 초기화
    __builtin_memset(&data, 0, sizeof(data));
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    data.pid = pid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

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

    data.path_offset = get_dentry_path(dentry, data.fullpath, sizeof(data.fullpath));
    
    // 경로가 제대로 구성되었는지 확인
    if (data.path_offset >= 0 && data.path_offset < sizeof(data.fullpath)) {
        bpf_trace_printk("cwd path in trace_execve: %s\n", &data.fullpath[data.path_offset]);
        events.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}
"""

class Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("comm", ctypes.c_char * 16),
        ("fullpath", ctypes.c_char * 256),
        ("path_offset", ctypes.c_int)
    ]

# def print_event(cpu, data, size):
#     event = ctypes.cast(data, ctypes.POINTER(Data)).contents
#     # path_offset 유효성 검사
#     if 0 <= event.path_offset < 256:
#         fullpath = event.fullpath[event.path_offset:].decode("utf-8", errors="replace")
#         print("PID: %d, COMM: %s, CWD: %s" % (
#             event.pid, 
#             event.comm.decode("utf-8", errors="replace"), 
#             fullpath
#         ))
#     else:
#         print("PID: %d, COMM: %s, CWD: <invalid path>" % (
#             event.pid, 
#             event.comm.decode("utf-8", errors="replace")
#         ))

def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    
    print(f"Event received - Size: {size}")
    print(f"PID: {event.pid}")
    print(f"COMM: {event.comm}")
    print(f"Path offset: {event.path_offset}")
    
    # 전체 버퍼의 내용을 hex로 출력
    print("Buffer content (hex):")
    buffer_content = bytes(event.fullpath)
    for i in range(0, len(buffer_content), 16):
        chunk = buffer_content[i:i+16]
        hex_values = ' '.join(f'{b:02x}' for b in chunk)
        ascii_values = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        print(f"{i:04x}: {hex_values:<48} {ascii_values}")
    print("-" * 80)

if __name__ == "__main__":
    b = BPF(text=bpf_program)
    b.attach_tracepoint(tp="sched:sched_process_exec", fn_name="trace_execve")

    b["events"].open_perf_buffer(print_event)
    print("Tracing... Ctrl+C to exit")
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        pass
    print("Exiting...")
