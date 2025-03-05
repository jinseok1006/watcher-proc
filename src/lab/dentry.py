#!/usr/bin/python3
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
} __attribute__((packed));

BPF_PERF_OUTPUT(events);

static __always_inline int get_dentry_path(struct dentry *dentry, char *buf, int buf_size)
{
    // Initialize buffer with zeros using a loop
    for (int i = 0; i < buf_size; i++) {
        buf[i] = 0;
    }
    
    int pos = buf_size - 1;
    buf[pos] = '\0';

    struct dentry *d = dentry;
    struct dentry *parent;
    
    // Simplified loop structure for better BPF compatibility
    for (int i = 0; i < MAX_DENTRY_LEVEL && d != NULL; i++) {
        bpf_probe_read(&parent, sizeof(parent), &d->d_parent);
        
        if (d == parent)
            break;

        struct qstr d_name;
        bpf_probe_read(&d_name, sizeof(d_name), &d->d_name);

        char dname[32];
        // Initialize dname array
        for (int j = 0; j < 32; j++) {
            dname[j] = 0;
        }
        
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
    }

    if (pos == buf_size - 1) {
        pos--;
        buf[pos] = '/';
    }
    
    return pos;
}

int trace_execve(struct pt_regs *ctx)
{
    struct data_t data = {};
    
    // Initialize data structure using a loop
    char *p = (char *)&data;
    for (int i = 0; i < sizeof(data); i++) {
        p[i] = 0;
    }
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    data.pid = pid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    struct fs_struct *fs = NULL; bpf_probe_read(&fs, sizeof(fs), &task->fs);
    if (!fs)
        return 0;

    struct path pwd;
    bpf_probe_read(&pwd, sizeof(pwd), &fs->pwd);
    struct dentry *dentry = pwd.dentry;
    if (!dentry)
        return 0;

    data.path_offset = get_dentry_path(dentry, data.fullpath, sizeof(data.fullpath));
    
    if (data.path_offset >= 0 && data.path_offset < sizeof(data.fullpath)) {
        bpf_trace_printk("cwd path in trace_execve: %s\n", &data.fullpath[data.path_offset]);
        events.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}
"""

class Data(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("comm", ctypes.c_char * 16),
        ("fullpath", ctypes.c_ubyte * 256),
        ("path_offset", ctypes.c_int)
    ]

def print_event(cpu, data, size):
    # 구조체로 변환
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    
    print(f"\n[Event]")
    print(f"PID: {event.pid}")
    print(f"COMM: {event.comm.decode('utf-8', errors='replace')}")
    print(f"Path offset: {event.path_offset}")
    
    # fullpath를 바이트로 출력
    fullpath_bytes = bytes(event.fullpath)
    print(f"Fullpath bytes: {fullpath_bytes}")
    
    if 0 <= event.path_offset < 256:
        path_bytes = fullpath_bytes[event.path_offset:]
        path_str = path_bytes.split(b'\0')[0].decode('utf-8', errors='replace')
        print(f"Decoded path: {path_str}")
    print("-" * 40)

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
