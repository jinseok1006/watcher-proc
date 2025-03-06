#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/cgroup.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/mm_types.h>

#define CONTAINER_ID_LEN 12
#define MAX_PATH_LEN 256
#define ARGSIZE 384
#define DOCKER_PREFIX_LEN 7        // "docker-" 길이
#define CONTAINERD_PREFIX_LEN 15   // "cri-containerd-" 길이
#define MAX_DENTRY_LEVEL 16
#define MAX_DNAME_LEN 64

// 에러 플래그 정의
#define ERR_NONE              0x00000000  // 모든 검사 통과
#define ERR_DENTRY_TOO_DEEP   0x00000001  // dentry 깊이가 MAX_DENTRY_LEVEL 초과
#define ERR_DNAME_TOO_LONG    0x00000002  // 개별 dname 길이가 MAX_DNAME_LEN 초과
#define ERR_ARGS_TOO_LONG     0x00000004  // 명령줄 인수가 ARGSIZE 초과

struct data_t {
    u32 pid;
    u32 error_flags;          // invalid_bits에서 이름 변경
    char container_id[CONTAINER_ID_LEN];
    char fullpath[MAX_PATH_LEN];
    char args[ARGSIZE];
    int path_offset;
    u32 args_len;
};

BPF_PERCPU_ARRAY(tmp_array, struct data_t, 1);
BPF_HASH(process_data, u32, struct data_t);
BPF_PROG_ARRAY(prog_array, 4);
BPF_PERF_OUTPUT(events);

static __always_inline bool check_prefix_and_extract(const char *name, const char *prefix, int prefix_len, char *container_id, int offset) {
    #pragma unroll
    for (int i = 0; i < prefix_len; i++) {
        if (name[i] != prefix[i])
            return false;
    }
    
    // container ID 길이 체크 (최소 12자)
    #pragma unroll
    for (int i = 0; i < 12; i++) {
        char c;
        bpf_probe_read_kernel(&c, 1, name + offset + i);
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    
    // 유효한 컨테이너 ID인 경우 복사
    #pragma unroll
    for (int i = 0; i < CONTAINER_ID_LEN; i++) {
        char c;
        bpf_probe_read_kernel(&c, 1, name + offset + i);
        if (c == '.' || c == 0)
            break;
        container_id[i] = c;
    }
    
    return true;
}

// 첫 번째 핸들러: 공간 확보 및 PID 설정
int init_handler(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 zero = 0;
    
    struct data_t *tmp = tmp_array.lookup(&zero);
    if (!tmp)
        return 0;
    
    tmp->pid = pid;
    process_data.update(&pid, tmp);
    prog_array.call(ctx, 1);  // container_handler로
    return 0;
}

// 두 번째 핸들러: 컨테이너 ID 수집
int container_handler(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct data_t *data = process_data.lookup(&pid);
    if (!data) {
        process_data.delete(&pid);
        return 0;
    }
    
    // task_struct에서 cgroup 정보 가져오기
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        process_data.delete(&pid);
        return 0;
    }

    struct cgroup *cgrp = task->cgroups->dfl_cgrp;
    if (!cgrp) {
        process_data.delete(&pid);
        return 0;
    }
        
    struct kernfs_node *kn = cgrp->kn;
    if (!kn) {
        process_data.delete(&pid);
        return 0;
    }
    
    // cgroup 이름 읽기
    char cgroup_name[MAX_PATH_LEN];
    bpf_probe_read_kernel_str(cgroup_name, sizeof(cgroup_name), (void *)kn->name);
    
    // docker 형식 확인 (docker-)
    if (check_prefix_and_extract(cgroup_name, "docker-", DOCKER_PREFIX_LEN, 
        data->container_id, DOCKER_PREFIX_LEN)) {
        prog_array.call(ctx, 2);  // cwd_handler로
        return 0;
    }
    
    // containerd 형식 확인 (cri-containerd-)
    if (check_prefix_and_extract(cgroup_name, "cri-containerd-", CONTAINERD_PREFIX_LEN,
        data->container_id, CONTAINERD_PREFIX_LEN)) {
        prog_array.call(ctx, 2);  // cwd_handler로
        return 0;
    }
    
    // 컨테이너가 아닌 경우
    process_data.delete(&pid);
    return 0;
}

static __always_inline int get_dentry_path(struct dentry *dentry, char *buf, int buf_size, u32 *error_flags)
{
    int pos = buf_size - 1;
    buf[pos] = '\0';

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
            *error_flags |= ERR_DNAME_TOO_LONG;
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
                *error_flags |= ERR_DENTRY_TOO_DEEP;
            }
        }
    }

    if (pos == buf_size - 1) {
        pos--;
        buf[pos] = '/';
    }
    
    return pos;
}

// 세 번째 핸들러: CWD 수집
int cwd_handler(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct data_t *data = process_data.lookup(&pid);
    if (!data) {
        process_data.delete(&pid);
        return 0;
    }
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        process_data.delete(&pid);
        return 0;
    }

    struct fs_struct *fs = NULL;
    bpf_probe_read(&fs, sizeof(fs), &task->fs);
    if (!fs) {
        process_data.delete(&pid);
        return 0;
    }

    struct path pwd = {};
    bpf_probe_read(&pwd, sizeof(pwd), &fs->pwd);
    struct dentry *dentry = pwd.dentry;
    if (!dentry) {
        process_data.delete(&pid);
        return 0;
    }

    data->path_offset = get_dentry_path(dentry, data->fullpath, sizeof(data->fullpath), &data->error_flags);
    
    prog_array.call(ctx, 3);  // args_handler로
    return 0;
}

// 네 번째 핸들러: 명령줄 인수 수집
int args_handler(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct data_t *data = process_data.lookup(&pid);
    if (!data) {
        process_data.delete(&pid);
        return 0;
    }
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        process_data.delete(&pid);
        return 0;
    }
    
    struct mm_struct *mm = task->mm;
    if (!mm || !mm->arg_start) {
        process_data.delete(&pid);
        return 0;
    }
    
    u64 start = (u64)mm->arg_start;
    u64 end   = (u64)mm->arg_end;
    u64 length = 0;

    if (end > start) {
        length = end - start;
    }

    if (length > ARGSIZE) {
        data->error_flags |= ERR_ARGS_TOO_LONG;
        length = ARGSIZE;
    }

    data->args_len = (u32)length;
    bpf_probe_read_user(data->args, length, (void *)start);
    
    events.perf_submit(ctx, data, sizeof(struct data_t));
    process_data.delete(&pid);
    return 0;
} 