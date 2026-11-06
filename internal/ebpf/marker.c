//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h> // IWYU pragma: keep

#define AF_INET 2

#define MARK 0x55


char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);     
    __uint(max_entries, 4096);
} policy_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8[256]);
    __type(value, __u8); 
    __uint(max_entries, 1024);
} procs_to_bypass_map SEC(".maps");


SEC("cgroup/sock_create")
int mark_socket(struct bpf_sock *ctx) {
    if (ctx->family != AF_INET) {
        return 1;
    }

    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem((void*)&policy_map, (const void*)&tgid) != NULL) {
        ctx->mark = MARK;
    }

    return 1;
}


SEC("tp_btf/sched_process_fork")
int BPF_PROG(cpy_process_trace, struct task_struct *p, struct task_struct *c) {
    if (p->tgid == c->tgid) {
        return 0;
    }
    __u32 p_tgid = p->tgid;
    if (bpf_map_lookup_elem((void*)&policy_map, (const void*)&p_tgid) != NULL) {
        __u8 i = 1;
        __u32 c_tgid = c->tgid;
        long r = bpf_map_update_elem((void*)&policy_map, (const void*)&c_tgid, (const void*)&i, 0);
        if (r) {
            bpf_printk("Failed to add child TGID %u: %ld", c_tgid, r);
        }
    }
    return 0;
}


SEC("tp_btf/sched_process_exit")
int BPF_PROG(del_process_trace, struct task_struct *task, bool group_dead) {
    if (group_dead) {
        __u32 tgid = task->tgid;
        long r = bpf_map_delete_elem((void*)&policy_map, &tgid);
        if (r && r != -ENOENT) {
            bpf_printk("Failed to delete TGID %u: %ld", tgid, r);
        }
    }
    return 0;
}


// Record processes whose execve path matches the bypass list.
SEC("tracepoint/syscalls/sys_enter_execve")
int execve_trace(struct trace_event_raw_sys_enter *ctx) {
    __u8 filename[256] = {0};
    __u8* filename_ptr = (__u8*)ctx->args[0];

    if (bpf_probe_read_user_str((void*)filename, sizeof(filename), (const void*)filename_ptr) < 0) {
        return 0;
    }

    if (bpf_map_lookup_elem((void*)&procs_to_bypass_map, (const void*)filename) != NULL) {
        __u32 tgid = bpf_get_current_pid_tgid() >> 32;
        __u8 i = 1;
        long r = bpf_map_update_elem((void*)&policy_map, (const void*)&tgid, (const void*)&i, 0);
        if (r) {
            bpf_printk("Failed to add TGID %u: %ld", tgid, r);
        }
    }
    return 0;
}
