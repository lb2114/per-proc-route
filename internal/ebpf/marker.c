//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define MARK 0x55

#define AF_INET 2
#define AF_INET6 11

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __type(value, __u32);
    __uint(max_entries, 4096);
} unreg_pids_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8[256]);
    __type(value, __u8);
    __uint(max_entries, 1024);
} procs_to_bypass_map SEC(".maps");


SEC("cgroup/sock_create")
int mark_socket(struct bpf_sock *ctx) {
    if (ctx->family != AF_INET && ctx->family != AF_INET6) {
        return 1;
    }

    ctx->mark = MARK;

    return 1;
}
 
SEC("tracepoint/syscalls/sys_enter_execve")
int execve_trace(struct trace_event_raw_sys_enter *ctx) {
    __u8 filename[256];
    __u8* filename_ptr = (__u8*)ctx->args[0];

    if (bpf_probe_read_user_str((void*)filename, sizeof(filename), (const void*)filename_ptr) < 0) {
        return 0;
    }

    if (bpf_map_lookup_elem((void*)&procs_to_bypass_map, (const void*)filename) != NULL) {
        __u32 pid = 0xFFFF & bpf_get_current_pid_tgid();
        bpf_ringbuf_output((void*)&unreg_pids_map, (void*)&pid, sizeof(pid), BPF_RB_FORCE_WAKEUP);
    }

    return 0;
}