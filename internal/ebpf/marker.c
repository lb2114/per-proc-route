//go:build ignore

#define MARK 0x55

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define AF_INET 2
#define AF_INET6 11


SEC("cgroup/sock_create")
int mark_socket(struct bpf_sock *ctx) {
    if (ctx->family != AF_INET && ctx->family != AF_INET6) {
        return 1;
    }

    ctx->mark = MARK;

    return 1;
}
