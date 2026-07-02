//go:build ignore

#define MARK 0x55

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <sys/socket.h>


SEC("cgroup/sock_create");
int mark_socket(struct bpf_sock *ctx) {
    if (ctx->family != AF_INET && ctx->family != AF_INET6) {
        return 1;
    }

    ctx->mark = MARK;

    return 0;
}