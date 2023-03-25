#include "headers/bpf_tracing.h"
#include "headers/common.h"
#include "bpf_common.h"

struct event_accept {
  struct event_base base;
  int listen_sockfd;
  int client_sockfd;
};
// Force emitting struct event into the ELF.
const struct event_accept *unused_accept __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events_accept SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, s32);
    __type(value, struct pt_regs);
    __uint(max_entries, 16);
} hash_accept SEC(".maps");

SEC("uprobe/accept")
int before_accept(struct pt_regs* ctx) {
    hash_store_pid2context(hash_accept);
    return 0;
}

SEC("uretprobe/accept")
int after_accept(struct pt_regs* ctx) {
    struct event_accept event = {};
    FormEventBase(event);

    s32 pid = bpf_get_current_pid_tgid();
    struct pt_regs* start_ctx = (struct pt_regs*)bpf_map_lookup_elem(&hash_accept, &pid);
    if (start_ctx == 0) {
        bpf_probe_read_kernel_str(event.base.err_msg, sizeof(event.base.err_msg), "~null ptr~");
        event.listen_sockfd = -1;
        event.client_sockfd = -1;
    } else {
        event.listen_sockfd = PT_REGS_PARM1(start_ctx);
        event.client_sockfd = PT_REGS_RC(ctx);
    }
    bpf_perf_event_output(ctx, &events_accept, BPF_F_CURRENT_CPU, &event, sizeof(struct event_accept));
    bpf_map_delete_elem(&hash_accept, &pid);
    return 0;
}

