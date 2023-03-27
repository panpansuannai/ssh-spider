#include "headers/bpf_tracing.h"
#include "headers/common.h"
#include "bpf_common.h"

struct event_open {
  struct event_base base;
  char path[64];
  int fd;
  int file_or_dir;
};
// Force emitting struct event into the ELF.
const struct event_open *unused_open __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events_open SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, s32);
    __type(value, struct pt_regs);
    __uint(max_entries, 16);
} hash_open SEC(".maps");

SEC("uprobe/open")
int before_open(struct pt_regs* ctx) {
    hash_store_pid2context(hash_open);
    return 0;
}

SEC("uretprobe/open")
int after_open(struct pt_regs* ctx) {
    struct event_open event = {};
    FormEventBase(event);

    s32 pid = bpf_get_current_pid_tgid();
    struct pt_regs* start_ctx = (struct pt_regs*)bpf_map_lookup_elem(&hash_open, &pid);
    if (start_ctx == 0) {
        bpf_probe_read_kernel_str(event.base.err_msg, sizeof(event.base.err_msg), "~null ptr~");
    } else {
        bpf_probe_read_user_str(event.path, sizeof(event.path), (char*)(PT_REGS_PARM1(start_ctx)));
        event.fd = PT_REGS_RC(ctx);
    }
    bpf_perf_event_output(ctx, &events_open, BPF_F_CURRENT_CPU, &event, sizeof(struct event_open));
    bpf_map_delete_elem(&hash_open, &pid);
    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, s32);
    __type(value, struct pt_regs);
    __uint(max_entries, 16);
} hash_openat SEC(".maps");

SEC("uprobe/openat")
int before_openat(struct pt_regs* ctx) {
    hash_store_pid2context(hash_openat);
    return 0;
}

SEC("uretprobe/openat")
int after_openat(struct pt_regs* ctx) {
    struct event_open event = {};
    FormEventBase(event);

    s32 pid = bpf_get_current_pid_tgid();
    struct pt_regs* start_ctx = (struct pt_regs*)bpf_map_lookup_elem(&hash_openat, &pid);
    if (start_ctx == 0) {
        bpf_probe_read_kernel_str(event.base.err_msg, sizeof(event.base.err_msg), "~null ptr~");
    } else {
        bpf_probe_read_user_str(event.path, sizeof(event.path), (char*)(PT_REGS_PARM2(start_ctx)));
        event.fd = PT_REGS_RC(ctx);
    }
    bpf_perf_event_output(ctx, &events_open, BPF_F_CURRENT_CPU, &event, sizeof(struct event_open));
    bpf_map_delete_elem(&hash_openat, &pid);
    return 0;
}

