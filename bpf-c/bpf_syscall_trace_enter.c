#include "headers/common.h"
#include "bpf_common.h"

struct event_syscall_trace_enter {
  struct event_base base;
  unsigned long syscall_num;
};
// Force emitting struct event into the ELF.
const struct event_syscall_trace_enter *unused_syscall_trace_enter __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events_syscall_trace_enter SEC(".maps");

SEC("kprobe/syscall_trace_enter")
int before_syscall_trace_enter(struct pt_regs* ctx) {
  struct event_syscall_trace_enter event = {};
  FormEventBase(event);
  event.syscall_num = ctx->orig_rax;
  bpf_perf_event_output(ctx, &events_syscall_trace_enter, BPF_F_CURRENT_CPU, &event, sizeof(event));
  return 0;
}
