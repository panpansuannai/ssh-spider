#include "headers/bpf_tracing.h"
#include "headers/common.h"
#include "bpf_common.h"

struct event_openpty {
  struct event_base base;
};
// Force emitting struct event into the ELF.
const struct event_openpty *unused_openpty __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events_openpty SEC(".maps");

/**
 *  API Definition: https://man7.org/linux/man-pages/man3/openpty.3.html
 *       int openpty(int *amaster, int *aslave, char *name,
 *        const struct termios *termp, const struct winsize *winp);
*/
SEC("uretprobe/openpty")
int after_openpty(struct pt_regs* ctx) {
  struct event_openpty event = {};
  FormEventBase(event);
  bpf_perf_event_output(ctx, &events_openpty, BPF_F_CURRENT_CPU, &event, sizeof(event));
  return 0;
}

