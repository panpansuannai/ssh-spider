#ifndef BPF_COMMON_H
#define BPF_COMMON_H

#include "headers/common.h"

struct event_base {
  s32 pid;
  char comm[16];
  int cpu;
  char err_msg[32];
};

#define FormEventBase(event) do { \
  if (bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm)) != 0) { \
    return 0; \
  } \
  s32 id = bpf_get_current_pid_tgid() >> 32; \
  event.base.pid = id; \
  event.base.cpu = bpf_get_smp_processor_id(); } while(0)

#define hash_store_pid2context(hash) do { \
  struct pt_regs c = *ctx; \
  s32 id = bpf_get_current_pid_tgid() >> 32; \
  bpf_map_update_elem(&hash, &id, &c, BPF_ANY); \
} while(0)

#endif
