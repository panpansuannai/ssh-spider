//go:build ignore
#include "headers/common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#include "bpf_openpty.c"
#include "bpf_getpwx.c"
#include "bpf_pam.c"
#include "bpf_syscall_trace_enter.c"
#include "bpf_accept.c"
#include "bpf_open.c"
