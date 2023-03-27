#include "headers/bpf_tracing.h"
#include "headers/common.h"
#include "bpf_common.h"

#define USE_GETPWNAM
#define USE_GETPWNAM_R
#define USE_GETPWUID
#define USE_GETPWUID_R

/**
 * API Definition: https://man7.org/linux/man-pages/man3/getpwnam.3.html
 *    struct passwd *getpwnam(const char *name);
 *    struct passwd *getpwuid(uid_t uid);
 *    int getpwnam_r(const char *restrict name, struct passwd *restrict pwd,
 *                char *restrict buf, size_t buflen, struct passwd **restrict result);
 *    int getpwuid_r(uid_t uid, struct passwd *restrict pwd,
 *                    char *restrict buf, size_t buflen, struct passwd **restrict result);
*/

struct passwd {
   char   *pw_name;       /* username */
   char   *pw_passwd;     /* user password */
   u32 pw_uid;        /* user ID */
};

struct event_passwd {
   char   pw_name[16];       /* username */
   char   pw_passwd[16];     /* user password */
   u32 pw_uid;        /* user ID */
};

struct event_getpwnam {
  struct event_base base;
  struct event_passwd result;
  char looking_name[16];
  s32 exist;
};
// Force emitting struct event into the ELF.
const struct event_getpwnam *_1 __attribute__((unused));

struct event_getpwuid {
  struct event_base base;
  struct event_passwd result;
  u32 looking_uid;
  s32 exist;
};
// Force emitting struct event into the ELF.
const struct event_getpwuid *_3 __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
}   events_getpwnam SEC(".maps"),
    events_getpwuid SEC(".maps"),
    events_getpwnam_r SEC(".maps"),
    events_getpwuid_r SEC(".maps");


// Get struct passwd from user space pionter `p`, and store in `result`
static void retrieve_passwd_from_context(struct event_base* base, struct event_passwd* result, struct passwd* p) {
  struct passwd pw = {};
  if(p == 0) {
    bpf_probe_read_kernel_str(base->err_msg, sizeof(base->err_msg), "~null ptr~");
  } else if(bpf_probe_read_kernel(&pw, sizeof(struct passwd), p)) {
    bpf_probe_read_kernel_str(base->err_msg, sizeof(base->err_msg), "~read_kernel fail~");
  } else {
    bpf_probe_read_user_str(result->pw_name, sizeof(pw.pw_name), pw.pw_name);
    bpf_probe_read_user_str(result->pw_passwd, sizeof(pw.pw_passwd), pw.pw_passwd);
    result->pw_uid = pw.pw_uid;
  }
}

#ifdef USE_GETPWNAM
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
  __type(key, s32);
  __type(value, struct event_getpwnam);
  __uint(max_entries, 16);
} hash_getpwnam SEC(".maps");

SEC("uprobe/getpwnam")
int before_getpwnam(struct pt_regs* ctx) {
  struct event_getpwnam event = {};
  FormEventBase(event);
  bpf_probe_read_user_str(&event.looking_name, sizeof(event.looking_name), (char*)PT_REGS_PARM1(ctx));
  bpf_map_update_elem(&hash_getpwnam, &event.base.pid, &event, BPF_ANY);
  return 0;
}

SEC("uretprobe/getpwnam")
int after_getpwnam(struct pt_regs* ctx) {
  s32 pid = bpf_get_current_pid_tgid() >> 32;
  struct event_getpwnam* e = (struct event_getpwnam*) bpf_map_lookup_elem(&hash_getpwnam, &pid);
  if (e == 0) {
    struct event_getpwnam event = {};
    FormEventBase(event);
    bpf_probe_read_kernel_str(event.base.err_msg, sizeof(event.base.err_msg), "~alone~");
    bpf_perf_event_output(ctx, &events_getpwnam, BPF_F_CURRENT_CPU, &event, sizeof(struct event_getpwnam));
    return 0;
  }
  struct event_getpwnam event = *e;
  struct passwd* p = (struct passwd*)PT_REGS_RC(ctx);
  retrieve_passwd_from_context(&event.base, &event.result, p);
  if (p == 0) {
      event.exist = -1;
  } else {
      event.exist = 0;
  }
  bpf_perf_event_output(ctx, &events_getpwnam, BPF_F_CURRENT_CPU, &event, sizeof(struct event_getpwnam));
  bpf_map_delete_elem(&hash_getpwnam, &pid);
  return 0;
}
#endif

#ifdef USE_GETPWNAM_R
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
  __type(key, s32);
  __type(value, struct pt_regs);
  __uint(max_entries, 16);
} hash_getpwnam_r SEC(".maps");

SEC("uprobe/getpwnam_r")
int before_getpwnam_r(struct pt_regs* ctx) {
  hash_store_pid2context(hash_getpwnam_r);
  return 0;
}

SEC("uretprobe/getpwnam_r")
int after_getpwnam_r(struct pt_regs* ctx) {
  struct event_getpwnam event = {};
  FormEventBase(event);

  s32 id = bpf_get_current_pid_tgid() >> 32;
  struct pt_regs* start_ctx = bpf_map_lookup_elem(&hash_getpwnam_r, &id);
  if(start_ctx == 0) {
    bpf_probe_read_kernel_str(event.base.err_msg, sizeof(event.base.err_msg), "~alone~");
	  bpf_perf_event_output(ctx, &events_getpwnam, BPF_F_CURRENT_CPU, &event, sizeof(struct event_getpwnam));
    return 0;
  }
  bpf_probe_read_user_str(&event.looking_name, sizeof(event.looking_name), (char*)PT_REGS_PARM1(start_ctx));
  struct passwd* p = (struct passwd*)PT_REGS_PARM2(start_ctx);
  retrieve_passwd_from_context(&event.base, &event.result, p);
  struct passwd** ptr = (struct passwd**) PT_REGS_PARM5(start_ctx);
  struct passwd* result = 0;
  bpf_probe_read_user(&result, sizeof(struct passwd*), ptr);
  if (result == 0) {
      event.exist = -1;
  } else {
      event.exist = 0;
  }
  // event.exist = (s32)PT_REGS_RC(ctx);
  bpf_map_delete_elem(&hash_getpwnam_r, &id);
  bpf_perf_event_output(ctx, &events_getpwnam_r, BPF_F_CURRENT_CPU, &event, sizeof(struct event_getpwnam));
  return 0;
}
#endif

#ifdef USE_GETPWUID
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
  __type(key, s32);
  __type(value, struct event_getpwuid);
  __uint(max_entries, 16);
} hash_getpwuid SEC(".maps");

SEC("uprobe/getpwuid")
int before_getpwuid(struct pt_regs* ctx) {
  struct event_getpwuid event = {};
  FormEventBase(event);
  event.looking_uid = (u32)PT_REGS_PARM1(ctx);
  bpf_map_update_elem(&hash_getpwuid, &event.base.pid, &event, BPF_ANY);
  return 0;
}

SEC("uretprobe/getpwuid")
int after_getpwuid(struct pt_regs* ctx) {
  s32 pid = bpf_get_current_pid_tgid() >> 32;
  struct event_getpwuid* e = (struct event_getpwuid*) bpf_map_lookup_elem(&hash_getpwuid, &pid);
  if (e == 0) {
    struct event_getpwuid event = {};
    FormEventBase(event);
    bpf_probe_read_kernel_str(event.base.err_msg, sizeof(event.base.err_msg), "~alone~");
    bpf_perf_event_output(ctx, &events_getpwuid, BPF_F_CURRENT_CPU, &event, sizeof(struct event_getpwuid));
    return 0;
  }
  struct event_getpwuid event = *e;
  struct passwd* p = (struct passwd*)PT_REGS_RC(ctx);
  retrieve_passwd_from_context(&event.base, &event.result, p);
  if (p == 0) {
      event.exist = -1;
  } else {
      event.exist = 0;
  }
  bpf_perf_event_output(ctx, &events_getpwuid, BPF_F_CURRENT_CPU, &event, sizeof(struct event_getpwuid));
  bpf_map_delete_elem(&hash_getpwuid, &pid);
  return 0;
}
#endif

#ifdef USE_GETPWUID_R
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
  __type(key, s32);
  __type(value, struct pt_regs);
  __uint(max_entries, 16);
} hash_getpwuid_r SEC(".maps");

SEC("uprobe/getpwuid_r")
int before_getpwuid_r(struct pt_regs* ctx) {
  hash_store_pid2context(hash_getpwuid_r);
  return 0;
}

SEC("uretprobe/getpwuid_r")
int after_getpwuid_r(struct pt_regs* ctx) {
  struct event_getpwuid event = {};
  FormEventBase(event);

  s32 id = bpf_get_current_pid_tgid() >> 32;
  struct pt_regs* start_ctx = bpf_map_lookup_elem(&hash_getpwuid_r, &id);
  if(start_ctx == 0) {
    bpf_probe_read_kernel_str(event.base.err_msg, sizeof(event.base.err_msg), "~alone~");
    bpf_perf_event_output(ctx, &events_getpwuid, BPF_F_CURRENT_CPU, &event, sizeof(struct event_getpwuid));
    return 0;
  }
  event.looking_uid = (u32)PT_REGS_PARM1(start_ctx);
  struct passwd* p = (struct passwd*)PT_REGS_PARM2(start_ctx);
  retrieve_passwd_from_context(&event.base, &event.result, p);
  event.exist = (s32)PT_REGS_RC(ctx);
  bpf_map_delete_elem(&hash_getpwuid_r, &id);
  bpf_perf_event_output(ctx, &events_getpwuid_r, BPF_F_CURRENT_CPU, &event, sizeof(struct event_getpwuid));
  return 0;
}
#endif
