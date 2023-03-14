#include "headers/bpf_tracing.h"
#include "headers/common.h"
#include "bpf_common.h"

#define USE_PAM_AUTHENTICATE

struct event_pam {
    struct event_base base;
    char api_name[16];
    char service_name[16];
    char user[16];
    char authtok[16];
    s32 pam_ret;
}; 
const struct event_pam *unused_pam __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events_pam SEC(".maps");

struct pam_handle_t {
  char *authtok;
  unsigned caller_is;
  void *pam_conversation;
  char *oldauthtok;
  char *prompt; /* for use by pam_get_user() */
  char *service_name;
  char *user;
  char *rhost;
  char *ruser;
  char *tty;
  char *xdisplay;
  char *authtok_type; /* PAM_AUTHTOK_TYPE */
  void *data;
  void *env; /* structure to maintain environment list */
};

#define FormPamEventBase(event) do { \
    FormEventBase(event); \
    bpf_probe_read_kernel_str(event.api_name, sizeof(event.api_name), __func__ + 6); \
}while(0)

static void retrieve_information_from_pam_handle(struct event_pam* pam, struct pam_handle_t* pamh) {
    struct pam_handle_t p = {};
    if(pamh == 0) {
        bpf_probe_read_kernel_str(pam->base.err_msg, sizeof(pam->base.err_msg), "~null ptr~");
    } else if(bpf_probe_read_kernel(&p, sizeof(struct pam_handle_t), pamh)) {
        bpf_probe_read_kernel_str(pam->base.err_msg, sizeof(pam->base.err_msg), "~read_kernel fail~");
    } else {
        bpf_probe_read_user_str(pam->service_name, sizeof(pam->service_name), p.service_name);
        bpf_probe_read_user_str(pam->user, sizeof(pam->user), p.user);
        bpf_probe_read_user_str(pam->authtok, sizeof(pam->authtok), p.authtok);
    }
} 


#ifdef USE_PAM_AUTHENTICATE
/**
 * API Definition: https://man7.org/linux/man-pages/man3/pam_authenticate.3.html
 *      int pam_authenticate(pam_handle_t *pamh, int flags);
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, s32);
    __type(value, struct pt_regs);
    __uint(max_entries, 16);
} hash_pam_authenticate SEC(".maps");

SEC("uprobe/pam_authenticate")
int before_pam_authenticate(struct pt_regs* ctx) {
    hash_store_pid2context(hash_pam_authenticate);
    return 0;
}

SEC("uretprobe/pam_authenticate")
int after_pam_authenticate(struct pt_regs* ctx) {
    struct event_pam event = {};
    FormPamEventBase(event);

    s32 pid = bpf_get_current_pid_tgid();
    struct pt_regs* start_ctx = (struct pt_regs*)bpf_map_lookup_elem(&hash_pam_authenticate, &pid);
    if (start_ctx == 0) {
        bpf_probe_read_kernel_str(&event.base.err_msg, sizeof(event.base.err_msg), "~alone~");
	    bpf_perf_event_output(ctx, &events_pam, BPF_F_CURRENT_CPU, &event, sizeof(struct event_pam));
        return 0;
    }
    struct pam_handle_t* pamh = (struct pam_handle_t*)PT_REGS_PARM1(start_ctx);
    retrieve_information_from_pam_handle(&event, pamh);
    event.pam_ret = (s32)PT_REGS_RC(ctx);
    bpf_perf_event_output(ctx, &events_pam, BPF_F_CURRENT_CPU, &event, sizeof(struct event_pam));
    bpf_map_delete_elem(&hash_pam_authenticate, &pid);
    return 0;
}
#endif
