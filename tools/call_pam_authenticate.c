#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>

static struct pam_conv conv = {
    misc_conv,
    NULL
};

int main(int argc, char *argv[]) {
    printf("start\n");
    pam_handle_t *pamh = NULL;
    int ret;

    if(argc != 2) {
        fprintf(stderr, "Usage: %s username\n", argv[0]);
        return 1;
    }

    ret = pam_start("sudo", argv[1], &conv, &pamh);

    if(ret == PAM_SUCCESS) {
        ret = pam_authenticate(pamh, 0);
    }

    if(pam_end(pamh, ret) != PAM_SUCCESS) {
        pamh = NULL;
        fprintf(stderr, "Failed to release PAM handle\n");
        return 1;
    }

    if(ret != PAM_SUCCESS) {
        fprintf(stderr, "Authentication failure\n");
        return 1;
    }

    printf("Authentication succeeded\n");
    return 0;
}
