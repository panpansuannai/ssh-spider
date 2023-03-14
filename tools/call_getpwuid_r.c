#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>


int main() {
    struct passwd p = {};
    struct passwd* r = 0;
    char buf[1024];
    int i = getpwuid_r(1000, &p, buf, 1024, &r);
    if (i == 0) {
        printf("getpwuid_r(%d): name(%s) passwd(%s) uid(%d)\n", 1000, p.pw_name, p.pw_passwd, p.pw_uid);
    }
    return 0;
}