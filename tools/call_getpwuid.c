#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>


int main() {
    struct passwd* p = getpwuid(1000);
    if (p) {
        printf("getpwuid(%d): name(%s) passwd(%s) uid(%d)\n", 1000, p->pw_name, p->pw_passwd, p->pw_uid);
    }
    return 0;
}