// gcc -fPIC -shared 
#define _GNU_SOURCE
#include <sys/types.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <pwd.h>
#include <stdio.h>

void * (*real_dlsym)(void *handle, const char *name);
void *libc;
char libc_path[] = "/usr/lib/x86_64-linux-gnu/libc.so.6";

void __attribute ((constructor)) init (void) {
  char buf[32];
  int maxver = 40;

  //Works on Ubuntu
  for(int a=0;a<maxver;a++) {
    sprintf(buf, "GLIBC_2.%d", a);
    real_dlsym = (void*(*)(void *handle, const char *name)) dlvsym(RTLD_NEXT,"dlsym", buf);
    if(real_dlsym) return;
  }

}

struct passwd *getpwnam(const char *name) {
    if(libc == NULL) {
        libc = dlopen(libc_path, RTLD_LAZY);
    }
    struct passwd* (*real_getpwnam)(const char*) = (struct passwd*(*)(const char*))real_dlsym(libc, "getpwnam");
    if (real_getpwnam == NULL) {
        printf("CALL getpwnam of %s but symbol not found\n", name);
        return NULL;
    }
    printf("CALL getpwnam of %s\n", name);
    return real_getpwnam(name);
}

int getpwnam_r(const char *restrict name, struct passwd *restrict pwd,
               char *restrict buf, size_t buflen,
               struct passwd **restrict result) {
    if(libc == NULL) {
        libc = dlopen(libc_path, RTLD_LAZY);
    }
    int (*real_getpwnam)(const char*, struct passwd*, char*, size_t, struct passwd**) = 
    (int (*)(const char*, struct passwd*, char*, size_t, struct passwd**))real_dlsym(libc, "getpwnam");
    if (real_getpwnam == NULL) {
        printf("CALL getpwnam_r of %s but symbol not found\n", name);
        return -1;
    }
    printf("CALL getpwnam_r of %s\n", name);
    return real_getpwnam(name, pwd, buf, buflen, result);
}
