#include<pty.h>

int main() {
    int i = openpty();
    return 0;
}