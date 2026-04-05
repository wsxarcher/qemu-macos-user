/* Test: simple printf via libc (requires dyld + libSystem) */
#include <stdio.h>
int main(void) {
    printf("Hello from C!\n");
    return 0;
}
